# SPDX-License-Identifier: BSD-2-Clause
"""`tailscale_device_attributes` against a real tailnet, through the module.

The tailnet this suite runs against does not offer custom posture attributes: the
read answers, and every write is refused with "feature not available on current
billing plan". The reachable half is asserted directly, and the write path is
probed so the suite exercises a real round trip on a tailnet where the feature is
offered rather than reporting a free plan as a module defect.

Every assertion drives the module's ``main()``. A write the plan refuses leaves
nothing behind, and the suite removes what it sets where a plan accepts it.
"""

from __future__ import annotations

from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.modules import tailscale_device_attributes

pytestmark = pytest.mark.live_smoke

#: The custom key the write tests use. A name nothing else on the tailnet holds,
#: so a read that finds it is a read of what this suite wrote.
PROBE_KEY = "custom:probeAttribute"

#: The refusal a tailnet that does not offer the feature answers with, verbatim.
#: Asserted as a substring so the module's own wrapper around it is not pinned.
PLAN_REFUSAL = "feature not available on current billing plan"


def _read(api: Api, device_id: str) -> dict[str, Any]:
    body = api.call("device_attributes_get", "GET", params={"deviceId": device_id}).body
    return body if isinstance(body, dict) else {}


def _custom(api: Api, device_id: str) -> dict[str, Any]:
    attributes = _read(api, device_id).get("attributes")
    if not isinstance(attributes, dict):
        return {}
    return {key: value for key, value in attributes.items() if str(key).startswith("custom:")}


def _clear(api: Api, device_id: str) -> None:
    for key in _custom(api, device_id):
        try:
            api.call(
                "device_attribute_delete",
                "DELETE",
                params={"deviceId": device_id, "attributeKey": key},
            )
        except Exception:
            return


@pytest.fixture
def attribute_writes(api: Api, live_device: Any) -> bool:
    """Whether this tailnet will accept a custom attribute write at all.

    Probed against the API rather than assumed from the plan, because the plan is
    the tailnet's property and not the collection's. A refusal is the state the
    write tests account for, not a failure of the module.
    """
    if not live_device.node_id:
        pytest.skip("the live device carries no node id")
    node_id = live_device.node_id
    try:
        api.call(
            "device_attribute_set",
            "POST",
            params={"deviceId": node_id, "attributeKey": PROBE_KEY},
            body={"value": "probe"},
        )
    except Exception:
        return False
    try:
        api.call(
            "device_attribute_delete",
            "DELETE",
            params={"deviceId": node_id, "attributeKey": PROBE_KEY},
        )
    finally:
        _clear(api, node_id)
    return True


def _options(credentials: dict[str, str], device: Any, attributes: list[dict[str, Any]]) -> dict:
    return {
        **credentials,
        "device_name": device.name.split(".", 1)[0],
        "attributes": attributes,
    }


def test_a_device_with_no_custom_attributes_reports_an_empty_map(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    live_device: Any,
) -> None:
    """The read returns a map, and the service-managed node: attributes are not it."""
    node_id = live_device.node_id
    _clear(api, node_id)
    stored = _read(api, node_id)
    assert stored.get("attributes"), "a real device carries node: attributes"

    module_args(_options(credentials, live_device, []))

    with module_result.success() as result:
        tailscale_device_attributes.main()

    assert result["changed"] is False
    assert result["attributes"] == {}, "only the custom namespace is managed"
    assert result["changed_attributes"] == []
    assert result["device"]["id"] == node_id


def test_a_check_run_reports_the_change_a_write_would_make(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    live_device: Any,
) -> None:
    """Check mode computes the merge from the read and writes nothing.

    This is the one write-shaped path a plan that refuses the feature still
    reaches, because check mode stops before the request.
    """
    node_id = live_device.node_id
    _clear(api, node_id)
    before = _custom(api, node_id)

    module_args(
        _options(credentials, live_device, [{"key": PROBE_KEY, "value": "check_value"}]),
        check_mode=True,
    )

    with module_result.success() as result:
        tailscale_device_attributes.main()

    assert result["changed"] is True
    assert result["changed_attributes"] == [PROBE_KEY]
    assert result["diff"]["before"] == {PROBE_KEY: None}
    assert result["diff"]["after"] == {PROBE_KEY: "check_value"}
    assert _custom(api, node_id) == before, "check mode wrote nothing"


def test_a_system_attribute_is_refused_without_touching_the_tailnet(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    live_device: Any,
) -> None:
    """A node: attribute is read-only, and the refusal names the custom namespace."""
    node_id = live_device.node_id
    before = _read(api, node_id)

    module_args(_options(credentials, live_device, [{"key": "node:os", "value": "linux"}]))

    with module_result.failure() as result:
        tailscale_device_attributes.main()

    assert "custom:" in result["msg"]
    assert "Traceback" not in result["msg"]
    assert _read(api, node_id) == before


def test_a_selector_naming_no_device_is_refused(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """A device that is not there is a stale playbook, not a state to reach."""
    module_args(
        {
            **credentials,
            "device_name": "ac-no-such-device",
            "attributes": [{"key": PROBE_KEY, "value": "x"}],
        }
    )

    with module_result.failure() as result:
        tailscale_device_attributes.main()

    assert "ac-no-such-device" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_no_credential_is_refused_before_any_request(
    module_args: Any, module_result: Any, live_device: Any
) -> None:
    module_args(
        {
            "device_name": live_device.name.split(".", 1)[0],
            "attributes": [{"key": PROBE_KEY, "value": "x"}],
        }
    )

    with module_result.failure() as result:
        tailscale_device_attributes.main()

    assert "api_token" in result["msg"] or "oauth_client_id" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_refused_write_surfaces_the_servers_reason(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    live_device: Any,
    attribute_writes: bool,
) -> None:
    """On a plan that does not offer the feature, the refusal must reach the operator.

    The module has no remedy, which is correct: a plan limit is not something a
    module can fix. What it owes is the server's own reason, intact and scrubbed,
    with nothing written.
    """
    if attribute_writes:
        pytest.skip("this tailnet accepts custom attribute writes")

    node_id = live_device.node_id
    before = _read(api, node_id)

    module_args(_options(credentials, live_device, [{"key": PROBE_KEY, "value": "x"}]))

    with module_result.failure() as result:
        tailscale_device_attributes.main()

    message = result["msg"]
    assert PLAN_REFUSAL in message, "the server's reason reaches the operator"
    assert "Traceback" not in message
    for secret in credentials.values():
        assert secret not in message
    assert _read(api, node_id) == before, "and nothing was written"


def test_a_custom_attribute_round_trips_and_converges(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    live_device: Any,
    attribute_writes: bool,
) -> None:
    """Set an attribute, read it back, then set it again and expect no change.

    Skipped where the plan refuses the write, which is the state this suite's
    tailnet is in. On a tailnet that offers the feature this is the whole
    reconcile, including the merge property: an attribute the task does not name
    is left alone.
    """
    if not attribute_writes:
        pytest.skip("this tailnet refuses custom attribute writes")

    node_id = live_device.node_id
    _clear(api, node_id)
    options = _options(credentials, live_device, [{"key": PROBE_KEY, "value": "round_trip"}])

    try:
        module_args(options)
        with module_result.success() as first:
            tailscale_device_attributes.main()

        assert first["changed"] is True
        assert first["attributes"] == {PROBE_KEY: "round_trip"}
        assert _custom(api, node_id) == {PROBE_KEY: "round_trip"}

        module_args(options)
        with module_result.success() as second:
            tailscale_device_attributes.main()

        assert second["changed"] is False, "the device already holds this"
    finally:
        _clear(api, node_id)


def test_a_deletion_removes_the_attribute(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    live_device: Any,
    attribute_writes: bool,
) -> None:
    if not attribute_writes:
        pytest.skip("this tailnet refuses custom attribute writes")

    node_id = live_device.node_id
    _clear(api, node_id)
    api.call(
        "device_attribute_set",
        "POST",
        params={"deviceId": node_id, "attributeKey": PROBE_KEY},
        body={"value": "to_remove"},
    )
    try:
        module_args(_options(credentials, live_device, [{"key": PROBE_KEY, "state": "absent"}]))
        with module_result.success() as result:
            tailscale_device_attributes.main()

        assert result["changed"] is True
        assert result["attributes"] == {}
        assert _custom(api, node_id) == {}
    finally:
        _clear(api, node_id)


def test_a_value_the_plan_stores_round_trips_in_type(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    live_device: Any,
    attribute_writes: bool,
) -> None:
    """A boolean and an integer must come back as themselves, not as strings.

    Asserted against the API's read rather than the module's return, because a
    value sent under the wrong type is stored as that type rather than refused.
    """
    if not attribute_writes:
        pytest.skip("this tailnet refuses custom attribute writes")

    node_id = live_device.node_id
    _clear(api, node_id)
    boolean_key = "custom:probeBoolean"
    number_key = "custom:probeNumber"
    try:
        module_args(
            _options(
                credentials,
                live_device,
                [
                    {"key": boolean_key, "value": True},
                    {"key": number_key, "value": 80},
                ],
            )
        )
        with module_result.success():
            tailscale_device_attributes.main()

        stored = _custom(api, node_id)
        assert stored.get(boolean_key) is True
        assert stored.get(number_key) == 80
    finally:
        _clear(api, node_id)
