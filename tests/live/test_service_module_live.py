# SPDX-License-Identifier: BSD-2-Clause
"""`tailscale_service` against a real tailnet, through the module.

Every assertion drives the module's ``main()``, never the kernel.

The endpoint is not a whole-document endpoint like the policy or the DNS
configuration, so ``preserved`` has no accessor for it and is not used here. What
a Service needs instead is a deletion, and every test that creates one takes it
through :func:`a_service`, which registers the removal with the session teardown
before the Service exists and deletes it in a ``finally`` whatever happens.

Three behaviours measured against the real API decide what this file asserts, and
each has a test that fails if the module stops relying on it:

* the server assigns the addresses, so a Service the task did not declare them
  for comes back holding a pair;
* an update has to carry both addresses back, or the API refuses it, so the
  module merges rather than replacing;
* the server stores an empty comment, display name or tag list as an absent key.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleNotFound,
)
from ansible_collections.abn.tailscale.plugins.modules import tailscale_service
from ansible_collections.abn.tailscale.tests.live.conftest import PREFIX
from ansible_collections.abn.tailscale.tests.live.conftest import PROBE_TAG
from ansible_collections.abn.tailscale.tests.live.conftest import Device
from ansible_collections.abn.tailscale.tests.live.conftest import Teardown

pytestmark = pytest.mark.live_smoke

#: A tag no policy in this tailnet grants, so the API refuses it. The name is
#: deliberately unlike any tag a tailnet would own.
UNOWNED_TAG = "tag:no-such-owner-exists"

#: A Service name carrying the harness prefix, so a leak is identifiable.
NAME = f"svc:{PREFIX}-web"

#: A TailVIP the task asks for by name, at the bottom of the range the API accepts
#: it from. A fixed address rather than one picked per run, because a test that
#: chose a free address could not prove it chose anything: this asserts the API
#: honours the request. Measured: much of 100.64.0.0/10 is reserved for Tailscale's
#: own use and refused, and this one is not. The only way this fails is a collision
#: with a Service another run created on the same address.
CHOSEN_IPV4 = "100.64.0.7"


def _run(
    module_args: Any, module_result: Any, options: dict[str, Any], **flags: Any
) -> dict[str, Any]:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_service.main()
    return dict(result)


def _stored(api: Api, name: str = NAME) -> dict[str, Any]:
    body = api.call("service_get", "GET", params={"serviceName": name}).body
    return body if isinstance(body, dict) else {}


@contextlib.contextmanager
def a_service(api: Api, teardown: Teardown, name: str = NAME) -> Iterator[None]:
    """Yield with no Service by this name, and remove whatever the body creates.

    Registered with the session teardown before the body runs, because a Service
    is a DNS name in the tailnet and a leaked one outlives the run. The
    registration tolerates a Service that never appears, which is what makes it
    safe to make before the fact.
    """

    def remove() -> None:
        try:
            api.call("service_delete", "DELETE", params={"serviceName": name})
        except TailscaleNotFound:
            # A Service that is already gone is the wanted state, and a teardown
            # step that raises would stop the ones registered after it.
            return

    teardown.register(f"service {name}", remove)
    remove()
    try:
        yield
    finally:
        remove()


def test_a_service_is_created_and_the_same_task_then_converges(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
    probe_policy: dict[str, Any],
) -> None:
    """The property the product is: a second run over the same task is quiet."""
    with a_service(api, teardown):
        options = {
            **credentials,
            "name": NAME,
            "display_name": "Web front end",
            "comment": "fronted by nginx",
            "ports": ["tcp:443"],
            "tags": [PROBE_TAG],
        }

        first = _run(module_args, module_result, options, diff=True)
        second = _run(module_args, module_result, options)

        assert first["changed"] is True
        assert first["diff"]["after"]["comment"] == "fronted by nginx"
        assert second["changed"] is False, f"stored service is {_stored(api)!r}"


def test_every_field_survives_the_round_trip_in_the_api_spelling(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
    probe_policy: dict[str, Any],
) -> None:
    """The module's snake_case options have to arrive as the API's camel case.

    Asserted by reading the Service back through the API, because that is where a
    translation bug would show up and nowhere else: a field sent under the wrong
    name is ignored rather than refused.
    """
    with a_service(api, teardown):
        _run(
            module_args,
            module_result,
            {
                **credentials,
                "name": NAME,
                "display_name": "Web front end",
                "comment": "fronted by nginx",
                "ports": ["tcp:443", "tcp:80"],
                "tags": [PROBE_TAG],
            },
        )

        stored = _stored(api)
        assert stored["name"] == NAME
        assert stored["displayName"] == "Web front end"
        assert stored["comment"] == "fronted by nginx"
        assert stored["ports"] == ["tcp:443", "tcp:80"]
        assert stored["tags"] == [PROBE_TAG]


def test_the_addresses_the_server_assigned_are_returned_and_converge(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    """A field the task did not declare comes back changed, and must not be compared.

    The server assigns both addresses on a create. A module that compared the
    request against the Service would then report a change for ever, which is
    exactly the trap the live suite found in `tailscale_dns`.
    """
    with a_service(api, teardown):
        first = _run(
            module_args, module_result, {**credentials, "name": NAME, "ports": ["tcp:443"]}
        )

        addrs = first["service"]["addrs"]
        assert len(addrs) == 2, f"the server assigns a pair, and it sent {addrs!r}"
        assert ":" not in addrs[0], "the IPv4 comes first"
        assert addrs[1].startswith("fd7a:"), "and the IPv6 after it"
        assert "addrs" not in first["diff"]["after"], "a check run cannot know them either"

        second = _run(
            module_args, module_result, {**credentials, "name": NAME, "ports": ["tcp:443"]}
        )
        assert second["changed"] is False, (
            f"stored service is {_stored(api)!r}, and an address the task never asked for "
            "must not be a difference"
        )


def test_an_update_carries_the_addresses_back_and_keeps_them(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    """The update rule the merge exists for: an update must carry both addresses.

    Measured: a PUT that names only a comment and carries no `addrs` is refused
    with "when updating a service, addrs must contain 2 elements", and so is one
    carrying a single address. The module sends the pair the Service holds.
    """
    with a_service(api, teardown):
        _run(module_args, module_result, {**credentials, "name": NAME, "ports": ["tcp:443"]})
        before = _stored(api)["addrs"]

        result = _run(
            module_args,
            module_result,
            {**credentials, "name": NAME, "comment": "moved to the eu cluster"},
        )

        assert result["changed"] is True
        assert _stored(api)["addrs"] == before, "the TailVIPs are the same pair"
        assert _stored(api)["comment"] == "moved to the eu cluster"


def test_an_option_the_task_left_out_is_not_cleared(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
    probe_policy: dict[str, Any],
) -> None:
    """The claim the module's documentation makes, against a replace endpoint.

    The PUT replaces the Service, so an omitted field is not "leave it alone" by
    the server's doing, it is "send the previous value" by the module's.
    """
    with a_service(api, teardown):
        both = {
            **credentials,
            "name": NAME,
            "display_name": "Web front end",
            "ports": ["tcp:443"],
            "tags": [PROBE_TAG],
        }
        _run(module_args, module_result, both)

        result = _run(
            module_args,
            module_result,
            {**credentials, "name": NAME, "comment": "moved to the eu cluster"},
        )

        assert result["changed"] is True
        after = _stored(api)
        assert after["comment"] == "moved to the eu cluster"
        assert after["displayName"] == "Web front end", "the label survived"
        assert after["ports"] == ["tcp:443"], "and so did the ports"
        assert after["tags"] == [PROBE_TAG], "and the tags"

        again = _run(
            module_args,
            module_result,
            {**credentials, "name": NAME, "comment": "moved to the eu cluster"},
        )
        assert again["changed"] is False, f"stored service is {after!r}"


def test_an_empty_string_clears_the_comment_and_then_converges(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    """The asymmetry that decides how "clear" is spelled.

    Measured: a comment sent as an empty string is stored as an absent key. So
    `comment: ''` and no comment at all are the same state, and a module that
    sent the empty string would differ from the tailnet on every run.
    """
    with a_service(api, teardown):
        _run(
            module_args,
            module_result,
            {**credentials, "name": NAME, "ports": ["tcp:443"], "comment": "fronted by nginx"},
        )
        assert _stored(api)["comment"] == "fronted by nginx"

        result = _run(
            module_args,
            module_result,
            {**credentials, "name": NAME, "ports": ["tcp:443"], "comment": ""},
        )
        assert result["changed"] is True
        assert "comment" not in _stored(api), "the server stores a cleared comment as absent"

        again = _run(
            module_args,
            module_result,
            {**credentials, "name": NAME, "ports": ["tcp:443"], "comment": ""},
        )
        assert again["changed"] is False, (
            f"stored service is {_stored(api)!r}, and asking for no comment must converge on it"
        )


def test_a_service_with_no_comment_converges_on_an_empty_string(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    """Empty and absent are the same state, so clearing what is not there is quiet."""
    with a_service(api, teardown):
        _run(module_args, module_result, {**credentials, "name": NAME, "ports": ["tcp:443"]})
        assert "comment" not in _stored(api)

        result = _run(module_args, module_result, {**credentials, "name": NAME, "comment": ""})
        assert result["changed"] is False


def test_a_declared_ipv4_is_assigned_on_a_create(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    """The one address the task can choose, which the server then honours."""
    with a_service(api, teardown):
        result = _run(
            module_args,
            module_result,
            {
                **credentials,
                "name": NAME,
                "ports": ["tcp:443"],
                "addrs": [CHOSEN_IPV4],
            },
        )

        assert result["service"]["addrs"][0] == CHOSEN_IPV4
        assert result["service"]["addrs"][1].startswith("fd7a:"), "the IPv6 is the server's"


def test_a_tag_the_policy_does_not_own_is_refused_with_the_reason(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    """A tag on a Service is access control, and a tag that does not exist is refused.

    `tagOwners` in the policy is what makes a tag exist, and the harness installs
    `tag:stress` there. A tag that is not granted produces a 400 whose message
    names the tag, and the collection turns that into the sentence that says what
    to do about it.
    """
    with a_service(api, teardown):
        module_args(
            {
                **credentials,
                "name": NAME,
                "ports": ["tcp:443"],
                "tags": [UNOWNED_TAG],
            }
        )
        with module_result.failure() as result:
            tailscale_service.main()

    assert UNOWNED_TAG in result["msg"]
    assert "tagOwners" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_check_mode_writes_nothing(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
    probe_policy: dict[str, Any],
) -> None:
    with a_service(api, teardown):
        result = _run(
            module_args,
            module_result,
            {**credentials, "name": NAME, "ports": ["tcp:443"], "tags": [PROBE_TAG]},
            check_mode=True,
        )

        assert result["changed"] is True
        assert result["diff"]["after"]["ports"] == ["tcp:443"]
        assert result["hosts"] == []
        with pytest.raises(TailscaleNotFound):
            _stored(api)


def test_check_mode_over_a_service_already_in_place_is_quiet(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
    probe_policy: dict[str, Any],
) -> None:
    """The first thing an operator does."""
    with a_service(api, teardown):
        options = {**credentials, "name": NAME, "ports": ["tcp:443"], "tags": [PROBE_TAG]}
        _run(module_args, module_result, options)

        result = _run(module_args, module_result, options, check_mode=True)

        assert result["changed"] is False
        assert result["service"]["addrs"] == _stored(api)["addrs"]


def test_the_returned_service_is_the_one_the_tailnet_holds(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
    probe_policy: dict[str, Any],
) -> None:
    """`service` must be what is there, not what was asked for.

    On a replace endpoint those differ whenever the server assigns, normalises
    or drops, and a module that returned the request would report a Service that
    nobody holds.
    """
    with a_service(api, teardown):
        result = _run(
            module_args,
            module_result,
            {
                **credentials,
                "name": NAME,
                "ports": ["tcp:443"],
                "tags": [PROBE_TAG],
                "comment": "fronted by nginx",
            },
        )
        after = _run(
            module_args,
            module_result,
            {**credentials, "name": NAME, "comment": "moved to the eu cluster"},
        )

        assert result["service"] != _stored(api), "the comment did change"
        assert after["service"] == _stored(api)


def test_hosts_are_empty_until_a_device_advertises_the_endpoint(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    """A Service is nothing but a name until a tagged device advertises it.

    Advertising is node-side configuration, which no Admin API endpoint does, so
    the host list is empty for a Service this suite creates. What the API answers
    is an absent `hosts` key rather than an empty list, and the module reports
    that as an empty list rather than as a missing key.

    The approval tests below cover the write the Admin API does offer on a device.
    """
    with a_service(api, teardown):
        result = _run(
            module_args, module_result, {**credentials, "name": NAME, "ports": ["tcp:443"]}
        )

        assert result["hosts"] == []
        hosts = api.call("service_hosts_list", "GET", params={"serviceName": NAME}).body
        assert hosts == {}, f"and the endpoint itself says so, with {hosts!r}"


def test_a_service_is_removed_and_a_second_run_is_quiet(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    """Removal takes the DNS name with it, and a second run must be quiet.

    The 404 on the second run is the answer to "is it there", not a failure, so
    the state is reached rather than reported as an error every time after it.
    """
    with a_service(api, teardown):
        _run(module_args, module_result, {**credentials, "name": NAME, "ports": ["tcp:443"]})
        before = _stored(api)

        first = _run(module_args, module_result, {**credentials, "name": NAME, "state": "absent"})
        assert first["changed"] is True
        assert first["diff"]["before"] == before
        assert first["diff"]["after"] is None
        assert "service" not in first

        second = _run(module_args, module_result, {**credentials, "name": NAME, "state": "absent"})
        assert second["changed"] is False, "a run over a Service that is gone is quiet"


def test_removing_a_service_that_was_never_there_is_quiet(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    with a_service(api, teardown):
        result = _run(module_args, module_result, {**credentials, "name": NAME, "state": "absent"})

        assert result["changed"] is False
        assert result["diff"]["before"] is None


def test_check_mode_removes_nothing(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    with a_service(api, teardown):
        _run(module_args, module_result, {**credentials, "name": NAME, "ports": ["tcp:443"]})

        result = _run(
            module_args,
            module_result,
            {**credentials, "name": NAME, "state": "absent"},
            check_mode=True,
        )

        assert result["changed"] is True
        assert _stored(api), "and the Service is still there"


def test_a_device_is_approved_and_the_same_task_then_converges(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
    live_device: Device,
) -> None:
    """Approving a host is a real access control action, and it is idempotent.

    A device the API cannot see is a refusal rather than a state to reconcile, so
    this uses a device that exists: the harness generated it.
    """
    with a_service(api, teardown):
        _run(module_args, module_result, {**credentials, "name": NAME, "ports": ["tcp:443"]})
        options = {**credentials, "name": NAME, "device_id": live_device.node_id, "approved": True}

        first = _run(module_args, module_result, options)
        second = _run(module_args, module_result, options)

        assert first["changed"] is True
        assert first["approval"]["approved"] is True
        assert "autoApproved" in first["approval"]
        assert second["changed"] is False, "an approval already in place is quiet"


def test_a_host_named_by_its_device_name_is_approved(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
    live_device: Device,
) -> None:
    """A host role knows its own name, not the node id the endpoint is addressed with."""
    with a_service(api, teardown):
        _run(module_args, module_result, {**credentials, "name": NAME, "ports": ["tcp:443"]})
        options = {
            **credentials,
            "name": NAME,
            "device_name": live_device.name,
            "approved": True,
        }

        first = _run(module_args, module_result, options)
        second = _run(module_args, module_result, options)

        assert first["changed"] is True
        assert first["approval"]["approved"] is True
        assert second["changed"] is False, "the id the name resolved to converges like any other"


def test_an_approval_never_touches_the_service(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
    live_device: Device,
) -> None:
    """Two resources, so a task about one does not write the other."""
    with a_service(api, teardown):
        _run(
            module_args,
            module_result,
            {**credentials, "name": NAME, "ports": ["tcp:443"], "tags": [PROBE_TAG]},
        )
        before = _stored(api)

        result = _run(
            module_args,
            module_result,
            {**credentials, "name": NAME, "device_id": live_device.node_id, "approved": True},
        )

        assert result["changed"] is True
        assert _stored(api) == before, "and the Service is untouched"


def test_a_revocation_is_a_write_and_then_converges(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
    live_device: Device,
) -> None:
    """Unlike the rest of a Service, the API stores a false here as a real false.

    Measured: the approval record reads `{"approved": false}` back rather than
    dropping the key, so a task that revokes an approval has a state to converge
    on.
    """
    with a_service(api, teardown):
        _run(module_args, module_result, {**credentials, "name": NAME, "ports": ["tcp:443"]})
        approve = {**credentials, "name": NAME, "device_id": live_device.node_id, "approved": True}
        revoke = {**approve, "approved": False}
        _run(module_args, module_result, approve)

        result = _run(module_args, module_result, revoke)

        assert result["changed"] is True
        assert result["approval"]["approved"] is False
        assert result["diff"]["before"]["approved"] is True
        assert result["diff"]["after"]["approved"] is False

        again = _run(module_args, module_result, revoke)
        assert again["changed"] is False, "a revoked approval is a state, and it is reached"


def test_check_mode_approves_nothing(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
    live_device: Device,
) -> None:
    with a_service(api, teardown):
        _run(module_args, module_result, {**credentials, "name": NAME, "ports": ["tcp:443"]})
        device_id = live_device.node_id
        options = {**credentials, "name": NAME, "device_id": device_id, "approved": True}

        result = _run(module_args, module_result, options, check_mode=True)

        assert result["changed"] is True
        assert result["approval"]["approved"] is True

        # The record itself is the only evidence, and it is read through the API
        # rather than the module so the check run's silence is what is asserted.
        record = api.call(
            "service_approval_get", "GET", params={"serviceName": NAME, "deviceId": device_id}
        ).body
        assert record == {"approved": False, "autoApproved": False}, record


def test_a_device_the_api_does_not_know_is_an_error(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """A selector that matches nothing fails rather than reporting a success.

    A device the API cannot see is one that does not exist, or one shared in from
    another tailnet, and neither is a state an approval reconciles. The id is one
    no tailnet has: device ids are numeric and the harness generates its own.
    """
    module_args({**credentials, "name": NAME, "device_id": "1", "approved": True})
    with module_result.failure() as result:
        tailscale_service.main()

    assert NAME in result["msg"]
    assert "not in this tailnet" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_an_approval_for_a_service_that_does_not_exist_is_an_error(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    live_device: Device,
) -> None:
    module_args(
        {
            **credentials,
            "name": f"svc:{PREFIX}-absent",
            "device_id": live_device.node_id,
            "approved": True,
        }
    )
    with module_result.failure() as result:
        tailscale_service.main()

    assert "Traceback" not in result["msg"]


def test_an_empty_port_list_is_refused_before_any_request(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    """A create has to name a port, and the way out of the API's refusal is its own.

    Measured: the API refuses a Service with no ports, on a create as much as on
    an update, and answers "use do-not-validate to opt out of port validation".
    """
    with a_service(api, teardown):
        module_args({**credentials, "name": NAME, "ports": []})
        with module_result.failure() as result:
            tailscale_service.main()

    assert "do-not-validate" in result["msg"]


def test_a_create_naming_no_port_is_refused_with_the_way_out(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    with a_service(api, teardown):
        module_args({**credentials, "name": NAME})
        with module_result.failure() as result:
            tailscale_service.main()

    assert "do-not-validate" in result["msg"]


def test_one_address_for_a_service_that_exists_is_refused(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    with a_service(api, teardown):
        _run(module_args, module_result, {**credentials, "name": NAME, "ports": ["tcp:443"]})

        module_args({**credentials, "name": NAME, "addrs": [CHOSEN_IPV4]})
        with module_result.failure() as result:
            tailscale_service.main()

    assert "both its addresses" in result["msg"]


def test_no_credential_option_at_all_fails_before_any_request(
    module_args: Any, module_result: Any
) -> None:
    module_args({"name": NAME, "ports": ["tcp:443"]})
    with module_result.failure() as result:
        tailscale_service.main()

    assert "api_token" in result["msg"] or "oauth_client_id" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_credential_never_reaches_the_result(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    with a_service(api, teardown):
        result = _run(
            module_args, module_result, {**credentials, "name": NAME, "ports": ["tcp:443"]}
        )

        for secret in credentials.values():
            assert secret not in json.dumps(result, default=str)
