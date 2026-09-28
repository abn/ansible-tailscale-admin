# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the two device modules, driven through the harness.

A device cannot be created, so there is no create endpoint to stub. What these
tests are about is the two ways a device module can be quietly wrong: selecting
the wrong device, and reporting a change for a device that already holds what the
task asked for. The first is a write to the wrong machine and the second breaks
the collection's first invariant, so each has a test here that fails when the
guard is removed.
"""

from __future__ import annotations

import json
from typing import Any
from typing import ClassVar

import pytest
from ansible_collections.abn.tailscale.plugins.modules import tailscale_device
from ansible_collections.abn.tailscale.plugins.modules import tailscale_device_routes

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
BASE = "https://api.tailscale.com/api/v2"

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"

HOST = "ac-stress-0"
SUFFIX = "tail1234.ts.net"
OTHER_HOST = "ac-stress-1"
OTHER_ID = "nOTHER000000000CNTRL"


def _device(
    host: str = HOST,
    node_id: str = "nDEVICE000000000CNTRL",
    *,
    name: str | None = None,
    tags: list[str] | None = None,
    authorized: bool = False,
    key_expiry_disabled: bool = True,
    address: str = "100.100.100.1",
    expires: str = "2099-01-01T00:00:00Z",
) -> dict[str, Any]:
    """A device document in the field set the API's default selection returns.

    Written out rather than trimmed from a larger fixture, because the point of
    several of these tests is which fields are present and which are not.
    """
    entry: dict[str, Any] = {
        "id": "3133440773018733",
        "nodeId": node_id,
        "user": "",
        "name": name if name is not None else f"{host}.{SUFFIX}",
        "hostname": host,
        "clientVersion": "1.82.0",
        "os": "linux",
        "created": "2026-01-01T00:00:00Z",
        "connectedToControl": True,
        "keyExpiryDisabled": key_expiry_disabled,
        "authorized": authorized,
        "isExternal": False,
        "isEphemeral": True,
        "tags": list(tags) if tags is not None else ["tag:stress"],
        "addresses": [address, "fd7a:115c:a1e0::1"],
        "expires": expires,
    }
    return entry


def _device_list(*entries: dict[str, Any]) -> dict[str, Any]:
    return {"devices": list(entries)}


class Body:
    def __init__(self, text: str) -> None:
        self._text = text

    def decode(self, *args: str) -> str:
        return self._text


def _reply(status: int, text: str) -> Any:
    """What open_url answers with: one object, not a pair."""

    class Response:
        status: int
        headers: dict

        def __init__(self, status: int) -> None:
            self.status = status
            self.headers = {}

        def read(self) -> Body:
            return Body(text)

    return Response(status)


class Tailnet:
    """A tailnet holding a fixed set of devices, and nothing else.

    Every write is applied to the device it addressed, so a test that runs the
    module twice is reading a tailnet the first run actually changed rather than a
    stub that always answers the same. Without that, a module which compared
    nothing would still pass the second run.

    A device the API would refuse a write to answers 400, and the device document
    is left as it was, which is what the API does.
    """

    def __init__(self, devices: list[dict[str, Any]]) -> None:
        self.devices = {device["nodeId"]: device for device in devices}
        self.order = [device["nodeId"] for device in devices]
        self.writes: list[tuple[str, str, Any]] = []
        self.requests: list[str] = []
        self.refuse_tags: bool = False

    def _find(self, device_id: str) -> dict[str, Any] | None:
        for node_id, device in self.devices.items():
            if device_id in (node_id, device.get("id")):
                return device
        return None

    def _listing(self) -> dict[str, Any]:
        return _device_list(*(self.devices[node_id] for node_id in self.order))

    def _routes(self, device: dict[str, Any]) -> dict[str, Any]:
        return {
            "advertisedRoutes": list(device.get("advertisedRoutes") or []),
            "enabledRoutes": list(device.get("enabledRoutes") or []),
        }

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        self.requests.append(f"{method} {url}")
        body = json.loads(str(data)) if data else {}
        _origin, _slash, rest = url.partition("/device/")
        if not rest:
            return _reply(200, json.dumps(self._listing()))
        device_id, _slash, action = rest.partition("/")
        device = self._find(device_id)
        if device is None:
            return _reply(404, '{"message": "no manageable device matching this ID found"}')
        if method == "DELETE":
            del self.devices[device["nodeId"]]
            self.order.remove(device["nodeId"])
            return _reply(200, "{}")
        if method == "GET":
            if action == "routes":
                return _reply(200, json.dumps(self._routes(device)))
            return _reply(200, json.dumps(device))
        if action == "name":
            device["name"] = f"{body['name']}.{SUFFIX}"
        elif action == "tags":
            if not body.get("tags") and device.get("tags"):
                return _reply(400, '{"message": "tagged nodes cannot be untagged without reauth"}')
            device["tags"] = list(body.get("tags") or [])
        elif action == "authorized":
            device["authorized"] = bool(body.get("authorized"))
        elif action == "key":
            device["keyExpiryDisabled"] = bool(body.get("keyExpiryDisabled"))
        elif action == "ip":
            device["addresses"] = [body["ipv4"], "fd7a:115c:a1e0::1"]
        elif action == "routes":
            device["enabledRoutes"] = list(body.get("routes") or [])
        elif action == "expire":
            device["expires"] = "2020-01-01T00:00:00Z"
        else:
            return _reply(404, '{"message": "not found"}')
        self.writes.append((action, device_id, body))
        return _reply(200, json.dumps(device) if action in ("routes",) else "{}")


@pytest.fixture
def tailnet(mocker: Any) -> Any:
    net = Tailnet([_device()])
    mocker.patch(_API_URL, net)
    return net


def _run(module_args: Any, module_result: Any, options: dict[str, Any], **flags: Any) -> dict:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_device.main()
    return dict(result)


def _run_routes(
    module_args: Any, module_result: Any, options: dict[str, Any], **flags: Any
) -> dict:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_device_routes.main()
    return dict(result)


# ---------------------------------------------------------------- selection


def test_a_device_is_selected_by_its_name_label(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_name": HOST, "authorized": True},
    )
    assert [write[0] for write in tailnet.writes] == ["authorized"]


def test_a_device_is_selected_by_its_full_magic_dns_name(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    """Both spellings name the same device, because Tailscale shows one and people
    type the other."""
    _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_name": f"{HOST}.{SUFFIX}", "authorized": True},
    )
    assert [write[0] for write in tailnet.writes] == ["authorized"], (
        "a task naming the full MagicDNS name is naming the same device"
    )


def test_a_device_is_selected_by_its_node_id(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_id": "nDEVICE000000000CNTRL", "authorized": True},
    )
    assert [write[0] for write in tailnet.writes] == ["authorized"]


def test_a_device_is_selected_by_its_legacy_numeric_id(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_id": "3133440773018733", "authorized": True},
    )
    assert [write[0] for write in tailnet.writes] == ["authorized"]


def test_a_device_is_selected_by_either_address_family(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    for address in ("100.100.100.1", "fd7a:115c:a1e0::1"):
        net = Tailnet([_device()])
        mocker.patch(_API_URL, net)
        result = _run(
            module_args,
            module_result,
            {"api_token": TOKEN, "address": address, "authorized": True},
        )
        assert result["changed"] is True, address


def test_a_device_is_selected_by_a_tag_it_carries(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    _run(module_args, module_result, {"api_token": TOKEN, "tag": "tag:stress", "authorized": True})
    assert [write[0] for write in tailnet.writes] == ["authorized"]


def test_a_tag_the_device_does_not_carry_matches_nothing(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    module_args({"api_token": TOKEN, "tag": "tag:other", "authorized": True})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "tag:other" in result["msg"]


def test_naming_no_device_is_refused_before_any_request(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    """A selector that matched everything is the failure this module exists to avoid.

    The argument spec refuses it, which is the earliest point it can be refused: the
    module body never runs, so no credential is resolved and nothing is read.
    """
    module_args({"api_token": TOKEN, "authorized": True})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "one of the following is required" in result["msg"]
    assert "device_name" in result["msg"]
    assert tailnet.requests == [], "a task naming nothing must not read the tailnet either"


def test_naming_a_device_that_is_not_there_is_refused(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    module_args({"api_token": TOKEN, "device_name": "absent-host", "authorized": True})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "No device in the tailnet matches" in result["msg"]
    assert tailnet.writes == []


def test_a_selector_matching_several_devices_is_refused(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """A tag is usually held by more than one device, and picking one is a guess."""
    net = Tailnet([_device(), _device(OTHER_HOST, OTHER_ID)])
    mocker.patch(_API_URL, net)
    module_args({"api_token": TOKEN, "tag": "tag:stress", "authorized": True})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "2 devices match" in result["msg"]
    assert "device_id" in result["msg"], "the message has to say how to be precise"
    assert net.writes == []


def test_two_selectors_at_once_are_refused_by_the_spec(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    module_args({"api_token": TOKEN, "device_name": HOST, "tag": "tag:stress", "authorized": True})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "mutually exclusive" in result["msg"]
    assert tailnet.requests == []


# ---------------------------------------------------------------- properties


def test_a_property_already_correct_writes_nothing(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "authorized": False}
    )
    assert result["changed"] is False
    assert result["changed_devices"] == []
    assert tailnet.writes == []


def test_a_differing_property_is_written(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "authorized": True}
    )
    assert result["changed"] is True
    assert result["changed_devices"] == [
        {"id": "nDEVICE000000000CNTRL", "properties": ["authorized"]}
    ]
    assert tailnet.writes == [("authorized", "nDEVICE000000000CNTRL", {"authorized": True})]


def test_every_property_is_written_in_one_run(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {
            "api_token": TOKEN,
            "device_name": HOST,
            "name": "renamed-host",
            "tags": ["tag:stress", "tag:build"],
            "authorized": True,
            "key_expiry_disabled": False,
            "tailscale_ip": "100.100.100.9",
            "expire_key": True,
        },
    )
    assert result["changed"] is True
    assert result["changed_devices"][0]["properties"] == [
        "authorized",
        "expire_key",
        "key_expiry_disabled",
        "name",
        "tags",
        "tailscale_ip",
    ]
    assert [write[0] for write in tailnet.writes] == [
        "name",
        "tags",
        "authorized",
        "key",
        "ip",
        "expire",
    ]


def test_only_the_options_given_are_sent(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    _run(module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "authorized": True})
    assert [write[0] for write in tailnet.writes] == ["authorized"]


def test_tags_are_compared_without_regard_to_order(
    module_args: Any, module_result: Any, tailnet: Any, mocker: Any
) -> None:
    """The API returns tags in its own order, so an ordered compare never converges."""
    net = Tailnet([_device(tags=["tag:a", "tag:b"])])
    mocker.patch(_API_URL, net)
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_name": HOST, "tags": ["tag:b", "tag:a"]},
    )
    assert result["changed"] is False, "the same set in another order is the same set"


def test_clearing_the_tags_of_a_device_that_has_none_writes_nothing(
    module_args: Any, module_result: Any, tailnet: Any, mocker: Any
) -> None:
    """The API stores an untagged device as an absent key, so both read as empty."""
    net = Tailnet([_device(tags=[])])
    mocker.patch(_API_URL, net)
    result = _run(module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "tags": []})
    assert result["changed"] is False


def test_taking_the_last_tag_off_is_the_api_s_refusal_not_a_change(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    module_args({"api_token": TOKEN, "device_name": HOST, "tags": []})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "tagOwners" in result["msg"] or "tag" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_the_reported_device_is_what_the_tailnet_holds_after_the_write(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    """A name is stored with the tailnet's suffix on it, which the request did not have."""
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_name": HOST, "name": "renamed-host"},
    )
    assert result["devices"][0]["name"] == f"renamed-host.{SUFFIX}"


def test_a_change_carries_the_values_a_diff_renders_from(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_name": HOST, "authorized": True},
        diff=True,
    )
    assert result["diff"]["before"] == {"nDEVICE000000000CNTRL": {"authorized": False}}
    assert result["diff"]["after"] == {"nDEVICE000000000CNTRL": {"authorized": True}}


def test_the_diff_covers_only_the_properties_this_run_changed(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_name": HOST, "authorized": True, "tags": ["tag:stress"]},
    )
    assert set(result["diff"]["before"]["nDEVICE000000000CNTRL"]) == {"authorized"}


def test_an_unmanaged_field_cannot_report_a_change(
    module_args: Any, module_result: Any, tailnet: Any, mocker: Any
) -> None:
    noisy = dict(_device(), blocksIncomingConnections=True, postureIdentity={"disabled": True})
    net = Tailnet([noisy])
    mocker.patch(_API_URL, net)
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "authorized": False}
    )
    assert result["changed"] is False


# ---------------------------------------------------------------- names


@pytest.mark.parametrize(
    "name",
    ["UPPER", "under_score", "dotted.name", "trailing-", "-leading", "double--dash", "with space"],
)
def test_a_name_the_server_would_rewrite_is_refused(
    module_args: Any, module_result: Any, tailnet: Any, name: str
) -> None:
    module_args({"api_token": TOKEN, "device_name": HOST, "name": name})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "change on every run" in result["msg"]
    assert tailnet.writes == []


def test_a_name_that_is_already_the_right_label_writes_nothing(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "name": HOST}
    )
    assert result["changed"] is False
    assert tailnet.writes == []


def test_an_over_long_name_is_refused(module_args: Any, module_result: Any, tailnet: Any) -> None:
    module_args({"api_token": TOKEN, "device_name": HOST, "name": "a" * 64})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "63 characters" in result["msg"]


def test_a_renamed_device_is_still_found_by_its_original_label(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    """The API's `hostname` does not follow a rename, so selecting by name means the
    label, and the label does move."""
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_id": "nDEVICE000000000CNTRL", "name": "renamed-host"},
    )
    assert result["changed"] is True
    again = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_name": "renamed-host", "authorized": True},
    )
    assert again["changed"] is True
    assert [write[0] for write in tailnet.writes] == ["name", "authorized"]


def test_an_address_the_api_would_reject_is_refused_before_a_request(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    module_args({"api_token": TOKEN, "device_name": HOST, "tailscale_ip": "not-an-address"})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "IPv4" in result["msg"]
    assert tailnet.requests == []


# ---------------------------------------------------------------- key expiry


def test_a_key_that_has_not_expired_is_expired(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "expire_key": True}
    )
    assert result["changed"] is True
    assert [write[0] for write in tailnet.writes] == ["expire"]


def test_a_key_that_has_already_expired_is_not_expired_again(
    module_args: Any, module_result: Any, tailnet: Any, mocker: Any
) -> None:
    """Expiring a key is an action, and the API's own timestamp is what makes it
    converge rather than report a change on every run."""
    net = Tailnet([_device(expires="2020-01-01T00:00:00Z")])
    mocker.patch(_API_URL, net)
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "expire_key": True}
    )
    assert result["changed"] is False
    assert net.writes == []


def test_expire_key_false_is_not_an_instruction_to_expire(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "expire_key": False}
    )
    assert result["changed"] is False
    assert tailnet.writes == []


def test_expiring_then_running_again_converges(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    options = {"api_token": TOKEN, "device_name": HOST, "expire_key": True}
    assert _run(module_args, module_result, options)["changed"] is True
    assert _run(module_args, module_result, options)["changed"] is False


# ---------------------------------------------------------------- deletion


def test_a_deleted_device_is_reported_and_its_diff_shows_the_removal(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "state": "absent"}
    )
    assert result["changed"] is True
    assert result["changed_devices"] == [{"id": "nDEVICE000000000CNTRL", "properties": ["exists"]}]
    assert result["devices"][0]["hostname"] == HOST, "what was removed has to be nameable"
    assert result["diff"] == {
        "before": {"nDEVICE000000000CNTRL": {"exists": True}},
        "after": {},
    }
    assert [request for request in tailnet.requests if request.startswith("DELETE")] == [
        f"DELETE {BASE}/device/nDEVICE000000000CNTRL"
    ]


def test_a_second_deletion_of_the_same_selector_reports_no_change(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    """The invariant, for a deletion: a device that is gone is not found twice."""
    options = {"api_token": TOKEN, "device_name": HOST, "state": "absent"}
    assert _run(module_args, module_result, options)["changed"] is True
    second = _run(module_args, module_result, options)
    assert second["changed"] is False
    assert second["devices"] == []
    assert second["diff"] == {"before": {}, "after": {}}


def test_a_deletion_matching_nothing_is_not_a_failure(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_name": "never-existed", "state": "absent"},
    )
    assert result["changed"] is False
    assert tailnet.writes == []


def test_a_deletion_matching_several_removes_all_of_them(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """Under absent the intent is that nothing matching is left, so a set is the ask."""
    net = Tailnet([_device(), _device(OTHER_HOST, OTHER_ID)])
    mocker.patch(_API_URL, net)
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "tag": "tag:stress", "state": "absent"}
    )
    assert result["changed"] is True
    assert len(result["changed_devices"]) == 2
    assert net.devices == {}


def test_a_device_that_vanished_before_the_delete_is_not_a_failure(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """An ephemeral device removes itself on disconnect, so a delete can lose a race."""
    net = Tailnet([_device()])

    def racing(
        url: str, data: Any = None, headers: Any = None, method: str = "GET", **kw: Any
    ) -> Any:
        if method == "DELETE":
            net.devices.clear()
            return _reply(404, '{"message": "not found"}')
        return net(url, data=data, headers=headers, method=method, **kw)

    mocker.patch(_API_URL, racing)
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "state": "absent"}
    )
    assert result["changed"] is False, "the device is gone, which is what was asked for"
    assert result["devices"] == []


def test_a_device_that_vanished_between_the_write_and_the_read_back_is_reported(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """Expiring a key can push an ephemeral device off the tailnet before the module
    reads it back, and that is the write having worked rather than the run failing."""
    net = Tailnet([_device()])

    def vanishing(
        url: str, data: Any = None, headers: Any = None, method: str = "GET", **kw: Any
    ) -> Any:
        reply = net(url, data=data, headers=headers, method=method, **kw)
        if method == "POST":
            net.devices.clear()
        return reply

    mocker.patch(_API_URL, vanishing)
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "authorized": True}
    )
    assert result["changed"] is True
    assert result["devices"][0]["nodeId"] == "nDEVICE000000000CNTRL", (
        "the device as the run read it, rather than nothing"
    )


def test_a_property_alongside_a_deletion_is_refused(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    module_args({"api_token": TOKEN, "device_name": HOST, "state": "absent", "authorized": True})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "authorized" in result["msg"]
    assert tailnet.writes == []


def test_expiring_a_key_alongside_a_deletion_is_refused(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    module_args({"api_token": TOKEN, "device_name": HOST, "state": "absent", "expire_key": True})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "expire_key" in result["msg"]


# ---------------------------------------------------------------- convergence


def test_running_twice_converges(module_args: Any, module_result: Any, tailnet: Any) -> None:
    options = {
        "api_token": TOKEN,
        "device_name": HOST,
        "tags": ["tag:stress", "tag:build"],
        "authorized": True,
        "key_expiry_disabled": False,
    }
    first = _run(module_args, module_result, options)
    assert first["changed"] is True
    second = _run(module_args, module_result, options)
    assert second["changed"] is False, "a second run over identical input must not change"
    assert second["diff"]["before"] == second["diff"]["after"]
    assert len(tailnet.writes) == 3


def test_a_rename_converges_when_the_device_is_selected_by_id(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    """A task that renames has to select by something the rename does not change.

    Selecting by the name it is changing is refused on the second run, because the
    name it selects on has moved, and a task that names a device which is not there
    is a failure rather than a quiet one.
    """
    options = {"api_token": TOKEN, "device_id": "nDEVICE000000000CNTRL", "name": "renamed-host"}
    assert _run(module_args, module_result, options)["changed"] is True
    second = _run(module_args, module_result, options)
    assert second["changed"] is False
    assert [write[0] for write in tailnet.writes] == ["name"]


def test_a_rename_selected_by_the_old_name_is_refused_rather_than_guessed(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    """The documented reason a rename has to be selected by ID, asserted rather than
    left as a warning in prose."""
    _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_id": "nDEVICE000000000CNTRL", "name": "renamed-host"},
    )
    module_args({"api_token": TOKEN, "device_name": HOST, "authorized": True})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "No device in the tailnet matches" in result["msg"]


def test_a_run_after_a_rename_still_finds_the_device_by_its_new_name(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_id": "nDEVICE000000000CNTRL", "name": "renamed-host"},
    )
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_name": "renamed-host", "name": "renamed-host"},
    )
    assert result["changed"] is False


# ---------------------------------------------------------------- check mode


def test_check_mode_writes_nothing(module_args: Any, module_result: Any, tailnet: Any) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_name": HOST, "authorized": True},
        check_mode=True,
    )
    assert result["changed"] is True
    assert result["changed_devices"][0]["properties"] == ["authorized"]
    assert result["diff"]["after"] == {"nDEVICE000000000CNTRL": {"authorized": True}}
    assert tailnet.writes == []


def test_check_mode_over_a_device_already_in_place_reports_no_change(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    options = {"api_token": TOKEN, "device_name": HOST, "authorized": True}
    _run(module_args, module_result, options)
    assert _run(module_args, module_result, options, check_mode=True)["changed"] is False


def test_check_mode_deletes_nothing(module_args: Any, module_result: Any, tailnet: Any) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_name": HOST, "state": "absent"},
        check_mode=True,
    )
    assert result["changed"] is True
    assert tailnet.writes == []
    assert list(tailnet.devices), "the device is still there"


# ---------------------------------------------------------------- plumbing


def test_a_missing_credential_fails_before_any_request(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    module_args({"device_name": HOST, "authorized": True})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "api_token" in result["msg"]
    assert tailnet.requests == []


def test_a_credential_never_reaches_the_result(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "authorized": True}
    )
    assert TOKEN not in json.dumps(result, default=str)


def test_a_refused_name_never_carries_the_credential(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    module_args({"api_token": TOKEN, "device_name": HOST, "name": "NOT VALID"})
    with module_result.failure() as result:
        tailscale_device.main()
    assert TOKEN not in result["msg"]


def test_an_unreadable_listing_fails_rather_than_matching_nothing(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """A listing this module cannot read must not be read as an empty tailnet."""

    class Html:
        status = 200
        headers: ClassVar[dict] = {}

        def read(self) -> Any:
            class _Body:
                def decode(self, *args: str) -> str:
                    return "<html>captive portal</html>"

            return _Body()

    mocker.patch(_API_URL, lambda *a, **k: Html())
    module_args({"api_token": TOKEN, "device_name": HOST, "authorized": True})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "could not read" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_tailnet_is_addressed_by_name_when_given(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "tailnet": "-1234567890123", "device_name": HOST, "authorized": True},
    )
    assert tailnet.requests[0].endswith("/tailnet/-1234567890123/devices")


# ---------------------------------------------------------------- routes


def test_routes_are_enabled_and_the_run_converges(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    options = {
        "api_token": TOKEN,
        "device_name": HOST,
        "enabled_routes": ["10.20.0.0/16", "10.21.0.0/16"],
    }
    first = _run_routes(module_args, module_result, options)
    assert first["changed"] is True
    assert first["routes"]["enabled_routes"] == ["10.20.0.0/16", "10.21.0.0/16"]
    assert first["diff"] == {"before": [], "after": ["10.20.0.0/16", "10.21.0.0/16"]}
    assert _run_routes(module_args, module_result, options)["changed"] is False


def test_routes_are_compared_without_regard_to_order(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """The API returns enabled routes sorted, so an ordered compare never converges."""
    net = Tailnet([_device()])
    net.devices["nDEVICE000000000CNTRL"]["enabledRoutes"] = ["10.21.0.0/16", "10.20.0.0/16"]
    mocker.patch(_API_URL, net)
    result = _run_routes(
        module_args,
        module_result,
        {
            "api_token": TOKEN,
            "device_name": HOST,
            "enabled_routes": ["10.20.0.0/16", "10.21.0.0/16"],
        },
    )
    assert result["changed"] is False


def test_clearing_the_enabled_routes_is_a_change(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    net = Tailnet([_device()])
    net.devices["nDEVICE000000000CNTRL"]["enabledRoutes"] = ["10.20.0.0/16"]
    mocker.patch(_API_URL, net)
    result = _run_routes(
        module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "enabled_routes": []}
    )
    assert result["changed"] is True
    assert result["routes"]["enabled_routes"] == []
    assert (
        _run_routes(
            module_args,
            module_result,
            {"api_token": TOKEN, "device_name": HOST, "enabled_routes": []},
        )["changed"]
        is False
    )


def test_routes_report_the_advertised_routes_alongside_the_enabled_ones(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    net = Tailnet([_device()])
    net.devices["nDEVICE000000000CNTRL"]["advertisedRoutes"] = ["10.20.0.0/16"]
    mocker.patch(_API_URL, net)
    result = _run_routes(
        module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "enabled_routes": []}
    )
    assert result["routes"] == {
        "advertised_routes": ["10.20.0.0/16"],
        "enabled_routes": [],
    }


def test_routes_refuse_a_selector_matching_several_devices(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    net = Tailnet([_device(), _device(OTHER_HOST, OTHER_ID)])
    mocker.patch(_API_URL, net)
    module_args({"api_token": TOKEN, "tag": "tag:stress", "enabled_routes": []})
    with module_result.failure() as result:
        tailscale_device_routes.main()
    assert "2 devices match" in result["msg"]
    assert net.writes == []


def test_routes_refuse_a_task_naming_no_device(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    module_args({"api_token": TOKEN, "enabled_routes": []})
    with module_result.failure() as result:
        tailscale_device_routes.main()
    assert "one of the following is required" in result["msg"]
    assert tailnet.requests == []


def test_routes_require_the_list_to_reconcile(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    module_args({"api_token": TOKEN, "device_name": HOST})
    with module_result.failure() as result:
        tailscale_device_routes.main()
    assert "enabled_routes" in result["msg"]


def test_routes_in_check_mode_write_nothing(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    result = _run_routes(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_name": HOST, "enabled_routes": ["10.20.0.0/16"]},
        check_mode=True,
    )
    assert result["changed"] is True
    assert result["diff"]["after"] == ["10.20.0.0/16"]
    assert tailnet.writes == []


def test_routes_report_the_device_they_belong_to(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    result = _run_routes(
        module_args,
        module_result,
        {"api_token": TOKEN, "device_id": "nDEVICE000000000CNTRL", "enabled_routes": []},
    )
    assert result["device"]["hostname"] == HOST
    assert result["device"]["nodeId"] == "nDEVICE000000000CNTRL"


def test_routes_reach_the_device_endpoint_and_not_the_tailnet_one(
    module_args: Any, module_result: Any, tailnet: Any
) -> None:
    """A device-scoped path under a tailnet prefix is a 404 that reads as a missing route."""
    _run_routes(
        module_args, module_result, {"api_token": TOKEN, "device_name": HOST, "enabled_routes": []}
    )
    assert tailnet.requests[1] == f"GET {BASE}/device/nDEVICE000000000CNTRL/routes"
