# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the tailscale_service module, driven through the harness.

The double below is a model of the endpoint as measured against a real tailnet,
not a stub that accepts anything. Three of its behaviours are the reason this
module needs a merge rather than a straight replace, and each of them has a test
that fails if the merge is removed:

* the PUT replaces the whole Service, so a field the task did not mention is
  cleared unless the module carries it forward;
* the server assigns the addresses, so a field the task did not declare comes
  back holding a value it never sent;
* the server stores an empty comment, display name or tag list as an absent key,
  so sending one is a difference on every run.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.modules import tailscale_service

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
BASE = "https://api.tailscale.com/api/v2"

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"

#: The addresses the double hands out, one pair per Service it is asked to
#: create. Written down rather than generated so a test can assert the module
#: returned exactly what the server stored.
ASSIGNED = ["100.119.6.70", "fd7a:115c:a1e0::b533:64c"]

#: A Service as the API stores one: the fields the task set, plus the pair the
#: server assigned, and nothing else. The absent keys matter, because an absent
#: key is how the server stores an empty value.
STORED: dict[str, Any] = {
    "name": "svc:web",
    "addrs": ASSIGNED,
    "ports": ["tcp:443"],
    "tags": ["tag:web"],
    "comment": "fronted by nginx",
    "displayName": "Web front end",
}

#: A field the module does not manage, which a Service could come to hold.
UNMANAGED: dict[str, Any] = {"somethingNew": {"nested": True}}

NAME = "svc:web"

#: The devices the double lists, shaped as the API returns them: the MagicDNS
#: name, the label a task can name it by, and both address families. Two, so that
#: a test can make a selector ambiguous by adding a third sharing a label.
DEVICES: list[dict[str, Any]] = [
    {
        "nodeId": "nNIBBLER01CNTRL",
        "id": "111",
        "name": "nibbler.example.ts.net",
        "addresses": ["100.64.0.5", "fd7a:115c:a1e0::5"],
    },
    {
        "nodeId": "nCANVAS02CNTRL",
        "id": "222",
        "name": "canvas.example.ts.net",
        "addresses": ["100.64.0.6", "fd7a:115c:a1e0::6"],
    },
]


class Body:
    def __init__(self, text: str) -> None:
        self._text = text

    def decode(self, *args: str) -> str:
        return self._text


def _reply(status: int, text: str) -> Any:
    """What open_url answers with: one object, not a pair."""

    class Response:
        def __init__(self, status: int) -> None:
            self.status = status
            self.headers: dict = {}

        def read(self) -> Body:
            return Body(text)

    return Response(status)


class Tailnet:
    """The Service endpoints, with the storage rules the real endpoint has.

    Deliberately not permissive. A double that accepts a body the API would
    refuse cannot fail a test that removed the carry-forward of the addresses or
    the ports, and that carry-forward is the whole reason the merge exists.
    """

    def __init__(self, current: dict[str, Any] | None = None, hosts: list | None = None) -> None:
        self.services = dict(current) if current else {}
        self.hosts = hosts if hosts is not None else []
        self.devices = [dict(entry) for entry in DEVICES]
        self.approvals: dict[tuple[str, str], dict[str, Any]] = {}
        self.writes: list[dict] = []
        self.deleted: list[str] = []
        self.requests: list[str] = []

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        path = url[len(BASE) :]
        self.requests.append(f"{method} {path}")
        parts = path.split("/")
        name = parts[4] if len(parts) > 4 and parts[3] == "services" else None

        if method == "GET" and len(parts) == 4 and parts[3] == "devices":
            return _reply(200, json.dumps({"devices": self.devices}))

        if method == "GET" and name and "device" in parts:
            device = parts[6]
            record = self.approvals.get((name, device))
            if record is None:
                return _reply(200, json.dumps({"approved": False, "autoApproved": False}))
            return _reply(200, json.dumps(record))
        if method == "POST" and name and "approved" in parts:
            body = json.loads(str(data))
            self.approvals[(name, parts[6])] = dict(body, autoApproved=False)
            return _reply(200, json.dumps(self.approvals[(name, parts[6])]))
        if method == "GET" and parts[3] == "services" and "devices" in parts:
            # An absent `hosts` key rather than an empty list, as measured.
            return _reply(200, json.dumps({"hosts": self.hosts} if self.hosts else {}))
        if method == "GET" and name:
            stored = self.services.get(name)
            if stored is None:
                return _reply(404, '{"message": "service not found"}')
            return _reply(200, json.dumps(stored))
        if method == "PUT" and name:
            body = json.loads(str(data))
            refusal = self._refuses(name, body)
            if refusal:
                return _reply(400, json.dumps({"message": refusal}))
            self.writes.append(body)
            self.services[name] = self._stored(name, body)
            return _reply(200, json.dumps(self.services[name]))
        if method == "DELETE" and name:
            if name not in self.services:
                return _reply(404, '{"message": "service not found"}')
            del self.services[name]
            self.deleted.append(name)
            return _reply(200, "null")
        return _reply(404, '{"message": "not found"}')

    def _refuses(self, name: str, body: dict) -> str:
        """The constraints the module's merge exists to satisfy, or an empty string."""
        if name in self.services:
            if len(body.get("addrs", [])) != 2:
                return "when updating a service, addrs must contain 2 elements"
        elif len(body.get("addrs", [])) > 1:
            return "when creating a new service, addrs must be empty or contain 1 IPv4 address"
        if not body.get("ports"):
            return 'ports are empty, use "do-not-validate" to opt out of port validation'
        return ""

    def _stored(self, name: str, body: dict) -> dict:
        """What the server keeps: the body, with the addresses it assigned.

        An empty string and an empty list are dropped, because the server stores
        them as absent keys and a document that keeps them differs from the
        tailnet for ever after. The IPv6 is the server's, and an IPv4 the task
        asked for on a create is kept.
        """
        stored = {key: value for key, value in body.items() if value not in ("", [])}
        if name not in self.services:
            kept = stored.get("addrs") or []
            stored["addrs"] = [*kept, ASSIGNED[1]] if kept else list(ASSIGNED)
        return stored


@pytest.fixture
def server(mocker: Any) -> Tailnet:
    tailnet = Tailnet()
    mocker.patch(_API_URL, tailnet)
    return tailnet


@pytest.fixture
def existing(mocker: Any) -> Tailnet:
    tailnet = Tailnet(current={NAME: dict(STORED)})
    mocker.patch(_API_URL, tailnet)
    return tailnet


def _run(module_args: Any, module_result: Any, options: dict, **flags: Any) -> dict[str, Any]:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_service.main()
    return dict(result)


def test_a_create_with_no_ports_is_refused_with_the_way_out(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    """The API refuses a Service with no ports, on a create as much as on an update."""
    module_args({"api_token": TOKEN, "name": NAME})

    with module_result.failure() as result:
        tailscale_service.main()

    assert "do-not-validate" in result["msg"]
    assert server.writes == []


def test_a_service_that_does_not_exist_is_created(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "ports": ["tcp:443"]},
    )

    assert result["changed"] is True
    assert server.writes == [{"name": NAME, "ports": ["tcp:443"]}]
    assert result["service"]["name"] == NAME


def test_the_addresses_the_server_assigned_are_returned(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    """The create response, not the request: nobody holds the body that was sent."""
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "ports": ["tcp:443"]},
    )

    assert result["service"]["addrs"] == ASSIGNED
    assert "addrs" not in result["diff"]["after"], "a check run cannot know them either"


def test_a_second_run_over_a_created_service_reports_no_change(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    """The property the whole merge exists for.

    The Service the server stored holds an address pair the task never sent. A
    module that compared the task against the Service would report a change for
    ever, and this is the assertion that catches it.
    """
    options = {
        "api_token": TOKEN,
        "name": NAME,
        "display_name": "Web front end",
        "comment": "fronted by nginx",
        "ports": ["tcp:443"],
        "tags": ["tag:web"],
    }

    first = _run(module_args, module_result, options)
    second = _run(module_args, module_result, options)

    assert first["changed"] is True
    assert second["changed"] is False, f"stored service is {server.services[NAME]!r}"
    assert len(server.writes) == 1


def test_a_bare_presence_task_writes_nothing_over_an_existing_service(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    """`state: present` with nothing declared must be a no-op, addresses included."""
    result = _run(module_args, module_result, {"api_token": TOKEN, "name": NAME})

    assert result["changed"] is False
    assert existing.writes == []
    assert result["service"] == STORED


def test_a_declared_address_is_sent_on_a_create(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "ports": ["tcp:443"], "addrs": ["100.100.100.100"]},
    )

    assert server.writes[0]["addrs"] == ["100.100.100.100"]


def test_an_option_the_task_left_out_is_carried_forward(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    """The PUT replaces the Service, so a field not sent is a field cleared.

    Sending only the comment would take the tags, the label and the ports with
    it, and the ports would then be refused outright.
    """
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "comment": "moved to the eu cluster"},
    )

    assert result["changed"] is True
    assert existing.writes == [
        {
            "name": NAME,
            "addrs": ASSIGNED,
            "ports": ["tcp:443"],
            "tags": ["tag:web"],
            "displayName": "Web front end",
            "comment": "moved to the eu cluster",
        }
    ]


def test_a_field_this_module_does_not_manage_survives_a_write(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """The merge starts from what the tailnet holds, so a future field is kept."""
    server = Tailnet(current={NAME: {**STORED, **UNMANAGED}})
    mocker.patch(_API_URL, server)

    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "comment": "moved to the eu cluster"},
    )

    assert result["changed"] is True
    assert server.writes[0]["somethingNew"] == UNMANAGED["somethingNew"]


def test_an_unmanaged_field_cannot_alone_report_a_change(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    server = Tailnet(current={NAME: {**STORED, **UNMANAGED}})
    mocker.patch(_API_URL, server)

    result = _run(module_args, module_result, {"api_token": TOKEN, "name": NAME})

    assert result["changed"] is False


def test_an_empty_comment_clears_it_and_leaves_no_key(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    """`comment: ''` is an instruction, and it converges.

    The server stores a cleared comment as an absent key, so sending `''` would
    leave a document that differs from the tailnet on every run.
    """
    result = _run(module_args, module_result, {"api_token": TOKEN, "name": NAME, "comment": ""})

    assert result["changed"] is True
    assert "comment" not in existing.writes[0]
    assert "comment" not in existing.services[NAME]

    again = _run(module_args, module_result, {"api_token": TOKEN, "name": NAME, "comment": ""})
    assert again["changed"] is False, "clearing a comment is a state, and it is reached"


def test_a_service_with_no_comment_is_not_a_change_when_one_is_cleared(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """Empty and absent are the same state, because the server stores them alike."""
    server = Tailnet(current={NAME: {k: v for k, v in STORED.items() if k != "comment"}})
    mocker.patch(_API_URL, server)

    result = _run(module_args, module_result, {"api_token": TOKEN, "name": NAME, "comment": ""})

    assert result["changed"] is False
    assert server.writes == []


def test_tags_are_compared_without_regard_to_order(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """The server keeps a Service's tags in an order of its own.

    Measured against the real endpoint: a Service written with one order reads back
    in another, so comparing the declared order against the returned one reports a
    change for ever on a task that is already satisfied. That is the same class as
    the DNS boolean, one field further on.
    """
    stored = {**STORED, "tags": ["tag:web", "tag:metrics"]}
    tailnet = Tailnet(current={NAME: dict(stored)})
    mocker.patch(_API_URL, tailnet)

    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "tags": ["tag:metrics", "tag:web"]},
    )

    assert result["changed"] is False, "the same set in another order is not a change"
    assert tailnet.writes == []


def test_an_empty_tag_list_clears_the_tags(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    result = _run(module_args, module_result, {"api_token": TOKEN, "name": NAME, "tags": []})

    assert result["changed"] is True
    assert "tags" not in existing.writes[0]


def test_a_tag_the_policy_does_not_own_surfaces_the_refusal(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """The API's own 400 is the only place the rule about `tagOwners` is enforced."""

    def refused(
        url: str, data: Any = None, headers: Any = None, method: str = "GET", **kw: Any
    ) -> Any:
        if method == "PUT":
            return _reply(
                400, '{"message": "requested tags [tag:nope] are invalid or not permitted"}'
            )
        return _reply(404, '{"message": "service not found"}')

    mocker.patch(_API_URL, refused)
    module_args({"api_token": TOKEN, "name": NAME, "ports": ["tcp:443"], "tags": ["tag:nope"]})
    with module_result.failure() as result:
        tailscale_service.main()

    assert "tag:nope" in result["msg"]
    assert "tagOwners" in result["msg"]


def test_hosts_are_returned_and_empty_means_no_key(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "ports": ["tcp:443"]},
    )

    assert result["hosts"] == []


def test_the_devices_hosting_a_service_are_returned(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    hosts = [{"stableNodeID": "nABCD123456CNTRL", "approvalLevel": "approved:manual"}]
    server = Tailnet(current={NAME: dict(STORED)}, hosts=hosts)
    mocker.patch(_API_URL, server)

    result = _run(module_args, module_result, {"api_token": TOKEN, "name": NAME})

    assert result["hosts"] == hosts
    assert result["changed"] is False


def test_check_mode_creates_nothing_and_invents_no_addresses(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "ports": ["tcp:443"]},
        check_mode=True,
    )

    assert result["changed"] is True
    assert result["service"] == {"name": NAME, "ports": ["tcp:443"]}
    assert server.writes == []
    assert server.services == {}


def test_check_mode_over_a_service_already_in_place_is_quiet(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    options = {"api_token": TOKEN, "name": NAME, "comment": "fronted by nginx"}

    result = _run(module_args, module_result, options, check_mode=True)

    assert result["changed"] is False
    assert existing.writes == []


def test_the_diff_holds_the_service_before_and_after(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "comment": "moved to the eu cluster"},
        diff=True,
    )

    assert result["diff"]["before"] == STORED
    assert result["diff"]["after"]["comment"] == "moved to the eu cluster"
    assert result["diff"]["after"]["ports"] == STORED["ports"], "and the ports it carried"


def test_removing_a_service_deletes_it(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    result = _run(module_args, module_result, {"api_token": TOKEN, "name": NAME, "state": "absent"})

    assert result["changed"] is True
    assert existing.deleted == [NAME]
    assert existing.services == {}
    assert "service" not in result
    assert result["diff"]["before"] == STORED
    assert result["diff"]["after"] is None


def test_removing_a_service_that_is_already_gone_is_quiet(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    """A second run over a deleted Service must not report a change.

    The 404 is the answer to "is it there", not a failure, so this converges
    rather than failing on a run that did what it was asked.
    """
    first = _run(module_args, module_result, {"api_token": TOKEN, "name": NAME, "state": "absent"})
    second = _run(module_args, module_result, {"api_token": TOKEN, "name": NAME, "state": "absent"})

    assert first["changed"] is False
    assert second["changed"] is False
    assert server.deleted == []


def test_removing_a_service_that_exists_twice_is_quiet(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    _run(module_args, module_result, {"api_token": TOKEN, "name": NAME, "state": "absent"})
    again = _run(module_args, module_result, {"api_token": TOKEN, "name": NAME, "state": "absent"})

    assert again["changed"] is False
    assert existing.deleted == [NAME]


def test_check_mode_removes_nothing(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "state": "absent"},
        check_mode=True,
    )

    assert result["changed"] is True
    assert existing.deleted == []


def test_a_device_is_approved_and_the_second_run_is_quiet(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    options = {"api_token": TOKEN, "name": NAME, "device_id": "12345", "approved": True}

    first = _run(module_args, module_result, options)
    second = _run(module_args, module_result, options)

    assert first["changed"] is True
    assert first["approval"] == {"approved": True, "autoApproved": False}
    assert second["changed"] is False


def test_a_revocation_is_a_write_and_is_stored_as_false(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    """Unlike the rest of a Service, the API stores a false here as a real false."""
    approve = {"api_token": TOKEN, "name": NAME, "device_id": "12345", "approved": True}
    revoke = {**approve, "approved": False}
    _run(module_args, module_result, approve)

    result = _run(module_args, module_result, revoke)

    assert result["changed"] is True
    assert result["approval"]["approved"] is False
    assert server.approvals[(NAME, "12345")] == {"approved": False, "autoApproved": False}

    again = _run(module_args, module_result, revoke)
    assert again["changed"] is False


def test_an_approval_already_in_place_writes_nothing(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    options = {"api_token": TOKEN, "name": NAME, "device_id": "12345", "approved": False}

    result = _run(module_args, module_result, options)

    assert result["changed"] is False
    assert server.approvals == {}


def test_check_mode_approves_nothing(module_args: Any, module_result: Any, server: Tailnet) -> None:
    options = {"api_token": TOKEN, "name": NAME, "device_id": "12345", "approved": True}

    result = _run(module_args, module_result, options, check_mode=True)

    assert result["changed"] is True
    assert result["approval"]["approved"] is True
    assert result["diff"]["after"]["approved"] is True
    assert server.approvals == {}


def test_an_approval_never_touches_the_service_itself(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "device_id": "12345", "approved": True},
    )

    assert server.writes == []
    assert server.deleted == []
    assert f"GET /tailnet/-/services/{NAME}" not in server.requests


def test_a_device_the_api_does_not_know_is_an_error(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """A selector that matches nothing fails, rather than reporting a success.

    A device the API cannot see is one that does not exist, or one shared in
    from another tailnet, and neither is a state an approval reconciles.
    """

    def not_found(
        url: str, data: Any = None, headers: Any = None, method: str = "GET", **kw: Any
    ) -> Any:
        return _reply(404, '{"message": "no manageable device matching this ID found"}')

    mocker.patch(_API_URL, not_found)
    module_args({"api_token": TOKEN, "name": NAME, "device_id": "99999", "approved": True})
    with module_result.failure() as result:
        tailscale_service.main()

    assert "99999" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_removing_a_service_while_naming_a_device_is_refused(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    """Two resources in one task, where one of them deletes."""
    module_args(
        {
            "api_token": TOKEN,
            "name": NAME,
            "device_id": "12345",
            "approved": True,
            "state": "absent",
        }
    )

    with module_result.failure() as result:
        tailscale_service.main()

    assert "approved" in result["msg"]
    assert server.requests == []


def test_a_device_approval_cannot_be_combined_with_the_service(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "name": NAME,
            "device_id": "12345",
            "approved": True,
            "ports": ["tcp:443"],
        }
    )

    with module_result.failure() as result:
        tailscale_service.main()

    assert "ports" in result["msg"]
    assert server.requests == []


def test_a_device_id_without_an_approval_is_refused_by_its_own_spec(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    module_args({"api_token": TOKEN, "name": NAME, "device_id": "12345"})

    with module_result.failure() as result:
        tailscale_service.main()

    assert "approved" in result["msg"]
    assert server.requests == []


def test_a_device_name_is_resolved_through_the_device_list(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    """A host role knows its own name, not the opaque id the endpoint takes."""
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "device_name": "nibbler", "approved": True},
    )

    assert result["changed"] is True
    assert (NAME, "nNIBBLER01CNTRL") in server.approvals
    assert "GET /tailnet/-/devices" in server.requests


def test_an_address_selects_the_device_that_holds_it(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "address": "100.64.0.6", "approved": True},
    )

    assert (NAME, "nCANVAS02CNTRL") in server.approvals


def test_a_device_name_matching_nothing_is_refused_before_the_approval(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    module_args({"api_token": TOKEN, "name": NAME, "device_name": "ghost", "approved": True})

    with module_result.failure() as result:
        tailscale_service.main()

    assert "ghost" in result["msg"]
    assert server.approvals == {}


def test_a_name_two_devices_share_is_refused_as_ambiguous(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    """A selector matching several devices must refuse rather than pick one."""
    server.devices.append(
        {
            "nodeId": "nTWIN03CNTRL",
            "id": "333",
            "name": "nibbler.other.ts.net",
            "addresses": ["100.64.0.7"],
        }
    )
    module_args({"api_token": TOKEN, "name": NAME, "device_name": "nibbler", "approved": True})

    with module_result.failure() as result:
        tailscale_service.main()

    assert "2 devices match" in result["msg"]
    assert server.approvals == {}


def test_two_spellings_of_the_device_are_refused(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "name": NAME,
            "device_id": "111",
            "device_name": "nibbler",
            "approved": True,
        }
    )

    with module_result.failure() as result:
        tailscale_service.main()

    assert "device_id" in result["msg"]
    assert server.approvals == {}


def test_an_approval_without_a_device_is_refused(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    module_args({"api_token": TOKEN, "name": NAME, "approved": True})

    with module_result.failure() as result:
        tailscale_service.main()

    assert "approved" in result["msg"]
    assert server.requests == []


@pytest.mark.parametrize(
    "name",
    [
        "web",
        "svc:",
        "svc:has space",
        "svc:under_score",
        "svc:dot.name",
        "svc:-leading",
        "svc:trailing-",
    ],
)
def test_a_name_the_api_would_refuse_is_refused_here(
    module_args: Any, module_result: Any, server: Tailnet, name: str
) -> None:
    module_args({"api_token": TOKEN, "name": name, "ports": ["tcp:443"]})

    with module_result.failure() as result:
        tailscale_service.main()

    assert "DNS label" in result["msg"]
    assert server.requests == [], "a bad name costs no request"


def test_an_empty_port_list_is_refused_with_the_way_out(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    module_args({"api_token": TOKEN, "name": NAME, "ports": []})

    with module_result.failure() as result:
        tailscale_service.main()

    assert "do-not-validate" in result["msg"]
    assert server.requests == []


def test_two_addresses_for_a_service_that_does_not_exist_is_refused(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "name": NAME,
            "ports": ["tcp:443"],
            "addrs": ["100.100.100.100", "fd7a:115c:a1e0::1"],
        }
    )

    with module_result.failure() as result:
        tailscale_service.main()

    assert "does not exist yet" in result["msg"]
    assert server.writes == [], "the read is what tells the two cases apart"
    assert server.services == {}


def test_one_address_for_a_service_that_exists_is_refused(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    module_args({"api_token": TOKEN, "name": NAME, "addrs": ["100.100.100.100"]})

    with module_result.failure() as result:
        tailscale_service.main()

    assert "both its addresses" in result["msg"]
    assert existing.writes == []


def test_both_addresses_for_a_service_that_exists_are_sent(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "addrs": ["100.100.100.100", ASSIGNED[1]]},
    )

    assert result["changed"] is True
    assert existing.writes[0]["addrs"] == ["100.100.100.100", ASSIGNED[1]]


def test_a_service_that_cannot_be_read_is_not_overwritten(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """A 200 that is not a Service must not be read as a Service that is absent.

    Reading it as absent would create over the top of whatever it should have
    been, which is what a proxy answering with an error page looks like from
    inside a module.
    """

    def html(
        url: str, data: Any = None, headers: Any = None, method: str = "GET", **kw: Any
    ) -> Any:
        return _reply(200, "<html>captive portal</html>")

    mocker.patch(_API_URL, html)
    module_args({"api_token": TOKEN, "name": NAME, "ports": ["tcp:443"]})
    with module_result.failure() as result:
        tailscale_service.main()

    assert "Nothing was written" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_missing_credential_fails_before_any_request(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    module_args({"name": NAME, "ports": ["tcp:443"]})

    with module_result.failure() as result:
        tailscale_service.main()

    assert "api_token" in result["msg"]
    assert server.requests == []


def test_a_credential_never_reaches_the_result(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "name": NAME, "ports": ["tcp:443"]},
    )

    assert TOKEN not in json.dumps(result, default=str)


def test_a_tailnet_is_addressed_by_name_when_given(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "tailnet": "-1234567890123", "name": NAME, "ports": ["tcp:443"]},
    )

    assert server.requests[0] == "GET /tailnet/-1234567890123/services/svc:web"
    assert server.requests[1].startswith("PUT /tailnet/-1234567890123/services/svc:web")
