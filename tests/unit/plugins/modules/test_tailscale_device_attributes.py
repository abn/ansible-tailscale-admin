# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the tailscale_device_attributes module, driven through the harness.

The endpoint merges, so the properties that matter are that an attribute the task
does not name is never sent, that only the attributes named are compared, and that
a removal is an explicit ``null`` rather than an omission. A device holds
service-managed ``node:`` attributes this module does not manage, and if those
could report a change the operator would have no way to make a run quiet.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.modules import tailscale_device_attributes

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
BASE = "https://api.tailscale.com/api/v2"

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"

NODE_ID = "n1234CNTRL"
DEVICE = {
    "id": "3133440773018733",
    "nodeId": NODE_ID,
    "hostname": "laptop-01",
    "name": "laptop-01.tail1234.ts.net",
    "addresses": ["100.64.0.5"],
}

#: Service-managed attributes a real device always carries. None of them is
#: managed here, so none may ever reach a request or a diff.
SYSTEM = {
    "node:os": "linux",
    "node:osVersion": "5.19.0-42-generic",
    "node:tsVersion": "1.102.5",
}


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
    """A tailnet with one device, whose posture attributes merge on a PATCH."""

    def __init__(self, attributes: dict | None = None, *, node_id: str = NODE_ID) -> None:
        self.attributes = dict(attributes if attributes is not None else {})
        self.node_id = node_id
        self.patches: list[dict] = []
        self.requests: list[str] = []

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        self.requests.append(f"{method} {url}")
        if method == "GET" and url.endswith("/devices"):
            return _reply(200, json.dumps({"devices": [DEVICE]}))
        if method == "GET" and "/attributes" in url:
            return _reply(200, json.dumps({"attributes": self.attributes}))
        if method == "PATCH" and url.endswith("/device-attributes"):
            patch = json.loads(str(data))
            self.patches.append(patch)
            for key, change in patch["nodes"][self.node_id].items():
                if change is None:
                    self.attributes.pop(key, None)
                else:
                    self.attributes[key] = change["value"]
            return _reply(200, "null")
        return _reply(404, '{"message": "not found"}')


@pytest.fixture
def server(mocker: Any) -> Any:
    tailnet = Tailnet()
    mocker.patch(_API_URL, tailnet)
    return tailnet


def test_an_attribute_already_correct_writes_nothing(
    module_args: Any, module_result: Any, server: Any
) -> None:
    server.attributes = {"custom:owner": "alice"}

    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [{"key": "custom:owner", "value": "alice"}],
        }
    )

    with module_result.success() as result:
        tailscale_device_attributes.main()

    assert result["changed"] is False
    assert server.patches == []


def test_a_differing_value_is_written(module_args: Any, module_result: Any, server: Any) -> None:
    server.attributes = {"custom:owner": "alice"}

    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [{"key": "custom:owner", "value": "bob"}],
        }
    )

    with module_result.success() as result:
        tailscale_device_attributes.main()

    assert result["changed"] is True
    assert result["changed_attributes"] == ["custom:owner"]
    assert server.patches == [{"nodes": {NODE_ID: {"custom:owner": {"value": "bob"}}}}]


def test_only_the_attributes_given_are_sent(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """A merging endpoint must be named only what the task asks about."""
    server.attributes = {"custom:owner": "alice", "custom:site": "berlin"}

    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [{"key": "custom:site", "value": "munich"}],
        }
    )

    with module_result.success():
        tailscale_device_attributes.main()

    assert server.patches == [{"nodes": {NODE_ID: {"custom:site": {"value": "munich"}}}}]
    assert server.attributes["custom:owner"] == "alice", "an unnamed attribute must not move"


def test_an_absent_attribute_is_deleted_with_null(
    module_args: Any, module_result: Any, server: Any
) -> None:
    server.attributes = {"custom:owner": "alice", "custom:stale": "x"}

    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [{"key": "custom:stale", "state": "absent"}],
        }
    )

    with module_result.success() as result:
        tailscale_device_attributes.main()

    assert result["changed"] is True
    assert server.patches == [{"nodes": {NODE_ID: {"custom:stale": None}}}]
    assert "custom:stale" not in server.attributes


def test_an_absent_attribute_already_gone_writes_nothing(
    module_args: Any, module_result: Any, server: Any
) -> None:
    server.attributes = {"custom:owner": "alice"}

    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [{"key": "custom:stale", "state": "absent"}],
        }
    )

    with module_result.success() as result:
        tailscale_device_attributes.main()

    assert result["changed"] is False
    assert server.patches == []


def test_a_set_and_a_delete_travel_in_one_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    server.attributes = {"custom:stale": "x"}

    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [
                {"key": "custom:owner", "value": "alice"},
                {"key": "custom:stale", "state": "absent"},
                {"key": "custom:site", "value": "berlin"},
            ],
        }
    )

    with module_result.success():
        tailscale_device_attributes.main()

    assert len(server.patches) == 1, "a mixed change is one request, not one per attribute"
    assert server.patches[0] == {
        "nodes": {
            NODE_ID: {
                "custom:owner": {"value": "alice"},
                "custom:stale": None,
                "custom:site": {"value": "berlin"},
            }
        }
    }


def test_every_value_type_round_trips(module_args: Any, module_result: Any, server: Any) -> None:
    """A boolean and an integer must not be flattened to a string on the way."""
    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [
                {"key": "custom:diskEncryption", "value": True},
                {"key": "custom:score", "value": 80},
                {"key": "custom:owner", "value": "alice"},
            ],
        }
    )

    with module_result.success() as result:
        tailscale_device_attributes.main()

    assert server.attributes["custom:diskEncryption"] is True
    assert server.attributes["custom:score"] == 80
    assert result["attributes"]["custom:score"] == 80


def test_a_system_attribute_is_refused_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [{"key": "node:os", "value": "linux"}],
        }
    )

    with module_result.failure() as result:
        tailscale_device_attributes.main()

    assert "custom:" in result["msg"]
    assert server.requests == [], "a key the API cannot store must not reach the tailnet"


def test_a_present_attribute_without_a_value_is_refused(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [{"key": "custom:owner"}],
        }
    )

    with module_result.failure() as result:
        tailscale_device_attributes.main()

    assert "custom:owner" in result["msg"]
    assert server.requests == []


def test_a_float_value_is_refused(module_args: Any, module_result: Any, server: Any) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [{"key": "custom:score", "value": 1.5}],
        }
    )

    with module_result.failure() as result:
        tailscale_device_attributes.main()

    assert "custom:score" in result["msg"]
    assert server.requests == []


def test_a_key_named_twice_is_refused(module_args: Any, module_result: Any, server: Any) -> None:
    """The API folds key case, so two spellings are one attribute and no answer."""
    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [
                {"key": "custom:owner", "value": "alice"},
                {"key": "custom:Owner", "value": "bob"},
            ],
        }
    )

    with module_result.failure() as result:
        tailscale_device_attributes.main()

    assert "custom:Owner" in result["msg"] or "custom:owner" in result["msg"]
    assert server.requests == []


def test_an_unmanaged_system_attribute_cannot_report_a_change(
    module_args: Any, module_result: Any, server: Any
) -> None:
    server.attributes = dict(SYSTEM)

    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [{"key": "custom:owner", "state": "absent"}],
        }
    )

    with module_result.success() as result:
        tailscale_device_attributes.main()

    assert result["changed"] is False, "a node: attribute is not a change this module tracks"
    assert server.patches == []


def test_the_returned_attributes_are_the_custom_ones_only(
    module_args: Any, module_result: Any, server: Any
) -> None:
    server.attributes = {**SYSTEM, "custom:owner": "alice"}

    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [{"key": "custom:owner", "value": "alice"}],
        }
    )

    with module_result.success() as result:
        tailscale_device_attributes.main()

    assert result["attributes"] == {"custom:owner": "alice"}


def test_the_diff_covers_only_the_attributes_this_run_changed(
    module_args: Any, module_result: Any, server: Any
) -> None:
    server.attributes = {**SYSTEM, "custom:owner": "alice", "custom:site": "berlin"}

    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [
                {"key": "custom:owner", "value": "bob"},
                {"key": "custom:site", "value": "berlin"},
                {"key": "custom:stale", "state": "absent"},
            ],
        }
    )

    with module_result.success() as result:
        tailscale_device_attributes.main()

    assert result["diff"]["before"] == {"custom:owner": "alice"}
    assert result["diff"]["after"] == {"custom:owner": "bob"}
    assert set(server.attributes) - {"custom:owner", "custom:site"}, "the device has more"


def test_a_deletion_renders_as_none_in_the_diff(
    module_args: Any, module_result: Any, server: Any
) -> None:
    server.attributes = {"custom:stale": "x"}

    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [{"key": "custom:stale", "state": "absent"}],
        }
    )

    with module_result.success() as result:
        tailscale_device_attributes.main()

    assert result["diff"]["before"] == {"custom:stale": "x"}
    assert result["diff"]["after"] == {"custom:stale": None}


def test_running_twice_converges(module_args: Any, module_result: Any, server: Any) -> None:
    server.attributes = {"custom:stale": "x"}
    options = {
        "api_token": TOKEN,
        "device_name": "laptop-01",
        "attributes": [
            {"key": "custom:owner", "value": "alice"},
            {"key": "custom:stale", "state": "absent"},
        ],
    }

    module_args(options)
    with module_result.success() as first:
        tailscale_device_attributes.main()
    module_args(options)
    with module_result.success() as second:
        tailscale_device_attributes.main()

    assert first["changed"] is True
    assert second["changed"] is False, "a second run over identical input must not change"
    assert len(server.patches) == 1


def test_check_mode_reports_the_change_and_writes_nothing(
    module_args: Any, module_result: Any, server: Any
) -> None:
    server.attributes = {"custom:stale": "x"}

    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [
                {"key": "custom:owner", "value": "alice"},
                {"key": "custom:stale", "state": "absent"},
            ],
        },
        check_mode=True,
    )

    with module_result.success() as result:
        tailscale_device_attributes.main()

    assert result["changed"] is True
    assert result["changed_attributes"] == ["custom:owner", "custom:stale"]
    assert result["attributes"] == {"custom:owner": "alice"}, "the projected state"
    assert server.patches == []
    assert all("PATCH" not in request for request in server.requests)


def test_a_device_matching_no_selector_is_refused(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "device_name": "not-a-device",
            "attributes": [{"key": "custom:owner", "value": "alice"}],
        }
    )

    with module_result.failure() as result:
        tailscale_device_attributes.main()

    assert "not-a-device" in result["msg"]
    assert server.patches == []


def test_a_missing_credential_fails_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "device_name": "laptop-01",
            "attributes": [{"key": "custom:owner", "value": "alice"}],
        }
    )

    with module_result.failure() as result:
        tailscale_device_attributes.main()

    assert "api_token" in result["msg"]
    assert server.requests == []


def test_a_credential_never_reaches_the_result(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "device_name": "laptop-01",
            "attributes": [{"key": "custom:owner", "value": "alice"}],
        }
    )

    with module_result.success() as result:
        tailscale_device_attributes.main()

    assert TOKEN not in json.dumps(result, default=str)


def test_a_tailnet_is_addressed_by_name_when_given(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "tailnet": "-1234567890123",
            "device_name": "laptop-01",
            "attributes": [{"key": "custom:owner", "value": "alice"}],
        }
    )

    with module_result.success():
        tailscale_device_attributes.main()

    assert any(
        "/tailnet/-1234567890123/device-attributes" in request for request in server.requests
    )
