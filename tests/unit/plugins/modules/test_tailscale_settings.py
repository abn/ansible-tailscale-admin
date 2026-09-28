# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the tailscale_settings module, driven through the harness.

The endpoint merges, so the property that matters is that an option left out is
never sent, and that only the options given are compared. A settings document
holds fields this module does not manage, and if those could report a change the
operator would have no way to make a run quiet.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.modules import tailscale_settings

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
BASE = "https://api.tailscale.com/api/v2"

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"

CURRENT: dict[str, Any] = {
    "devicesApprovalOn": False,
    "devicesAutoUpdatesOn": True,
    "devicesKeyDurationDays": 180,
    "usersApprovalOn": False,
    "networkFlowLoggingOn": False,
    "regionalRoutingOn": False,
    "httpsEnabled": True,
}

UNMANAGED: dict[str, Any] = {"someFieldFromTheFuture": "whatever"}


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
    def __init__(self, current: dict | None = None) -> None:
        self.current = dict(current if current is not None else CURRENT)
        self.patches: list[dict] = []
        self.requests: list[str] = []

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        self.requests.append(f"{method} {url}")
        if method == "GET":
            return _reply(200, json.dumps(self.current))
        if method == "PATCH":
            patch = json.loads(str(data))
            self.patches.append(patch)
            self.current.update(patch)
            return _reply(200, "{}")
        return _reply(404, '{"message": "not found"}')


@pytest.fixture
def server(mocker: Any) -> Any:
    tailnet = Tailnet()
    mocker.patch(_API_URL, tailnet)
    return tailnet


def test_nothing_given_writes_nothing(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN})

    with module_result.success() as result:
        tailscale_settings.main()

    assert result["changed"] is False
    assert result["changed_settings"] == []
    assert server.patches == []


def test_a_setting_already_correct_writes_nothing(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "devices_key_duration_days": 180})

    with module_result.success() as result:
        tailscale_settings.main()

    assert result["changed"] is False
    assert server.patches == []


def test_a_differing_setting_is_written(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN, "devices_approval_on": True})

    with module_result.success() as result:
        tailscale_settings.main()

    assert result["changed"] is True
    assert result["changed_settings"] == ["devicesApprovalOn"]
    assert server.patches == [{"devicesApprovalOn": True}]


def test_a_change_carries_the_values_a_diff_renders_from(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """`diff_mode: support: full` promises this, and the callback reads `result['diff']`."""
    module_args({"api_token": TOKEN, "devices_approval_on": True})

    with module_result.success() as result:
        tailscale_settings.main()

    assert result["diff"]["before"] == {"devicesApprovalOn": CURRENT["devicesApprovalOn"]}
    assert result["diff"]["after"] == {"devicesApprovalOn": True}


def test_the_diff_covers_only_the_settings_this_run_changed(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """A diff across the whole settings document would bury the one line that matters."""
    module_args({"api_token": TOKEN, "devices_approval_on": True})

    with module_result.success() as result:
        tailscale_settings.main()

    assert set(result["diff"]["before"]) == {"devicesApprovalOn"}, "not the settings left alone"
    assert set(CURRENT) - set(result["diff"]["before"]), "the fixture does have other settings"


def test_only_the_options_given_are_sent(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN, "users_approval_on": True})

    with module_result.success():
        tailscale_settings.main()

    assert server.patches == [{"usersApprovalOn": True}], "an unmentioned option must not be sent"


def test_an_explicit_false_is_sent_not_dropped(
    module_args: Any, module_result: Any, server: Any, mocker: Any
) -> None:
    on = Tailnet(current={**CURRENT, "devicesAutoUpdatesOn": True})
    mocker.patch(_API_URL, on)

    module_args({"api_token": TOKEN, "devices_auto_updates_on": False})

    with module_result.success() as result:
        tailscale_settings.main()

    assert result["changed"] is True, "turning a setting off is a change"
    assert on.patches == [{"devicesAutoUpdatesOn": False}]


def test_an_unmanaged_field_cannot_report_a_change(
    module_args: Any, module_result: Any, server: Any, mocker: Any
) -> None:
    noisy = Tailnet(current={**CURRENT, **UNMANAGED})
    mocker.patch(_API_URL, noisy)

    module_args({"api_token": TOKEN, "devices_approval_on": False})

    with module_result.success() as result:
        tailscale_settings.main()

    assert result["changed"] is False, "a field this module does not manage is not a change"


def test_several_settings_are_reported_together(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "devices_approval_on": True,
            "devices_key_duration_days": 365,
            "regional_routing_on": True,
        }
    )

    with module_result.success() as result:
        tailscale_settings.main()

    assert result["changed_settings"] == [
        "devicesApprovalOn",
        "devicesKeyDurationDays",
        "regionalRoutingOn",
    ]
    assert server.patches[0] == {
        "devicesApprovalOn": True,
        "devicesKeyDurationDays": 365,
        "regionalRoutingOn": True,
    }


def test_a_string_setting_is_sent(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN, "acls_external_link": "https://example.com/policy"})

    with module_result.success():
        tailscale_settings.main()

    assert server.patches == [{"aclsExternalLink": "https://example.com/policy"}]


def test_running_twice_converges(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN, "devices_approval_on": True})

    with module_result.success() as first:
        tailscale_settings.main()
    with module_result.success() as second:
        tailscale_settings.main()

    assert first["changed"] is True
    assert second["changed"] is False, "a second run over identical input must not change"
    assert len(server.patches) == 1


def test_check_mode_writes_nothing(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN, "devices_approval_on": True}, check_mode=True)

    with module_result.success() as result:
        tailscale_settings.main()

    assert result["changed"] is True
    assert result["changed_settings"] == ["devicesApprovalOn"]
    assert server.patches == []
    assert server.requests == [f"GET {BASE}/tailnet/-/settings"]


def test_a_missing_credential_fails_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"devices_approval_on": True})

    with module_result.failure() as result:
        tailscale_settings.main()

    assert "api_token" in result["msg"]
    assert server.requests == []


def test_a_credential_never_reaches_the_result(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "devices_approval_on": True})

    with module_result.success() as result:
        tailscale_settings.main()

    assert TOKEN not in json.dumps(result, default=str)


def test_a_tailnet_is_addressed_by_name_when_given(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "tailnet": "-1234567890123", "devices_approval_on": True})

    with module_result.success():
        tailscale_settings.main()

    assert server.requests[0].endswith("/tailnet/-1234567890123/settings")
