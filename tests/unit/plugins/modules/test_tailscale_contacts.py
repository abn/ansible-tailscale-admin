# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the tailscale_contacts module, driven through the harness.

The API reads the three contacts as keys of one document and writes one type per
request. The properties that matter are that only the types the task named are
written, that a type already holding the requested address is not written, and
that an empty address is declined before a request the server answers with a
bare 500.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.modules import tailscale_contacts

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
BASE = "https://api.tailscale.com/api/v2"

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"

CURRENT: dict[str, Any] = {
    "account": {"email": "owner@example.com", "needsVerification": False},
    "support": {"email": "support@example.com", "needsVerification": False},
    "security": {"email": "security@example.com", "needsVerification": True},
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
    def __init__(self, current: Any = None) -> None:
        self.current = copy.deepcopy(CURRENT if current is None else current)
        self.patches: list[tuple[str, dict]] = []
        self.requests: list[str] = []

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        self.requests.append(f"{method} {url}")
        if method == "GET":
            return _reply(200, json.dumps(self.current))
        if method == "PATCH":
            patch = json.loads(str(data))
            self.patches.append((url, patch))
            contact_type = url.rsplit("/", 1)[-1]
            self.current[contact_type] = {**self.current.get(contact_type, {}), **patch}
            return _reply(200, "")
        return _reply(404, '{"message": "not found"}')


@pytest.fixture
def server(mocker: Any) -> Any:
    tailnet = Tailnet()
    mocker.patch(_API_URL, tailnet)
    return tailnet


def test_nothing_given_writes_nothing(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN})

    with module_result.success() as result:
        tailscale_contacts.main()

    assert result["changed"] is False
    assert result["changed_contacts"] == []
    assert server.patches == []


def test_a_contact_already_correct_writes_nothing(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "support": "support@example.com"})

    with module_result.success() as result:
        tailscale_contacts.main()

    assert result["changed"] is False
    assert server.patches == []


def test_a_pending_verification_does_not_report_a_change(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """The security contact needs verification, and that is not an address change."""
    module_args({"api_token": TOKEN, "security": "security@example.com"})

    with module_result.success() as result:
        tailscale_contacts.main()

    assert result["changed"] is False, "needsVerification is not the reconciled state"
    assert server.patches == []


def test_a_differing_contact_is_written(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN, "support": "help@example.com"})

    with module_result.success() as result:
        tailscale_contacts.main()

    assert result["changed"] is True
    assert result["changed_contacts"] == ["support"]
    assert server.patches == [(f"{BASE}/tailnet/-/contacts/support", {"email": "help@example.com"})]


def test_only_the_contact_given_is_sent(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN, "security": "sec@example.com"})

    with module_result.success():
        tailscale_contacts.main()

    assert [entry[0] for entry in server.patches] == [f"{BASE}/tailnet/-/contacts/security"]


def test_an_unmentioned_contact_is_not_sent(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """An omitted option arrives as None and must not become a write."""
    module_args({"api_token": TOKEN, "account": "new-owner@example.com"})

    with module_result.success():
        tailscale_contacts.main()

    assert len(server.patches) == 1, "three contacts exist and only one was named"


def test_several_contacts_are_written_together(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "account": "new-owner@example.com",
            "security": "sec@example.com",
        }
    )

    with module_result.success() as result:
        tailscale_contacts.main()

    assert result["changed_contacts"] == ["account", "security"]
    assert server.patches == [
        (f"{BASE}/tailnet/-/contacts/account", {"email": "new-owner@example.com"}),
        (f"{BASE}/tailnet/-/contacts/security", {"email": "sec@example.com"}),
    ]


def test_a_change_carries_the_values_a_diff_renders_from(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """`diff_mode: support: full` promises this, and the callback reads `result['diff']`."""
    module_args({"api_token": TOKEN, "support": "help@example.com"})

    with module_result.success() as result:
        tailscale_contacts.main()

    assert result["diff"]["before"] == {"support": CURRENT["support"]}
    assert result["diff"]["after"] == {
        "support": {"email": "help@example.com", "needsVerification": False}
    }


def test_the_diff_covers_only_the_contacts_this_run_changed(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """A diff across the whole contacts document would bury the line that matters."""
    module_args({"api_token": TOKEN, "security": "sec@example.com"})

    with module_result.success() as result:
        tailscale_contacts.main()

    assert set(result["diff"]["before"]) == {"security"}, "not the contacts left alone"
    assert set(CURRENT) - set(result["diff"]["before"]), "the fixture does have other contacts"


def test_the_result_carries_every_contact_after_the_run(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "support": "help@example.com"})

    with module_result.success() as result:
        tailscale_contacts.main()

    assert result["contacts"]["support"]["email"] == "help@example.com"
    assert result["contacts"]["account"] == CURRENT["account"], "and the rest as read"


def test_running_twice_converges(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN, "support": "help@example.com"})

    with module_result.success() as first:
        tailscale_contacts.main()
    with module_result.success() as second:
        tailscale_contacts.main()

    assert first["changed"] is True
    assert second["changed"] is False, "a second run over identical input must not change"
    assert len(server.patches) == 1


def test_check_mode_writes_nothing(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN, "support": "help@example.com"}, check_mode=True)

    with module_result.success() as result:
        tailscale_contacts.main()

    assert result["changed"] is True
    assert result["changed_contacts"] == ["support"]
    assert server.patches == []
    assert server.requests == [f"GET {BASE}/tailnet/-/contacts"]


def test_an_empty_address_is_refused_before_any_write(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """The API answers an empty address with a bare 500, so the module declines it."""
    module_args({"api_token": TOKEN, "support": ""})

    with module_result.failure() as result:
        tailscale_contacts.main()

    assert "support" in result["msg"]
    assert "empty" in result["msg"]
    assert server.patches == []
    assert server.requests == [f"GET {BASE}/tailnet/-/contacts"]


def test_an_empty_address_already_held_is_quiet(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """Asking for the empty address the tailnet already holds is not a write."""
    empty = copy.deepcopy(CURRENT)
    empty["support"]["email"] = ""
    tailnet = Tailnet(current=empty)
    mocker.patch(_API_URL, tailnet)

    module_args({"api_token": TOKEN, "support": ""})
    with module_result.success() as result:
        tailscale_contacts.main()

    assert result["changed"] is False
    assert tailnet.patches == []


def test_a_missing_credential_fails_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"support": "help@example.com"})

    with module_result.failure() as result:
        tailscale_contacts.main()

    assert "api_token" in result["msg"]
    assert server.requests == []


def test_a_credential_never_reaches_the_result(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "support": "help@example.com"})

    with module_result.success() as result:
        tailscale_contacts.main()

    assert TOKEN not in json.dumps(result, default=str)


def test_a_tailnet_is_addressed_by_name_when_given(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "tailnet": "-1234567890123", "support": "help@example.com"})

    with module_result.success():
        tailscale_contacts.main()

    assert server.patches[0][0] == f"{BASE}/tailnet/-1234567890123/contacts/support"


def test_a_body_that_is_not_a_document_fails(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """A proxy error page answering 200 must not read as three unset contacts."""
    tailnet = Tailnet()
    tailnet.current = "not a document"
    mocker.patch(_API_URL, tailnet)

    module_args({"api_token": TOKEN, "support": "help@example.com"})
    with module_result.failure() as result:
        tailscale_contacts.main()

    assert "contacts" in result["msg"]
    assert tailnet.patches == []
