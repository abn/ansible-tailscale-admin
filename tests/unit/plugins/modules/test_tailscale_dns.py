# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the tailscale_dns module, driven through the harness.

The endpoint replaces the whole document, so the property worth proving is that an
option the task does not mention survives a run that changes something else.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.modules import tailscale_dns

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
BASE = "https://api.tailscale.com/api/v2"

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"

#: A stored document in the shape the server actually keeps: a `false` and an empty
#: collection are dropped on the way in, so the tailnet holds no `useWithExitNode`,
#: no `preferences` block and no empty maps.
CURRENT: dict[str, Any] = {
    "nameservers": [{"address": "9.9.9.9"}],
    "splitDNS": {"kept.example.com": [{"address": "10.0.0.1"}]},
    "searchPaths": ["kept.example.com"],
}


class Body:
    def __init__(self, text: str) -> None:
        self._text = text

    def decode(self, *args: str) -> str:
        return self._text


def _reply(status: int, text: str, headers: dict | None = None) -> Any:
    class Response:
        status: int
        headers: dict

        def __init__(self, status: int, headers: dict) -> None:
            self.status = status
            self.headers = headers

        def read(self) -> Body:
            return Body(text)

    return Response(status, headers or {})


class Tailnet:
    def __init__(self, current: dict | None = None) -> None:
        self.current = dict(current if current is not None else CURRENT)
        self.writes: list[dict] = []
        self.requests: list[str] = []

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        self.requests.append(f"{method} {url}")
        if url.endswith("/dns/configuration") and method == "GET":
            return _reply(200, json.dumps(self.current))
        if url.endswith("/dns/configuration") and method == "POST":
            self.writes.append(json.loads(str(data)))
            self.current = json.loads(str(data))
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
        tailscale_dns.main()

    assert result["changed"] is False
    assert server.writes == []


def test_setting_a_preference_writes_the_merged_document(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "magic_dns": True})

    with module_result.success() as result:
        tailscale_dns.main()

    assert result["changed"] is True
    assert server.writes[0]["preferences"]["magicDNS"] is True


def test_a_field_the_task_never_mentioned_survives(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """The property a replace endpoint makes non-obvious."""
    module_args({"api_token": TOKEN, "magic_dns": True})

    with module_result.success():
        tailscale_dns.main()

    written = server.writes[0]
    assert written["nameservers"] == CURRENT["nameservers"], "nameservers were not asked about"
    assert written["splitDNS"] == CURRENT["splitDNS"], "split DNS was not asked about"
    assert written["searchPaths"] == CURRENT["searchPaths"], "search paths were not asked about"
    # The tailnet held no preferences block, so there is no other preference to
    # carry over. What must not happen is a block invented to hold `overrideLocalDNS:
    # false`, which the server would drop and the next run would report again.
    assert written["preferences"] == {"magicDNS": True}, "and no other preference appeared"


def test_an_explicit_false_is_honoured_not_treated_as_unset(
    module_args: Any, module_result: Any, server: Any, mocker: Any
) -> None:
    """Turning a preference off is a change, and the write carries its absence.

    Not `magicDNS: false` in the request. The server drops a false rather than
    storing it, so a request carrying one leaves the tailnet without the key and
    the task still asking for it, which is a change reported on every run. The
    key is removed instead, and the tailnet is then holding exactly what the task
    asked for.

    Measured against the real endpoint, twice writing the same document changes
    nothing.
    """
    enabled = Tailnet(
        current={**CURRENT, "preferences": {"magicDNS": True, "overrideLocalDNS": False}}
    )
    mocker.patch(_API_URL, enabled)

    module_args({"api_token": TOKEN, "magic_dns": False})

    with module_result.success() as result:
        tailscale_dns.main()

    assert result["changed"] is True, "turning it off is a change"
    assert "magicDNS" not in enabled.writes[0].get("preferences", {}), (
        "the request omits it, because a false is not stored and would never converge"
    )


def test_a_setting_already_correct_writes_nothing(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "override_local_dns": False})

    with module_result.success() as result:
        tailscale_dns.main()

    assert result["changed"] is False


def test_resolvers_are_translated_to_camel_case(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "nameservers": [{"address": "1.1.1.1", "use_with_exit_node": True}],
        }
    )

    with module_result.success():
        tailscale_dns.main()

    assert server.writes[0]["nameservers"] == [{"address": "1.1.1.1", "useWithExitNode": True}]


def test_a_resolver_without_the_flag_sends_no_flag_at_all(
    module_args: Any, module_result: Any, server: Any
) -> None:
    # The option's default is false and the server stores a false as an absent
    # key, so a request carrying `useWithExitNode: false` comes back without it and
    # the next run sees a difference that never goes away. The key is what carries
    # the flag, so the flag being off is the key being absent.
    module_args({"api_token": TOKEN, "nameservers": [{"address": "1.1.1.1"}]})

    with module_result.success():
        tailscale_dns.main()

    assert server.writes[0]["nameservers"] == [{"address": "1.1.1.1"}]


def test_a_resolver_with_the_flag_on_sends_it(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {"api_token": TOKEN, "nameservers": [{"address": "1.1.1.1", "use_with_exit_node": True}]}
    )

    with module_result.success():
        tailscale_dns.main()

    assert server.writes[0]["nameservers"] == [{"address": "1.1.1.1", "useWithExitNode": True}]


def test_split_dns_values_are_translated_too(
    module_args: Any, module_result: Any, server: Any
) -> None:
    # Split DNS entries go through the same shaping as nameservers, and the server
    # drops a false flag there too, so an entry at the default carries no key.
    module_args(
        {
            "api_token": TOKEN,
            "split_dns": {"internal.example.com": [{"address": "10.0.0.53"}]},
        }
    )

    with module_result.success():
        tailscale_dns.main()

    assert server.writes[0]["splitDNS"] == {"internal.example.com": [{"address": "10.0.0.53"}]}


def test_a_split_dns_entry_with_the_flag_on_sends_it(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "split_dns": {
                "internal.example.com": [{"address": "10.0.0.53", "use_with_exit_node": True}]
            },
        }
    )

    with module_result.success():
        tailscale_dns.main()

    assert server.writes[0]["splitDNS"] == {
        "internal.example.com": [{"address": "10.0.0.53", "useWithExitNode": True}]
    }


def test_a_resolver_that_omits_the_flag_keeps_the_tailnets_own(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """An entry that does not give the field leaves it as the tailnet holds it.

    The default used to be false, so omitting the field turned a resolver's flag off
    and a task that never mentioned it reported a change on every run.
    """
    tailnet = Tailnet({"nameservers": [{"address": "1.1.1.1", "useWithExitNode": True}]})
    mocker.patch(_API_URL, tailnet)
    module_args({"api_token": TOKEN, "nameservers": [{"address": "1.1.1.1"}]})

    with module_result.success() as result:
        tailscale_dns.main()

    assert result["changed"] is False, "the tailnet already holds what the task declares"


def test_a_resolver_may_be_given_as_a_bare_address(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """A string is the same as a mapping that gives only the address."""
    module_args({"api_token": TOKEN, "nameservers": ["1.1.1.1", "2a07:a8c0::6e:1191"]})

    with module_result.success() as result:
        tailscale_dns.main()

    assert result["changed"] is True
    assert server.writes[0]["nameservers"] == [
        {"address": "1.1.1.1"},
        {"address": "2a07:a8c0::6e:1191"},
    ]


def test_a_bare_address_also_carries_the_flag_forward(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    tailnet = Tailnet({"nameservers": [{"address": "1.1.1.1", "useWithExitNode": True}]})
    mocker.patch(_API_URL, tailnet)
    module_args({"api_token": TOKEN, "nameservers": ["1.1.1.1"]})

    with module_result.success() as result:
        tailscale_dns.main()

    assert result["changed"] is False


def test_an_explicit_false_turns_the_flag_off(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """The one way to ask for a resolver no longer reached through an exit node."""
    tailnet = Tailnet({"nameservers": [{"address": "1.1.1.1", "useWithExitNode": True}]})
    mocker.patch(_API_URL, tailnet)
    module_args(
        {"api_token": TOKEN, "nameservers": [{"address": "1.1.1.1", "use_with_exit_node": False}]}
    )

    with module_result.success() as result:
        tailscale_dns.main()

    assert result["changed"] is True
    assert tailnet.writes[0]["nameservers"] == [{"address": "1.1.1.1"}]


def test_a_split_dns_resolver_also_carries_the_flag_forward(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    tailnet = Tailnet(
        {"splitDNS": {"internal.example.com": [{"address": "10.0.0.53", "useWithExitNode": True}]}}
    )
    mocker.patch(_API_URL, tailnet)
    module_args(
        {"api_token": TOKEN, "split_dns": {"internal.example.com": [{"address": "10.0.0.53"}]}}
    )

    with module_result.success() as result:
        tailscale_dns.main()

    assert result["changed"] is False


def test_a_resolver_entry_that_is_neither_shape_is_refused(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "nameservers": [{"not_an_address": "1.1.1.1"}]})

    with module_result.failure() as result:
        tailscale_dns.main()

    assert "resolver entry" in result["msg"]
    assert "Traceback" not in result["msg"]
    assert server.writes == []


def test_search_paths_are_renamed_on_the_way_out(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "search_paths": ["a.example.com"]})

    with module_result.success():
        tailscale_dns.main()

    assert server.writes[0]["searchPaths"] == ["a.example.com"]
    assert "search_paths" not in server.writes[0]


def test_running_twice_converges(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN, "magic_dns": True})

    with module_result.success() as first:
        tailscale_dns.main()
    with module_result.success() as second:
        tailscale_dns.main()

    assert first["changed"] is True
    assert second["changed"] is False, "a second run over identical input must not change"
    assert len(server.writes) == 1


def test_check_mode_writes_nothing(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN, "magic_dns": True}, check_mode=True)

    with module_result.success() as result:
        tailscale_dns.main()

    assert result["changed"] is True
    assert server.writes == []
    assert server.requests == [f"GET {BASE}/tailnet/-/dns/configuration"]


def test_the_effective_configuration_is_returned(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "magic_dns": True})

    with module_result.success() as result:
        tailscale_dns.main()

    returned = result["dns_configuration"]
    assert returned["preferences"]["magicDNS"] is True
    assert returned["nameservers"] == CURRENT["nameservers"]


def test_a_change_carries_the_documents_a_diff_renders_from(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """`diff_mode: support: full` promises this, and the callback reads `result['diff']`."""
    module_args({"api_token": TOKEN, "magic_dns": True})

    with module_result.success() as result:
        tailscale_dns.main()

    assert result["diff"]["before"] == CURRENT, "the configuration as the tailnet held it"
    assert result["diff"]["after"] == result["dns_configuration"]
    assert result["diff"]["before"] != result["diff"]["after"]


def test_an_unchanged_run_reports_no_diff(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """Asking for what the tailnet already holds is not a change.

    The tailnet holds no `magicDNS`, so `false` is what it already says. Asking for
    it must be quiet, which is the case that only works if a false and an absent key
    are compared as the same thing.
    """
    module_args({"api_token": TOKEN, "magic_dns": False})

    with module_result.success() as result:
        tailscale_dns.main()

    assert result["changed"] is False, "the tailnet already says false by saying nothing"
    assert result["diff"]["before"] == result["diff"]["after"]


def test_an_empty_nameserver_list_clears_rather_than_being_stored(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """An empty list is how the resolvers go, and the server stores that as no key.

    Sending `[]` would leave the tailnet without the key and the task still asking
    for an empty list, so every run reported a change.
    """
    module_args({"api_token": TOKEN, "nameservers": []})

    with module_result.success() as result:
        tailscale_dns.main()

    assert result["changed"] is True
    assert "nameservers" not in server.writes[0], "the key is removed rather than emptied"


def test_a_missing_credential_fails_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"magic_dns": True})

    with module_result.failure() as result:
        tailscale_dns.main()

    assert "api_token" in result["msg"]
    assert server.requests == []


def test_a_credential_never_reaches_the_result(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "magic_dns": True})

    with module_result.success() as result:
        tailscale_dns.main()

    assert TOKEN not in json.dumps(result, default=str)


def test_a_tailnet_is_addressed_by_name_when_given(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "tailnet": "-1234567890123", "magic_dns": True})

    with module_result.success():
        tailscale_dns.main()

    assert server.requests[0].endswith("/tailnet/-1234567890123/dns/configuration")


@pytest.mark.parametrize("body", ["<html>captive portal</html>", "", "not json"])
def test_an_unread_current_document_fails_rather_than_discarding_it(
    module_args: Any, module_result: Any, mocker: Any, body: str
) -> None:
    """The endpoint replaces the whole document, so merging into {} loses it all."""
    server = Tailnet()

    def answering(
        url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        if method == "GET":
            return _reply(200, body)
        server.writes.append(json.loads(str(data)))
        return _reply(200, "{}")

    mocker.patch(_API_URL, answering)
    module_args({"api_token": TOKEN, "magic_dns": True})

    with module_result.failure() as result:
        tailscale_dns.main()

    assert "Nothing was written" in result["msg"]
    assert server.writes == [], "an unread document must never be replaced"
