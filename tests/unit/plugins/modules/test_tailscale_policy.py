# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the tailscale_policy module, driven through the harness.

The only thing replaced is the socket. The credential resolution, the client, the
policy cycle and the module's own argument handling all run for real, because a
test that stubs the code under test proves nothing about it.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale import _api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import diff
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import loads
from ansible_collections.abn.tailscale.plugins.modules import tailscale_policy

POLICY = '{\n  // the policy under test\n  "acls": [],\n}\n'
OTHER = '{"acls": [{"action": "accept", "src": ["group:eng"], "dst": ["*:*"]}]}\n'
OPEN = "{}\n"
ETAG = '"e0b2816b418"'
TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"

#: Deny-all plus the tag owner an app connector needs, so a document under test
#: is refused for what it is testing rather than for a missing prerequisite.
DECLARABLE = {
    "acls": [],
    "tagOwners": {"tag:connector": ["autogroup:admin"]},
}

#: A connector with everything the server insists on, and nothing it merely
#: wants: the tag is owned, and a rule and an approver make it reachable.
WORKING_CONNECTOR = {
    "name": "example",
    "connectors": ["tag:connector"],
    "domains": ["example.com"],
}

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"


class Body:
    def __init__(self, text: str) -> None:
        self._text = text

    def decode(self, *args: str) -> str:
        return self._text


class Reply:
    """What open_url answers with: one object, not a pair.

    open_url returns the response itself on success and raises HTTPError for a
    status it treats as a failure, so a stand-in that returned a pair would agree
    with a wrong transport rather than catch it.
    """

    def __init__(self, text: str, status: int = 200, headers: dict | None = None) -> None:
        self._text = text
        self.status = status
        self.headers = headers or {}

    def read(self) -> Body:
        return Body(self._text)


def _reply(status: int, text: str, headers: dict | None = None) -> Reply:
    return Reply(text, status, headers)


class Tailnet:
    """The tailnet as the API holds it, recording every request."""

    def __init__(self, policy: str = POLICY, etag: str = ETAG) -> None:
        self.policy = policy
        self.etag = etag
        self.requests: list[tuple[str, dict]] = []
        self.writes = 0
        self.validated = 0

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        sent = dict(headers or {})
        self.requests.append((f"{method} {url}", {"data": data, "headers": sent}))
        return self.reply_for(url, data, sent, method)

    def reply_for(self, url: str, data: Any, sent: dict, method: str) -> Any:
        if url.endswith("/acl/validate"):
            self.validated += 1
            return _reply(200, "{}", {"Content-Type": "application/json"})

        if url.endswith("/acl"):
            if method == "GET":
                return _reply(200, self.policy, {"ETag": self.etag})
            guard = sent.get("If-Match")
            if guard is None:
                return _reply(400, '{"message": "If-Match required"}')
            if guard != self.etag:
                return _reply(412, '{"message": "mismatched If-Match"}')
            self.writes += 1
            self.policy = str(data)
            self.etag = f'"after-{self.writes}"'
            return _reply(200, "{}", {"Content-Type": "application/json"})

        return _reply(404, '{"message": "not found"}')

    def sent(self) -> list[str]:
        return [line for line, payload in self.requests]

    def write_headers(self) -> dict:
        for line, payload in self.requests:
            if line.startswith("POST") and line.endswith("/acl"):
                return payload["headers"]
        raise AssertionError("no write was attempted")


class Race:
    """A tailnet where another writer lands one edit just after the first read.

    The read itself is answered first, so the module holds the pre-edit document
    and ETag; the edit lands immediately afterwards. The write that follows is
    therefore refused with a 412, and the read the retry makes sees the edit.
    """

    def __init__(self, tailnet: Tailnet, added: dict[str, Any]) -> None:
        self._tailnet = tailnet
        self._added = added
        self._landed = False

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        if method == "GET":
            reply = self._tailnet(url, data=data, headers=headers, method=method, **kwargs)
            if not self._landed:
                self._landed = True
                self._tailnet.policy = (
                    json.dumps({**loads(self._tailnet.policy), **self._added}) + "\n"
                )
                self._tailnet.etag = '"rival"'
            return reply
        return self._tailnet(url, data=data, headers=headers, method=method, **kwargs)


@pytest.fixture
def server(mocker: Any) -> Any:
    tailnet = Tailnet()
    mocker.patch(_API_URL, tailnet)
    return tailnet


@pytest.fixture
def policy(tmp_path: Any) -> Any:
    def write(text: str) -> str:
        path = tmp_path / "policy.hujson"
        path.write_text(text, encoding="utf-8")
        return str(path)

    return write


@pytest.fixture
def writable(tmp_path: Any) -> Any:
    """A policy file holding a document a connector can be declared into.

    Called with no document it writes `DECLARABLE`, which is the deny-all
    document with the one tag owner a connector needs.
    """

    def write(document: Any = None) -> str:
        path = tmp_path / "declared.hujson"
        path.write_text(
            json.dumps(DECLARABLE if document is None else document) + "\n", encoding="utf-8"
        )
        return str(path)

    return write


@pytest.fixture(autouse=True)
def _fresh_warnings() -> None:
    """Start each test with nothing recorded as a warning.

    A module records its warnings into a list the whole process shares, and
    refuses to record one it already holds. Two tests running the same document
    therefore produce the same warning text, and the second one adds nothing a
    test can see, so the list is emptied rather than reasoned about.
    """
    from ansible.module_utils.common import warnings

    warnings._global_warnings.clear()


@pytest.fixture
def this_run() -> Any:
    """The warnings one run recorded, read out of a module result.

    The result carries every warning the process holds, which is the one list
    the module and the result share, so this is where an operator reads them
    from too.
    """
    return lambda result: [str(item.event.msg) for item in result.get("warnings", [])]


def test_an_unchanged_policy_reports_no_change(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    module_args({"policy": policy(POLICY), "api_token": TOKEN})

    with module_result.success() as result:
        tailscale_policy.main()

    assert result["changed"] is False
    assert result["changed_paths"] == []
    assert server.writes == 0, "an unchanged policy must not be written"


def test_a_document_given_as_content_reconciles_the_same_way(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """The two sources differ in where the text comes from, and in nothing else."""
    module_args({"content": POLICY, "api_token": TOKEN})

    with module_result.success() as result:
        tailscale_policy.main()

    assert result["changed"] is False
    assert server.writes == 0


def test_content_that_differs_is_canonicalised_and_written(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "content": '{"acls": [{"action": "accept", "src": ["tag:lab"], "dst": ["*:*"]}]}',
            "api_token": TOKEN,
        }
    )

    with module_result.success() as result:
        tailscale_policy.main()

    assert result["changed"] is True
    assert server.writes == 1
    assert loads(server.policy) == {
        "acls": [{"action": "accept", "src": ["tag:lab"], "dst": ["*:*"]}]
    }


def test_content_reaches_the_declared_sections(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """A declaration spliced into text lands as it does into a file."""
    module_args(
        {
            "content": json.dumps({"acls": []}),
            "groups": {"group:lab": ["alice@example.com"]},
            "api_token": TOKEN,
        }
    )

    with module_result.success() as result:
        tailscale_policy.main()

    assert result["changed"] is True
    assert loads(server.policy)["groups"] == {"group:lab": ["alice@example.com"]}


def test_policy_and_content_together_are_refused(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    module_args({"policy": policy(POLICY), "content": POLICY, "api_token": TOKEN})

    with module_result.failure() as result:
        tailscale_policy.main()

    assert "policy" in result["msg"]
    assert server.requests == []


def test_neither_policy_nor_content_is_refused(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN})

    with module_result.failure() as result:
        tailscale_policy.main()

    assert "content" in result["msg"]
    assert server.requests == []


def test_a_changed_policy_is_validated_then_written_once(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    module_args({"policy": policy(OTHER), "api_token": TOKEN})

    with module_result.success() as result:
        tailscale_policy.main()

    assert result["changed"] is True
    assert result["changed_paths"]
    assert server.validated == 1
    assert server.writes == 1
    assert server.sent() == [
        f"GET {_base()}/tailnet/-/acl",
        f"POST {_base()}/tailnet/-/acl/validate",
        f"POST {_base()}/tailnet/-/acl",
    ], "read, validate, replace, in that order"


def test_a_change_carries_the_documents_a_diff_renders_from(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    """`diff_mode: support: full` promises this, and the callback reads `result['diff']`.

    A top-level `before` and `after` look equivalent and render nothing, which
    is what a first attempt at this did, so the test asserts the nesting.
    """
    module_args({"policy": policy(OTHER), "api_token": TOKEN})

    with module_result.success() as result:
        tailscale_policy.main()

    assert result["diff"]["before"] == loads(POLICY)
    assert result["diff"]["after"] == loads(OTHER)
    assert result["diff"]["before"] != result["diff"]["after"]


def test_an_unchanged_run_reports_no_diff(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    module_args({"policy": policy(POLICY), "api_token": TOKEN})

    with module_result.success() as result:
        tailscale_policy.main()

    assert result["changed"] is False
    assert result["diff"]["before"] == result["diff"]["after"]


def test_running_twice_converges(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    """The gate for this wave: apply twice, and the second run changes nothing."""
    module_args({"policy": policy(OTHER), "api_token": TOKEN})

    with module_result.success() as first:
        tailscale_policy.main()
    with module_result.success() as second:
        tailscale_policy.main()

    assert first["changed"] is True
    assert second["changed"] is False, "a second run over identical input must not change"
    assert second["changed_paths"] == []
    assert server.writes == 1, "written once, not once per run"


def test_a_write_carries_the_fingerprint_from_the_read(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    module_args({"policy": policy(OTHER), "api_token": TOKEN})

    with module_result.success():
        tailscale_policy.main()

    assert server.write_headers()["If-Match"] == ETAG


def test_the_document_is_sent_as_hujson(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    module_args({"policy": policy(OTHER), "api_token": TOKEN})

    with module_result.success():
        tailscale_policy.main()

    assert server.write_headers()["Content-Type"] == "application/hujson"


def test_an_opening_policy_is_refused(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    module_args({"policy": policy(OPEN), "api_token": TOKEN})

    with module_result.failure() as result:
        tailscale_policy.main()

    assert "allow" in result["msg"]
    assert server.writes == 0
    assert server.sent() == [], "refused before spending a request"


def test_an_opening_policy_is_allowed_when_confirmed(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    module_args({"policy": policy(OPEN), "api_token": TOKEN, "allow_all_traffic": True})

    with module_result.success():
        tailscale_policy.main()

    assert server.writes == 1


def test_an_empty_acl_list_needs_no_confirmation(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    module_args({"policy": policy('{"acls": []}'), "api_token": TOKEN})

    with module_result.success() as result:
        tailscale_policy.main()

    assert result["changed"] is False, "the tailnet already denies everything"


def test_check_mode_writes_nothing(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    module_args({"policy": policy(OTHER), "api_token": TOKEN}, check_mode=True)

    with module_result.success() as result:
        tailscale_policy.main()

    assert result["changed"] is True
    assert server.writes == 0
    assert server.validated == 0, "check mode makes one request, a read"


def test_a_missing_credential_fails_before_any_request(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    module_args({"policy": policy(POLICY)})

    with module_result.failure() as result:
        tailscale_policy.main()

    assert "api_token" in result["msg"]
    assert server.sent() == []


def test_both_credential_kinds_are_refused(
    module_args: Any, module_result: Any, policy: Any
) -> None:
    module_args(
        {
            "policy": policy(POLICY),
            "api_token": TOKEN,
            "oauth_client_id": "kABCD123456CNTRL",
            "oauth_client_secret": "tskey-client-secret",
        }
    )

    with module_result.failure() as result:
        tailscale_policy.main()

    assert "mutually exclusive" in result["msg"]


def test_a_credential_never_reaches_the_result(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    module_args({"policy": policy(OTHER), "api_token": TOKEN})

    with module_result.success() as result:
        tailscale_policy.main()

    assert TOKEN not in json.dumps(result, default=str), "no_log must scrub the result"


def test_a_concurrent_edit_converges_and_the_diff_reports_what_it_replaced(
    module_args: Any, module_result: Any, policy: Any, mocker: Any
) -> None:
    """The refused write landed nothing, the retry lands one, and the diff is honest.

    The other writer's section is one the task does not declare. The module
    reconciles the whole document, so that section goes, and the point of the test
    is that the run says so: its ``before`` is the document the retry read, not the
    one the first read saw.
    """
    tailnet = Tailnet(policy=POLICY, etag=ETAG)
    added = {"hosts": {"gateway": "100.64.0.1"}}
    mocker.patch(_API_URL, Race(tailnet, added))
    module_args({"policy": policy(OTHER), "api_token": TOKEN})

    with module_result.success() as result:
        tailscale_policy.main()

    assert result["changed"] is True
    assert result["diff"]["before"]["hosts"] == added["hosts"], "the retry read saw the edit"
    stored = loads(tailnet.policy)
    assert "hosts" not in stored, "a section the file does not declare is removed"
    assert stored["acls"] == loads(OTHER)["acls"], "and the declared state was applied"
    assert tailnet.writes == 1, "the refused write landed nothing; the retry landed one"


def test_a_document_that_keeps_changing_fails_after_three_attempts(
    module_args: Any, module_result: Any, policy: Any, mocker: Any
) -> None:
    tailnet = Tailnet(policy=POLICY, etag=ETAG)

    def always_stale(
        url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        if method == "GET":
            tailnet.requests.append(
                (f"{method} {url}", {"data": data, "headers": dict(headers or {})})
            )
            return Reply(tailnet.policy, 200, {"ETag": '"stale"'})
        return tailnet(url, data=data, headers=headers, method=method, **kwargs)

    mocker.patch(_API_URL, always_stale)
    module_args({"policy": policy(OTHER), "api_token": TOKEN})

    with module_result.failure() as result:
        tailscale_policy.main()

    assert "contended" in result["msg"]
    assert "3 attempts" in result["msg"]
    assert tailnet.writes == 0, "a refused write applies nothing"


def test_the_etag_is_returned_for_the_next_run(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    module_args({"policy": policy(POLICY), "api_token": TOKEN})

    with module_result.success() as result:
        tailscale_policy.main()

    assert result["etag"] == ETAG


def test_a_policy_file_that_is_not_hujson_is_reported(
    module_args: Any, module_result: Any, server: Any, policy: Any
) -> None:
    module_args({"policy": policy("{not json"), "api_token": TOKEN})

    with module_result.failure() as result:
        tailscale_policy.main()

    assert "HuJSON" in result["msg"] or "hujson" in result["msg"].lower()


def _base() -> str:
    return _api.ApiOptions(base_url="https://api.tailscale.com/api/v2", tailnet="-").base_url


# Declaring part of the document on the task
# -------------------------------------------


def test_a_declared_group_reaches_the_document_that_is_written(
    module_args: Any, module_result: Any, server: Any, writable: Any
) -> None:
    module_args(
        {
            "policy": writable(),
            "api_token": TOKEN,
            "groups": {"group:eng": ["alice@example.com"]},
        }
    )

    with module_result.success() as result:
        tailscale_policy.main()

    assert result["changed"] is True
    assert result["diff"]["after"]["groups"] == {"group:eng": ["alice@example.com"]}
    assert loads(server.policy)["groups"] == {"group:eng": ["alice@example.com"]}


def test_a_declared_connector_reaches_the_document_that_is_written(
    module_args: Any, module_result: Any, server: Any, writable: Any
) -> None:
    module_args(
        {
            "policy": writable(),
            "api_token": TOKEN,
            "app_connectors": [WORKING_CONNECTOR],
        }
    )

    with module_result.success() as result:
        tailscale_policy.main()

    written = loads(server.policy)
    assert written["nodeAttrs"] == [
        {
            "target": ["*"],
            "app": {"tailscale.com/app-connectors": [WORKING_CONNECTOR]},
        }
    ]
    assert result["changed_paths"], "and the run says which nodes it would write"


def test_a_declared_test_reaches_the_document_that_is_written(
    module_args: Any, module_result: Any, server: Any, writable: Any, this_run: Any
) -> None:
    module_args(
        {
            "policy": writable(),
            "api_token": TOKEN,
            "tests": [{"src": "alice@example.com", "accept": ["100.64.0.1:22"]}],
        }
    )

    with module_result.success() as result:
        tailscale_policy.main()

    assert loads(server.policy)["tests"] == [
        {"src": "alice@example.com", "accept": ["100.64.0.1:22"]}
    ]
    assert this_run(result) == []


def test_a_declared_document_converges_on_a_second_run(
    module_args: Any, module_result: Any, server: Any, writable: Any
) -> None:
    """The invariant the whole collection is built around, for a declared document.

    The tailnet answers with the connector's own tag order, its group members in
    the order it chose, and the tests in the order they were written, so a
    second run has to see the document it wrote.
    """
    options = {
        "policy": writable(),
        "api_token": TOKEN,
        "groups": {"group:eng": ["zeta@example.com", "alpha@example.com"]},
        "app_connectors": [WORKING_CONNECTOR],
        "tests": [{"src": "alice@example.com", "deny": ["100.64.0.2:22"]}],
    }

    module_args(options)
    with module_result.success() as first:
        tailscale_policy.main()
    with module_result.success() as second:
        tailscale_policy.main()

    assert first["changed"] is True
    assert second["changed"] is False
    assert second["changed_paths"] == []
    assert server.writes == 1


def test_a_preset_app_is_written_as_the_identifier_tailscale_publishes(
    module_args: Any, module_result: Any, server: Any, writable: Any
) -> None:
    module_args(
        {
            "policy": writable(),
            "api_token": TOKEN,
            "app_connectors": [{"name": "gh", "connectors": ["tag:connector"], "preset": "GitHub"}],
        }
    )

    with module_result.success():
        tailscale_policy.main()

    entry = loads(server.policy)["nodeAttrs"][0]["app"]["tailscale.com/app-connectors"][0]
    assert entry == {
        "name": "gh",
        "connectors": ["tag:connector"],
        "presetAppID": "github",
    }, "and no domains key, which the server refuses alongside a preset"


def test_a_preset_app_outside_the_published_table_is_refused_by_the_argument_spec(
    module_args: Any, module_result: Any, server: Any, writable: Any
) -> None:
    module_args(
        {
            "policy": writable(),
            "api_token": TOKEN,
            "app_connectors": [
                {"name": "gh", "connectors": ["tag:connector"], "preset": "GitHub Enterprise"}
            ],
        }
    )

    with module_result.failure() as result:
        tailscale_policy.main()

    assert "GitHub Enterprise" in result["msg"]
    assert server.sent() == [], "a name outside the table costs no request"


def test_a_connector_whose_tag_is_unowned_is_refused_before_any_request(
    module_args: Any, module_result: Any, server: Any, writable: Any
) -> None:
    module_args(
        {
            "policy": writable(),
            "api_token": TOKEN,
            "app_connectors": [
                {"name": "example", "connectors": ["tag:unowned"], "domains": ["example.com"]}
            ],
        }
    )

    with module_result.failure() as result:
        tailscale_policy.main()

    assert "tag:unowned" in result["msg"]
    assert "must be a tag" in result["msg"], "the message carries the server's own reason"
    assert server.sent() == []


def test_a_connector_no_rule_can_reach_is_reported_and_the_write_proceeds(
    module_args: Any, module_result: Any, server: Any, writable: Any, this_run: Any
) -> None:
    module_args(
        {
            "policy": writable(),
            "api_token": TOKEN,
            "app_connectors": [WORKING_CONNECTOR],
        }
    )

    with module_result.success() as result:
        tailscale_policy.main()

    assert result["changed"] is True
    reported = this_run(result)
    assert any("reachable by no access rule" in warning for warning in reported)
    assert any("auto-approver" in warning for warning in reported)
    assert server.writes == 1, "the document is what the task asked for"


def test_a_connector_a_rule_and_an_approver_reach_is_reported_nothing(
    module_args: Any, module_result: Any, server: Any, writable: Any, this_run: Any
) -> None:
    module_args(
        {
            "policy": writable(
                {
                    **DECLARABLE,
                    "grants": [
                        {"src": ["autogroup:member"], "dst": ["tag:connector"], "ip": ["*"]}
                    ],
                    "autoApprovers": {"routes": {"100.64.0.0/10": ["tag:connector"]}},
                }
            ),
            "api_token": TOKEN,
            "app_connectors": [WORKING_CONNECTOR],
        }
    )

    with module_result.success() as result:
        tailscale_policy.main()

    assert this_run(result) == []


def test_a_file_naming_a_group_no_section_declares_is_reported(
    module_args: Any, module_result: Any, server: Any, policy: Any, this_run: Any
) -> None:
    module_args({"policy": policy(OTHER), "api_token": TOKEN})

    with module_result.success() as result:
        tailscale_policy.main()

    reported = this_run(result)
    assert any("group:eng" in warning for warning in reported)
    assert any("/acls/0/src" in warning for warning in reported), "and where it was named"


def test_a_group_the_file_and_the_task_disagree_about_is_refused(
    module_args: Any, module_result: Any, server: Any, writable: Any
) -> None:
    module_args(
        {
            "policy": writable({**DECLARABLE, "groups": {"group:eng": ["alice@example.com"]}}),
            "api_token": TOKEN,
            "groups": {"group:eng": ["bob@example.com"]},
        }
    )

    with module_result.failure() as result:
        tailscale_policy.main()

    assert "declared twice" in result["msg"]
    assert server.sent() == []


def test_a_group_the_task_repeats_in_another_order_is_not_a_conflict(
    module_args: Any, module_result: Any, server: Any, writable: Any
) -> None:
    declared = {**DECLARABLE, "groups": {"group:eng": ["alice@example.com", "bob@example.com"]}}
    module_args(
        {
            "policy": writable(declared),
            "api_token": TOKEN,
            "groups": {"group:eng": ["bob@example.com", "alice@example.com"]},
        }
    )

    with module_result.success() as result:
        tailscale_policy.main()

    assert not diff(result["diff"]["after"], declared), (
        "the two spellings are the same document, and the server sorts group members anyway"
    )


def test_a_declared_document_is_not_written_in_check_mode(
    module_args: Any, module_result: Any, server: Any, writable: Any
) -> None:
    module_args(
        {"policy": writable(), "api_token": TOKEN, "app_connectors": [WORKING_CONNECTOR]},
        check_mode=True,
    )

    with module_result.success() as result:
        tailscale_policy.main()

    assert result["changed"] is True
    assert result["diff"]["after"]["nodeAttrs"]
    assert server.writes == 0
    assert server.validated == 0


def test_a_declared_document_still_needs_the_opening_opt_in(
    module_args: Any, module_result: Any, server: Any, writable: Any
) -> None:
    module_args(
        {
            "policy": writable({}),
            "api_token": TOKEN,
            "groups": {"group:eng": ["alice@example.com"]},
        }
    )

    with module_result.failure() as result:
        tailscale_policy.main()

    assert "allow_all_traffic" in result["msg"]
    assert server.sent() == [], "the guard runs on the document the task composed"
