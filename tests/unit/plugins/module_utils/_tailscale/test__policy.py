# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the policy read, compare and guarded-write cycle."""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Response
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import loads
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleBadRequest,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscalePreconditionFailed,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._policy import Outcome
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._policy import PolicyError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._policy import check_widening
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._policy import opens_tailnet
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._policy import read
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._policy import reconcile
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._policy import validate
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._policy import write

DENY_ALL: dict[str, Any] = {"acls": []}
ONE_RULE: dict[str, Any] = {
    "acls": [{"action": "accept", "src": ["group:eng"], "dst": ["tag:web:443"]}]
}
ETAG = '"e0b2816b418"'
TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"


class Call:
    """One request the code under test asked for."""

    def __init__(self, name: str, method: str, **kwargs: Any) -> None:
        self.name = name
        self.method = method
        self.kwargs = kwargs


class FakeApi:
    """A recording stand-in for :class:`._api.Api`.

    Only the surface the policy cycle uses, because a fake that mirrors the whole
    client is a second implementation to keep in step with the first.
    """

    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.calls: list[Call] = []

    def call(self, name: str, method: str, **kwargs: Any) -> Response:
        self.calls.append(Call(name, method, **kwargs))
        if not self.responses:
            raise AssertionError(f"unexpected call to {name}")
        answer = self.responses.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def named(self) -> list[str]:
        return [call.name for call in self.calls]

    def headers_of(self, name: str) -> dict:
        for call in self.calls:
            if call.name == name:
                return call.kwargs.get("headers") or {}
        raise AssertionError(f"no call to {name}")


def policy_response(policy: Any, etag: str = ETAG) -> Response:
    return Response(status=200, body=policy, etag=etag)


def accepted(body: Any = None) -> Response:
    """A 200 that reported nothing wrong, which is what a passing answer looks like.

    It used to be a `RawResponse`, the transport shape rather than the caller's,
    and nothing caught it because `validate` discarded the reply. Reading the
    reply is what exposed the double as wrong.
    """
    return Response(status=200, body=body if body is not None else {}, etag=ETAG)


#: The vendored description names three 200 outcomes. These are the two that carry
#: a `data` array, and telling them apart is the whole point.
FAILURE: list[dict[str, Any]] = [
    {
        "user": "eng@example.com",
        "errors": ['address "10.0.0.1:22": want: Drop, got: Accept'],
    }
]
WARNING: list[dict[str, Any]] = [
    {
        "user": "group:unknown@example.com",
        "warnings": [
            "group is not syncing from SCIM and will be ignored by rules in the policy file"
        ],
    }
]


def validate_answers_with(entries: list[dict[str, Any]]) -> Response:
    """A validator 200 carrying `entries`, which may be failures or warnings."""
    failed = any("errors" in entry for entry in entries)
    return Response(
        status=200,
        body={"message": "test(s) failed" if failed else "warning(s) found", "data": entries},
        etag=ETAG,
    )


def test_reading_returns_the_policy_and_its_fingerprint() -> None:
    api = FakeApi(policy_response(ONE_RULE))

    current = read(api)

    assert current.policy == ONE_RULE
    assert current.etag == ETAG
    assert api.named() == ["policy_get"]


def test_reading_parses_hujson_that_the_transport_could_not() -> None:
    hujson = '{\n  // a comment\n  "acls": []\n}\n'
    api = FakeApi(Response(status=200, body=hujson, etag=ETAG))

    assert read(api).policy == DENY_ALL


def test_a_policy_that_is_already_right_writes_nothing() -> None:
    api = FakeApi(policy_response(ONE_RULE))

    outcome = reconcile(api, ONE_RULE)

    assert outcome == Outcome(
        changed=False,
        differences=[],
        etag=ETAG,
        before=ONE_RULE,
        after=ONE_RULE,
        warnings=[],
    )
    assert api.named() == ["policy_get"], "an unchanged policy must not be written"


def test_a_second_run_over_its_own_output_changes_nothing() -> None:
    """The property the whole collection is built around."""
    # The second read returns what the first write put there, which is the
    # server echoing the document back unchanged.
    api = FakeApi(
        policy_response(DENY_ALL),
        accepted(),
        accepted(),
        policy_response(ONE_RULE, '"after"'),
    )
    first = reconcile(api, ONE_RULE)
    assert first.changed is True

    # The second read sees what the first write put there, byte for byte.
    again = reconcile(api, ONE_RULE)

    assert again.changed is False, "reconciling identical input twice must converge"
    assert again.differences == []


def test_an_outcome_carries_both_documents_for_a_diff() -> None:
    """`diff_mode: support: full` is a promise about `before` and `after`.

    Ansible renders a diff from exactly those two keys and nothing else, so a
    module that declares full support without returning them prints nothing under
    `--diff` while its documentation promises otherwise.
    """
    api = FakeApi(policy_response(DENY_ALL), accepted(), accepted())

    outcome = reconcile(api, ONE_RULE)

    assert outcome.before == DENY_ALL, "the document as the tailnet held it"
    assert outcome.after == ONE_RULE, "the document it was reconciled to"


def test_an_unchanged_run_reports_the_same_document_on_both_sides() -> None:
    api = FakeApi(policy_response(ONE_RULE))

    outcome = reconcile(api, ONE_RULE)

    assert outcome.changed is False
    assert outcome.before == outcome.after == ONE_RULE


def test_a_check_run_reports_the_document_it_would_have_written() -> None:
    """Nothing is written, so the after document is the only place it appears."""
    api = FakeApi(policy_response(DENY_ALL))

    outcome = reconcile(api, ONE_RULE, check_mode=True)

    assert outcome.changed is True
    assert outcome.after == ONE_RULE
    assert api.named() == ["policy_get"], "check mode makes exactly one request"


def test_a_differing_policy_is_validated_before_it_is_written() -> None:
    api = FakeApi(policy_response(DENY_ALL), accepted(), accepted())

    outcome = reconcile(api, ONE_RULE)

    assert outcome.changed is True
    assert api.named() == ["policy_get", "policy_validate", "policy_set"]
    assert outcome.differences, "a change must be reported as a change"


def test_a_policy_the_server_refuses_is_never_written() -> None:
    api = FakeApi(
        policy_response(DENY_ALL),
        TailscaleBadRequest("invalid ACL", 400, "POST", "/tailnet/-/acl/validate"),
    )

    with pytest.raises(TailscaleBadRequest):
        reconcile(api, ONE_RULE)

    assert "policy_set" not in api.named(), "a refused document must not be written"


def test_a_precondition_failure_converges_on_the_second_attempt() -> None:
    """A 412 is not terminal: read again, recompute, and write what is now there."""
    rival = {"groups": {"group:eng": ["alice@example.com"]}}
    second = {**DENY_ALL, **rival}
    api = FakeApi(
        policy_response(DENY_ALL),
        accepted(),
        TailscalePreconditionFailed("mismatch", 412, "POST", "/tailnet/-/acl"),
        policy_response(second, '"second"'),
        accepted(),
        accepted(),
    )

    outcome = reconcile(api, ONE_RULE)

    assert outcome.changed is True
    assert outcome.before == second, "the diff is against what the second read saw"
    assert outcome.after == ONE_RULE, "and the declared document is what is written"
    assert api.named() == [
        "policy_get",
        "policy_validate",
        "policy_set",
        "policy_get",
        "policy_validate",
        "policy_set",
    ]


def test_the_retry_writes_the_declared_document_and_reports_what_it_removed() -> None:
    """The retry is about the read, not about preserving a section by accident.

    A section another writer adds during the race is not carried forward. This
    reconciles the whole document, so a section the file does not declare is
    removed on the next run whether or not a race happened, and keeping it for one
    run would leave the tailnet holding something the file cannot explain and cost
    a second changed run when the next one removed it. What the retry owes is that
    the write is computed from the document it just read, which is what makes the
    reported ``before`` truthful.
    """
    added = {"hosts": {"gateway": "100.64.0.1"}}
    api = FakeApi(
        policy_response(DENY_ALL),
        accepted(),
        TailscalePreconditionFailed("mismatch", 412, "POST", "/tailnet/-/acl"),
        policy_response({**DENY_ALL, **added}, '"second"'),
        accepted(),
        accepted(),
    )

    outcome = reconcile(api, ONE_RULE)

    written = loads(api.calls[-1].kwargs["body"])
    assert written == ONE_RULE, "the declared document is what is written"
    assert outcome.before == {**DENY_ALL, **added}, (
        "the diff is against the document the retry read, so the removal is visible"
    )


def test_a_retry_that_finds_nothing_to_do_writes_nothing() -> None:
    """The second read can already match the declared document, so no write follows."""
    api = FakeApi(
        policy_response(DENY_ALL),
        accepted(),
        TailscalePreconditionFailed("mismatch", 412, "POST", "/tailnet/-/acl"),
        policy_response(ONE_RULE, '"second"'),
    )

    outcome = reconcile(api, ONE_RULE)

    assert outcome.changed is False
    assert outcome.before == outcome.after == ONE_RULE
    assert api.named() == ["policy_get", "policy_validate", "policy_set", "policy_get"]


def test_a_document_that_changes_on_every_attempt_is_contended() -> None:
    """The retry is bounded at three, so a document that never settles fails."""
    api = FakeApi()
    for index in range(3):
        api.responses.extend(
            [
                policy_response({**DENY_ALL, f"section{index}": True}),
                accepted(),
                TailscalePreconditionFailed("mismatch", 412, "POST", "/tailnet/-/acl"),
            ]
        )

    with pytest.raises(TailscalePreconditionFailed) as caught:
        reconcile(api, ONE_RULE)

    assert "contended" in str(caught.value)
    assert "3 attempts" in str(caught.value)
    assert api.named().count("policy_set") == 3, "the bound is three attempts"
    assert api.named().count("policy_get") == 3


def test_check_mode_reads_and_stops() -> None:
    api = FakeApi(policy_response(DENY_ALL))

    outcome = reconcile(api, ONE_RULE, check_mode=True)

    assert outcome.changed is True
    assert outcome.differences
    assert api.named() == ["policy_get"], "check mode makes exactly one request, a read"


def test_a_write_without_a_fingerprint_is_refused() -> None:
    # The desired document has to differ, or reconciliation returns before it
    # reaches the write and the guard is never exercised.
    api = FakeApi(policy_response(ONE_RULE, etag=""), accepted())

    with pytest.raises(PolicyError, match="unguarded"):
        reconcile(api, DENY_ALL)

    assert "policy_set" not in api.named(), "the whole point is that nothing is sent"


def test_a_write_whose_fingerprint_is_absent_is_refused() -> None:
    api = FakeApi(policy_response(ONE_RULE, etag=""))

    with pytest.raises(PolicyError, match="unguarded"):
        write(api, DENY_ALL, "")

    assert api.calls == []


def test_a_write_sends_the_fingerprint_it_was_given() -> None:
    api = FakeApi(accepted())

    write(api, DENY_ALL, ETAG)

    assert api.headers_of("policy_set")["If-Match"] == ETAG


def test_a_write_sends_the_policy_as_hujson() -> None:
    api = FakeApi(accepted())

    write(api, DENY_ALL, ETAG)

    assert api.headers_of("policy_set")["Content-Type"] == "application/hujson"


def test_a_document_with_no_access_keys_opens_the_tailnet() -> None:
    assert opens_tailnet({}) is True
    assert opens_tailnet({"groups": {"group:eng": ["a@example.com"]}}) is True


@pytest.mark.parametrize(
    "document",
    [{"acls": []}, {"grants": []}, {"acls": [], "ssh": []}, {"grants": [{}], "acls": []}],
)
def test_a_document_with_an_access_key_does_not(document: dict[str, Any]) -> None:
    assert opens_tailnet(document) is False


@pytest.mark.parametrize("document", [None, [], "acls", 7, True])
def test_a_document_that_is_not_an_object_is_treated_as_opening(document: Any) -> None:
    assert opens_tailnet(document) is True


@pytest.mark.parametrize(
    "document",
    [
        {"acls": None},
        {"grants": None},
        {"acls": None, "grants": None},
        {"acls": "[]"},
        {"acls": {}, "ssh": []},
    ],
)
def test_a_null_where_the_rules_belong_is_treated_as_opening(document: dict[str, Any]) -> None:
    # A rendered-but-empty variable arrives as a null, which is a nil slice on the
    # server and therefore the same allow-all as an absent key. Testing presence
    # rather than the value let exactly that through the guard.
    assert opens_tailnet(document) is True


def test_an_opening_document_is_refused_without_the_opt_in() -> None:
    with pytest.raises(PolicyError, match="allow"):
        check_widening({}, allow_all_traffic=False)


def test_an_opening_document_is_permitted_with_the_opt_in() -> None:
    check_widening({}, allow_all_traffic=True)


def test_a_closed_document_needs_no_opt_in() -> None:
    check_widening(DENY_ALL, allow_all_traffic=False)
    check_widening(ONE_RULE, allow_all_traffic=False)


def test_an_opening_document_is_refused_before_anything_is_read() -> None:
    api = FakeApi()

    with pytest.raises(PolicyError):
        reconcile(api, {})

    assert api.calls == [], "refuse before spending a request"


def test_a_report_only_run_of_validate_sends_the_document() -> None:
    api = FakeApi(accepted())

    validate(api, ONE_RULE)

    body = api.calls[0].kwargs["body"]
    assert json.loads(body) == ONE_RULE


def test_a_failed_validation_is_caught_by_the_verdict_not_by_a_status() -> None:
    """The endpoint answers 200 for a policy whose own tests failed.

    The refusal is in the body, so a caller that only looked at the status
    proved nothing. This is the shape the vendored spec documents, with the
    failure list the API returns.
    """
    api = FakeApi(validate_answers_with(FAILURE))

    with pytest.raises(PolicyError) as caught:
        validate(api, ONE_RULE)

    message = str(caught.value)
    assert "own tests" in message
    assert "eng@example.com" in message, "the operator needs to know which test failed"
    assert "want: Drop" in message, "and why it failed"


def test_a_warning_is_not_treated_as_a_failure() -> None:
    """The same 200 also carries warnings, and a valid policy must still write.

    The vendored description names three 200 outcomes: tests failed with `errors`
    per entry, warnings found with `warnings` per entry, and success with an empty
    body. Refusing on the presence of an entry turned every SCIM warning into a
    refusal of a valid policy, and named the wrong cause while doing it.
    """
    api = FakeApi(validate_answers_with(WARNING))

    reported = validate(api, ONE_RULE)

    assert reported, "the warning is the server's own and is actionable, so it is returned"
    assert "warning" in reported[0]
    assert "not syncing from SCIM" in reported[0]


def test_a_warning_reaches_the_result_so_the_operator_sees_it() -> None:
    api = FakeApi(policy_response(DENY_ALL), validate_answers_with(WARNING), accepted())

    outcome = reconcile(api, ONE_RULE)

    assert outcome.changed is True, "a warning must not stop the write"
    assert outcome.warnings


def test_an_error_and_a_warning_together_refuse_and_name_the_error() -> None:
    api = FakeApi(validate_answers_with([*FAILURE, *WARNING]))

    with pytest.raises(PolicyError) as caught:
        validate(api, ONE_RULE)

    assert "want: Drop" in str(caught.value)
    assert "not syncing from SCIM" not in str(caught.value), "the refusal is about errors"


def test_an_entry_with_neither_key_is_not_a_failure() -> None:
    """The discriminator is `errors`, not the presence of the entry."""
    api = FakeApi(validate_answers_with([{"user": "someone@example.com"}]))

    assert validate(api, ONE_RULE) == []


def test_the_subject_of_a_finding_is_scrubbed_and_capped_like_its_reason() -> None:
    """`user` comes from the document's own rules and is the one unbounded value."""
    api = FakeApi(
        validate_answers_with(
            [
                {
                    "user": f"Authorization: Bearer {TOKEN} " + "x" * 500,
                    "errors": ["unreachable"],
                }
            ]
        )
    )

    with pytest.raises(PolicyError) as caught:
        validate(api, ONE_RULE)

    assert TOKEN not in str(caught.value)
    assert "[redacted]" in str(caught.value)


def test_a_credential_quoted_in_a_failure_is_stripped() -> None:
    """A rule may quote a value shaped like a credential; the message is long-lived."""
    api = FakeApi(
        Response(
            status=200,
            body={
                "message": "test(s) failed",
                "data": [
                    {
                        "user": "eng@example.com",
                        "errors": ["src: tskey-api-abcdefghijklmnop is not a valid group"],
                    }
                ],
            },
            etag=ETAG,
        )
    )

    with pytest.raises(PolicyError) as caught:
        validate(api, ONE_RULE)

    assert "tskey-api-abcdefghijklmnop" not in str(caught.value)


def test_many_failures_are_bounded_rather_than_pasted_in_full() -> None:
    api = FakeApi(
        Response(
            status=200,
            body={
                "message": "test(s) failed",
                "data": [
                    {"user": f"user{index}@example.com", "errors": [f"rule {index} did not hold"]}
                    for index in range(40)
                ],
            },
            etag=ETAG,
        )
    )

    with pytest.raises(PolicyError) as caught:
        validate(api, ONE_RULE)

    message = str(caught.value)
    assert "and 35 more" in message
    assert "user39@example.com" not in message, "the message stops at the budget"
