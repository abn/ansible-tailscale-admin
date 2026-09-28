# SPDX-License-Identifier: BSD-2-Clause
"""`tailscale_policy` against a real tailnet, through the module.

Every assertion drives the module's ``main()``, never the kernel. The kernel has
unit tests; what this file is for is the module as a user meets it, which means
argument validation, check mode, diff mode and, above all, that a second run
reports ``changed: 0``.

Cleanup is the ``preserved`` fixture, which restores the policy in a ``finally``.
The policy endpoint replaces the whole document, so a test that changes it and
does not put it back changes it for every test after it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import loads
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscalePreconditionFailed,
)
from ansible_collections.abn.tailscale.plugins.modules import tailscale_policy

pytestmark = pytest.mark.live_smoke

#: Deny-all, which is the safe direction and needs no opt-in, and is the state
#: most of these tests start from and are restored to.
DENY_ALL = '{\n  "acls": [],\n}\n'


def _policy_file(tmp_path: Path, body: str | dict[str, Any]) -> str:
    """Write a HuJSON policy and return its path.

    A file rather than a template, because the module reads a path and a test that
    did not exercise that would miss a whole class of failure.
    """
    target = tmp_path / "policy.hujson"
    target.write_text(json.dumps(body) + "\n" if isinstance(body, dict) else body, encoding="utf-8")
    return str(target)


def one_rule_to(address: str) -> str:
    """A document with a single rule, addressed to a device that exists.

    The address comes from a generated device rather than a literal. A hard-coded
    Tailscale IP resolves only while some node holds it, so on a tailnet without
    one the write is refused for a reason that has nothing to do with the module,
    and the failure reads like a module bug.
    """
    return f"""{{
  "acls": [
    {{"action": "accept", "src": ["*"], "dst": ["{address}:443"]}},
  ],
}}
"""


def _run(
    module_args: Any, module_result: Any, options: dict[str, Any], **flags: Any
) -> dict[str, Any]:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_policy.main()
    return dict(result)


def _expect_failure(
    module_args: Any, module_result: Any, options: dict[str, Any]
) -> dict[str, Any]:
    module_args(options)
    with module_result.failure() as result:
        tailscale_policy.main()
    return dict(result)


#: The tag every app connector in this file routes through. It is granted in the
#: document each test writes rather than assumed, because a tag exists only where
#: `tagOwners` declares it and the server refuses the write otherwise.
CONNECTOR = "tag:ac-connector"

#: The eleven preset apps the module holds an identifier for, as the name
#: Tailscale publishes and the identifier the API wants. Written out here rather
#: than read from the module, because a test that asserts the module's table
#: against itself proves nothing. The four apps that carry a region are absent by
#: design: Tailscale owns the list of regions and local zones, so a task gives
#: those an identifier rather than composing one.
FIXED_PRESETS = {
    "AWS CloudFront (global)": "aws-cloudfront-global",
    "Confluence": "confluence",
    "GitHub": "github",
    "Google Workspace": "google-workspace",
    "Jira": "jira",
    "Microsoft 365": "microsoft-365",
    "Okta": "okta",
    "Oracle Services Network (global)": "oracle-osn-global",
    "Salesforce (Hyperforce environment)": "salesforce-hyperforce",
    "Salesforce (Salesforce-hosted)": "salesforce",
    "Stripe": "stripe",
}


def declared_document(address: str, *, reachable: bool = True) -> dict[str, Any]:
    """A document an app connector, a group and a test can be declared into.

    `reachable` decides whether the connector's tag is made reachable and
    approved. Both matter, because the module reports a connector that is
    neither as doing nothing, and a test that wants that warning asks for the
    document without them.
    """
    document: dict[str, Any] = {
        "acls": [{"action": "accept", "src": ["*"], "dst": [f"{address}:22"]}],
        "tagOwners": {CONNECTOR: ["autogroup:admin"]},
    }
    if reachable:
        document["grants"] = [
            {
                "src": ["autogroup:member"],
                "dst": [CONNECTOR],
                "ip": ["tcp:53", "udp:53"],
            }
        ]
        document["autoApprovers"] = {"routes": {"0.0.0.0/0": [CONNECTOR], "::/0": [CONNECTOR]}}
    return document


def one_connector(**overrides: Any) -> dict[str, Any]:
    """One app connector declaration, with the tag a test needs to be reachable."""
    entry: dict[str, Any] = {
        "name": "ac-probe",
        "connectors": [CONNECTOR],
        "preset": "GitHub",
    }
    entry.update(overrides)
    return entry


def connectors_of(document: Any) -> list[dict[str, Any]]:
    """The app connectors a stored document holds, wherever the map sits."""
    for entry in document.get("nodeAttrs", []):
        app = entry.get("app", {}) if isinstance(entry, dict) else {}
        if "tailscale.com/app-connectors" in app:
            return app["tailscale.com/app-connectors"]
    return []


def messages_of(result: dict[str, Any]) -> list[str]:
    """The warning texts a run produced, in the shape `AnsibleModule.warn` records."""
    return [str(item.event.msg) for item in result.get("warnings", [])]


def test_a_full_write_then_read_converges(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
    device_address: str,
) -> None:
    """Create, then reconcile again, and the second run must report no change.

    The property the whole collection is built around, against a real API, on a
    resource that replaces a whole document.
    """
    with preserved("policy"):
        path = _policy_file(tmp_path, one_rule_to(device_address))

        first = _run(module_args, module_result, {**credentials, "policy": path}, diff=True)
        assert first["changed"] is True
        assert first["changed_paths"], "a write that changed something must say what"
        assert first["diff"]["after"]["acls"], "the diff must carry the document it wrote"

        # This is the assertion that matters. The server's canonical form is not
        # the file's, so without canonicalisation every run reports a change.
        second = _run(module_args, module_result, {**credentials, "policy": path})
        assert second["changed"] is False
        assert second["changed_paths"] == []
        assert second["diff"]["before"] == second["diff"]["after"]


def test_a_document_given_as_content_is_written_and_then_converges(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    device_address: str,
) -> None:
    """The text a play already holds reconciles as the same document in a file does."""
    with preserved("policy"):
        document = one_rule_to(device_address)

        first = _run(module_args, module_result, {**credentials, "content": document}, diff=True)
        assert first["changed"] is True
        assert first["changed_paths"], "a write that changed something must say what"

        second = _run(module_args, module_result, {**credentials, "content": document})
        assert second["changed"] is False
        assert second["diff"]["before"] == second["diff"]["after"]


def test_check_mode_reports_the_change_without_writing(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
    device_address: str,
) -> None:
    """A check run must leave the tailnet exactly as it found it."""
    with preserved("policy"):
        before = api.call("policy_get", "GET").body
        path = _policy_file(tmp_path, one_rule_to(device_address))

        result = _run(module_args, module_result, {**credentials, "policy": path}, check_mode=True)

        assert result["changed"] is True, "check mode still reports what it would do"
        assert result["changed_paths"], "and which nodes"
        after = api.call("policy_get", "GET").body
        assert after == before, "and it wrote nothing"


def test_a_real_second_run_of_check_mode_reports_no_change(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
    device_address: str,
) -> None:
    """Check mode over a policy already in place, which is the first run an operator does."""
    with preserved("policy"):
        path = _policy_file(tmp_path, one_rule_to(device_address))
        _run(module_args, module_result, {**credentials, "policy": path})

        result = _run(module_args, module_result, {**credentials, "policy": path}, check_mode=True)

        assert result["changed"] is False, "the tailnet already matches the file"
        assert result["changed_paths"] == []


def test_a_missing_file_fails_with_a_message_not_a_traceback(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    tmp_path: Path,
) -> None:
    """The most likely first mistake, and it must be readable."""
    absent = tmp_path / "not-here.hujson"

    result = _expect_failure(module_args, module_result, {**credentials, "policy": str(absent)})

    assert "not-here.hujson" in result["msg"]
    assert "cannot read" in result["msg"]
    assert "Traceback" not in result["msg"]
    assert "FileNotFoundError" not in result["msg"]


def test_unparseable_hujson_fails_before_any_write(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
) -> None:
    """A file that does not parse must not cost a request that changes something."""
    with preserved("policy"):
        before = api.call("policy_get", "GET").body
        path = _policy_file(tmp_path, "{ this is not a policy\n")

        result = _expect_failure(module_args, module_result, {**credentials, "policy": path})

        assert result["msg"]
        assert api.call("policy_get", "GET").body == before, "nothing was written"


def test_a_document_that_opens_the_tailnet_needs_the_opt_in(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
) -> None:
    """Invariant 3, against the real API rather than a mock of it."""
    with preserved("policy"):
        path = _policy_file(tmp_path, "{}\n")

        refused = _expect_failure(module_args, module_result, {**credentials, "policy": path})
        assert "allow_all_traffic" in refused["msg"], "the message names the way forward"

        allowed = _run(
            module_args,
            module_result,
            {**credentials, "policy": path, "allow_all_traffic": True},
        )
        assert allowed["changed"] is True


def test_an_empty_list_needs_no_opt_in(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
) -> None:
    """Measured against the server's own evaluator: an empty list is deny-all.

    The other half of the previous test, and the case where being cautious would
    be wrong. A guard that refused this would make the safe policy unwritable.
    """
    with preserved("policy"):
        path = _policy_file(tmp_path, DENY_ALL)

        result = _run(module_args, module_result, {**credentials, "policy": path})

        assert result["changed"] is True
        assert api.call("policy_get", "GET").body == {"acls": []}


def test_a_failing_test_in_the_document_is_refused_with_its_reason(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
    device_address: str,
) -> None:
    """The validator's verdict is in a 200 body, and it must be read.

    The document denies everything, so the only thing the server can object to is
    its own test: it asks for a reachability the policy does not grant, and the
    verdict arrives in a 200 rather than a status. Both selectors are taken from
    the run rather than written down, so the test says what it means on any
    tailnet and the address is one a device really holds.
    """
    with preserved("policy"):
        document = {
            "acls": [],
            "tests": [
                {
                    "src": device_address,
                    "accept": [f"{device_address}:22"],
                    "deny": [f"{device_address}:22"],
                }
            ],
        }
        path = _policy_file(tmp_path, json.dumps(document) + "\n")

        result = _expect_failure(module_args, module_result, {**credentials, "policy": path})

        assert "failed its own tests" in result["msg"]
        assert "Traceback" not in result["msg"]


def test_a_written_policy_comes_back_canonicalised(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
) -> None:
    """A file with comments and trailing commas is accepted and stored as JSON.

    The HuJSON path is most of what a real policy file is, and if the stored
    document did not match the canonical form then the second run of every other
    test here would report a change.
    """
    with preserved("policy"):
        messy = '{\n  // a comment\n  "acls": [],\n}\n'
        path = _policy_file(tmp_path, messy)

        _run(module_args, module_result, {**credentials, "policy": path})

        stored = api.call("policy_get", "GET").body
        assert stored == {"acls": []}, "stored as the canonical document, not the file"
        again = _run(module_args, module_result, {**credentials, "policy": path})
        assert again["changed"] is False, "so the file and the tailnet agree"


def test_an_etag_is_reported_and_is_the_one_the_next_write_guards_with(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
    device_address: str,
) -> None:
    """Invariant 2, observed rather than asserted.

    The reported fingerprint is the one from the read, which is what a later write
    carries as `If-Match`. The comparison is between the second and third run, not
    the first and second: the first run's value was read before its own write, and
    the write reissued one, so the first two legitimately differ. Measured: six
    reads with no write between them all return the same value, so it is the write
    that changes it and not the read.

    Asserted through the result rather than by reading the header, because the
    result is what a user is shown.
    """
    with preserved("policy"):
        path = _policy_file(tmp_path, one_rule_to(device_address))
        first = _run(module_args, module_result, {**credentials, "policy": path})
        second = _run(module_args, module_result, {**credentials, "policy": path})
        third = _run(module_args, module_result, {**credentials, "policy": path})

        assert first["etag"], "a policy read carries a fingerprint"
        assert second["changed"] is False, "the second run had nothing to do"
        assert third["etag"] == second["etag"], (
            "so a run that changes nothing reports the fingerprint it read, and the "
            "next write is guarded by it"
        )


def test_a_concurrent_edit_converges_and_the_diff_reports_the_replacement(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
    device_address: str,
    monkeypatch: Any,
) -> None:
    """Invariant 2, narrowed: a write refused with a 412 re-reads and converges.

    The API offers no way to interleave two writers mid-request, so the race is
    driven where it lives: the client lands another writer's edit between this
    run's read and its write, the write is refused with a 412, and the run reads
    again, recomputes and writes. The edit is a section the task does not declare,
    so this reconciles the whole document and that section goes, which is what
    happens on any run. What the retry owes is that the run reports it: the diff's
    ``before`` is the document the retry read.
    """
    from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._policy import write

    with preserved("policy"):
        added = {"hosts": {"gateway": "192.0.2.1"}}
        landed = {"done": False}

        class OneLandedEdit:
            """The real client, with one out-of-band write landing before the first write."""

            def __init__(self, client: Api) -> None:
                self._client = client

            def call(self, name: str, method: str, **kwargs: Any) -> Any:
                if name == "policy_set" and not landed["done"]:
                    landed["done"] = True
                    current = self._client.call("policy_get", "GET", expect_etag=True)
                    body = loads(current.body) if isinstance(current.body, str) else current.body
                    self._client.call(
                        "policy_set",
                        "POST",
                        body=json.dumps({**body, **added}) + "\n",
                        headers={
                            "Content-Type": "application/hujson",
                            "If-Match": current.etag,
                        },
                    )
                return self._client.call(name, method, **kwargs)

        monkeypatch.setattr(tailscale_policy, "build_client", lambda params: OneLandedEdit(api))
        path = _policy_file(tmp_path, one_rule_to(device_address))

        result = _run(module_args, module_result, {**credentials, "policy": path})

        assert result["changed"] is True
        assert result["diff"]["before"].get("hosts") == added["hosts"], "the retry read saw it"
        stored = api.call("policy_get", "GET").body
        assert "hosts" not in stored, "a section the file does not declare is removed"
        assert stored["acls"] == loads(one_rule_to(device_address))["acls"], (
            "while the declared state was applied"
        )

        # The guard itself, unchanged, with a fingerprint the server has never
        # issued. Asserted at the seam rather than through the module, because the
        # module reads a fresh fingerprint every run and would never present one.
        with pytest.raises(TailscalePreconditionFailed) as refused:
            write(api, {"acls": []}, "0" * 12)
        assert "changed after this run read it" in refused.value.message


def test_a_malformed_document_names_what_the_server_objected_to(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
) -> None:
    """The API's own reason must reach the operator, with nothing leaked.

    The rule names a group this tailnet does not have, which the API refuses with
    "group not found". That is a real refusal from a real API, and it is the shape
    an operator hits when a policy is applied before its groups exist.
    """
    with preserved("policy"):
        document = {"acls": [{"action": "accept", "src": ["group:nosuchgroup"], "dst": ["*:*"]}]}
        path = _policy_file(tmp_path, json.dumps(document) + "\n")

        result = _expect_failure(module_args, module_result, {**credentials, "policy": path})

        message = result["msg"]
        assert "group not found" in message, "the server's own reason reaches the operator"
        assert "Traceback" not in message
        for secret in credentials.values():
            assert secret not in message, "no credential in a failure message"


def test_no_credential_option_at_all_fails_before_any_request(
    module_args: Any,
    module_result: Any,
    api: Api,
    tmp_path: Path,
) -> None:
    """A task with no credential fails on the spot rather than after a request."""
    path = _policy_file(tmp_path, DENY_ALL)

    result = _expect_failure(module_args, module_result, {"policy": path})

    assert "api_token" in result["msg"] or "oauth_client_id" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_credential_of_the_wrong_shape_is_refused_before_a_request(
    module_args: Any,
    module_result: Any,
    tmp_path: Path,
) -> None:
    """Half an OAuth client is not a credential, and saying so is better than a 401."""
    path = _policy_file(tmp_path, DENY_ALL)

    result = _expect_failure(
        module_args, module_result, {"policy": path, "oauth_client_id": "k-example"}
    )

    assert "oauth_client_secret" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_refused_credential_reports_a_message_a_person_can_act_on(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    tmp_path: Path,
) -> None:
    """A bad secret against the real API, which answers 401 for several causes.

    The message cannot tell a missing secret from a malformed one from an expired
    one, and must say so rather than guessing, so the assertions are that it names
    the credential as the problem and never echoes the secret back.
    """
    path = _policy_file(tmp_path, DENY_ALL)
    bad = {**credentials, "oauth_client_secret": "not-the-secret"}

    module_args({**bad, "policy": path})
    with module_result.failure() as result:
        tailscale_policy.main()

    message = result["msg"]
    assert "401" in message, "the status the token endpoint answered with"
    assert "Traceback" not in message
    assert "not-the-secret" not in message, "the secret is not echoed back"
    assert credentials["oauth_client_id"] not in message, "nor the client id"


def test_a_declared_document_converges_and_the_second_run_reports_no_change(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
    device_address: str,
) -> None:
    """Groups, an app connector and a test, all declared on one task.

    The three shapes that nest, in the run that has to converge. Group members
    are the case the server reorders, so a canonical form that did not treat
    them as a set would report a change for ever.
    """
    with preserved("policy"):
        path = _policy_file(tmp_path, declared_document(device_address))
        options = {
            **credentials,
            "policy": path,
            "groups": {"group:ac-probe": ["zeta@example.com", "alpha@example.com"]},
            "app_connectors": [one_connector()],
            "tests": [{"src": device_address, "accept": [f"{device_address}:22"]}],
        }

        first = _run(module_args, module_result, options)
        assert first["changed"] is True

        second = _run(module_args, module_result, options)
        assert second["changed"] is False, (
            f"the tailnet and the task disagree after one write: {second['changed_paths']}"
        )

        stored = api.call("policy_get", "GET").body
        assert stored["groups"] == {"group:ac-probe": ["alpha@example.com", "zeta@example.com"]}, (
            "and the server is what sorted them"
        )
        assert connectors_of(stored) == [
            {"name": "ac-probe", "connectors": [CONNECTOR], "presetAppID": "github"}
        ]
        assert stored["tests"] == [{"src": device_address, "accept": [f"{device_address}:22"]}]


def test_every_preset_app_the_module_holds_is_accepted_and_stored_as_written(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
    device_address: str,
) -> None:
    """The whole mapping, against the server that owns the truth about it.

    A wrong identifier is a connector that fetches no domains, and the module
    holds the mapping from the name Tailscale publishes to the identifier it
    writes. All eleven go into one document so that a wrong one is a refusal
    naming the entry rather than a hole in the coverage.
    """
    with preserved("policy"):
        path = _policy_file(tmp_path, declared_document(device_address))
        options = {
            **credentials,
            "policy": path,
            "app_connectors": [
                {
                    "name": f"ac-{index}",
                    "connectors": [CONNECTOR],
                    "preset": preset,
                }
                for index, preset in enumerate(FIXED_PRESETS)
            ],
        }

        first = _run(module_args, module_result, options)
        assert first["changed"] is True

        stored = connectors_of(api.call("policy_get", "GET").body)
        assert [entry["presetAppID"] for entry in stored] == list(FIXED_PRESETS.values()), (
            "and the server stored what the module wrote, for every row of the table"
        )
        assert not any("domains" in entry for entry in stored), (
            "a preset app carries no domains, and the server refuses any"
        )

        second = _run(module_args, module_result, options)
        assert second["changed"] is False, second["changed_paths"]


def test_a_parametrised_preset_app_is_stored_as_the_task_gave_it(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
    device_address: str,
) -> None:
    """The region-carrying identifier is written as given, not composed.

    Tailscale owns the list of regions and local zones, so the module holds no
    list to check a composed one against and passes the value through.
    """
    with preserved("policy"):
        path = _policy_file(tmp_path, declared_document(device_address))
        options = {
            **credentials,
            "policy": path,
            "app_connectors": [
                {
                    "name": "ac-oracle",
                    "connectors": [CONNECTOR],
                    "preset_id": "oracle-oci-us-ashburn-1",
                }
            ],
        }

        _run(module_args, module_result, options)

        assert connectors_of(api.call("policy_get", "GET").body) == [
            {
                "name": "ac-oracle",
                "connectors": [CONNECTOR],
                "presetAppID": "oracle-oci-us-ashburn-1",
            }
        ]


def test_a_connector_whose_tag_is_unowned_is_refused_before_any_request(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
    device_address: str,
) -> None:
    """A tag the document does not grant is a write the server refuses.

    Measured: the server answers `connector (tag) must be a tag` and applies
    nothing, so the module answers first and names the tag to add.
    """
    with preserved("policy"):
        before = api.call("policy_get", "GET").body
        path = _policy_file(tmp_path, declared_document(device_address))

        result = _expect_failure(
            module_args,
            module_result,
            {
                **credentials,
                "policy": path,
                "app_connectors": [one_connector(connectors=["tag:ac-unowned"])],
            },
        )

        assert "tag:ac-unowned" in result["msg"]
        assert "must be a tag" in result["msg"]
        assert "tagOwners" in result["msg"], (
            "and names the section to fix, which the server's own message does not"
        )
        assert api.call("policy_get", "GET").body == before, "nothing was written"


def test_a_connector_nothing_can_reach_is_reported_and_the_write_proceeds(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
    device_address: str,
) -> None:
    """The prerequisites the server tolerates, reported rather than refused.

    Measured: the server accepts a connector no rule can reach and one with no
    route approver, and the connector routes nothing. A warning is the honest
    level, because the document is what the task asked for.
    """
    with preserved("policy"):
        path = _policy_file(tmp_path, declared_document(device_address, reachable=False))

        result = _run(
            module_args,
            module_result,
            {**credentials, "policy": path, "app_connectors": [one_connector()]},
        )

        reported = messages_of(result)
        assert result["changed"] is True
        assert any("reachable by no access rule" in warning for warning in reported)
        assert connectors_of(api.call("policy_get", "GET").body), "and it was written"


def test_a_group_nobody_declared_is_named_before_the_server_refuses_the_write(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
    device_address: str,
) -> None:
    """The module's own finding arrives before the server's objection does.

    A group that no section declares is refused by the API with `group not
    found` unless it is synced from an identity provider, which a policy file
    cannot show, so the finding is a warning and the server still has the last
    word. Both say the same thing here, which is the point.
    """
    with preserved("policy"):
        document = {
            "acls": [
                {"action": "accept", "src": ["group:ac-absent"], "dst": [f"{device_address}:22"]}
            ]
        }
        path = _policy_file(tmp_path, json.dumps(document) + "\n")

        result = _expect_failure(module_args, module_result, {**credentials, "policy": path})

        assert any("group:ac-absent" in warning for warning in messages_of(result))
        assert "group not found" in result["msg"]


def test_a_test_the_task_declares_runs_and_its_verdict_is_reported(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
    device_address: str,
) -> None:
    """A test declared on the task is a real test, run before anything is written.

    The document denies everything, so the only thing the server can object to is
    the assertion the task made: it asks for a reachability the rules do not
    grant, and the verdict arrives in a 200 rather than a status.
    """
    with preserved("policy"):
        before = api.call("policy_get", "GET").body
        path = _policy_file(
            tmp_path, '{"acls": [], "tagOwners": {"tag:ac-connector": ["autogroup:admin"]}}\n'
        )

        result = _expect_failure(
            module_args,
            module_result,
            {
                **credentials,
                "policy": path,
                "tests": [{"src": device_address, "accept": [f"{device_address}:22"]}],
            },
        )

        assert "failed its own tests" in result["msg"]
        assert "Traceback" not in result["msg"]
        assert api.call("policy_get", "GET").body == before, "so nothing was written"


def test_check_mode_writes_nothing_for_a_declared_document(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    tmp_path: Path,
    device_address: str,
) -> None:
    """A declared section is composed in check mode too, and written in neither."""
    with preserved("policy"):
        before = api.call("policy_get", "GET").body
        path = _policy_file(tmp_path, declared_document(device_address))

        result = _run(
            module_args,
            module_result,
            {
                **credentials,
                "policy": path,
                "groups": {"group:ac-probe": ["alpha@example.com"]},
                "app_connectors": [one_connector()],
            },
            check_mode=True,
        )

        assert result["changed"] is True
        assert result["diff"]["after"]["groups"] == {"group:ac-probe": ["alpha@example.com"]}
        assert connectors_of(result["diff"]["after"]), "and the connector it would write"
        assert api.call("policy_get", "GET").body == before
