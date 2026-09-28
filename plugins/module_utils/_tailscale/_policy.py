# SPDX-License-Identifier: BSD-2-Clause
"""Reading, comparing and writing a tailnet policy file.

Internal to this collection. The path carries a leading underscore, which
declares the kernel private: it can be refactored in any release without a major
version bump. See ``.agents/rules/ansible.md``.

This is the highest-blast-radius code in the collection. A policy file that is
written wrongly locks the operators out of their own tailnet, and unlike every
other resource here there is no partial success: the document is replaced whole.
Three properties follow from that, and each is enforced in this file rather than
left to the module that calls it.

**A write is always guarded, and an absent guard aborts it.** The policy is the
only resource with a concurrency surface, because two operators editing one
tailnet is ordinary rather than exceptional. Every write carries the ``ETag`` the
read returned, and when the read produced no ``ETag`` the write does not happen at
all. An unguarded write here would silently discard whatever the other operator
did in between, which is the failure that turns a race into an outage.

**The server runs the document's own tests before anything is replaced.**
``policy_validate`` executes the ``tests`` the document declares, and it
answers a failure with a 200 whose body carries the verdict, so the body is read
rather than the status. The same 200 also carries warnings, and a warning is not
a failure: warnings are surfaced and the write proceeds. What it does *not* do is
decide whether the ACLs would lock the operators out: it runs the tests you
wrote, not an independent judgement about reachability. A document that grants no
access to the operator applying it passes validation if its own tests pass, and
the write is what refuses it. Check mode does not call it, because check mode
makes exactly one request and that one is a read.

**A document that opens the tailnet is refused without an explicit opt-in.** A
policy with neither ``acls`` nor ``grants`` is allow-all to Tailscale, and an
absent key is an easy thing to write by accident: an empty file, a truncated
document, a templating accident. An empty ``acls`` or ``grants`` list is deny-all
and is the safe direction, so only the absent case is guarded. Measured, not
assumed: see :func:`opens_tailnet`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from typing import NamedTuple
from typing import Protocol

from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import NO_ETAG
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Response
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import diff
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import loads
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import render
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscalePreconditionFailed,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import redact

__all__ = [
    "Current",
    "Outcome",
    "PolicyClient",
    "PolicyError",
    "check_widening",
    "opens_tailnet",
    "read",
    "reconcile",
    "validate",
    "write",
]

#: Keys whose presence means the operator has said something about access. With
#: neither present, Tailscale's default applies and that default is allow-all.
_ACCESS_KEYS = ("acls", "grants")


class PolicyClient(Protocol):
    """The part of the client this file uses.

    Narrower than :class:`._api.Api` on purpose. Depending on the whole client
    would mean a test double had to reimplement all of it to stand in for a single
    method, which is a second implementation to keep in step with the first.

    Only the keywords used here are declared. A protocol asking for ``**kwargs``
    would demand arbitrary keyword acceptance, which a client with a fixed
    signature does not provide, and a client with more optional keywords than this
    does satisfy it.
    """

    def call(
        self,
        name: str,
        method: str,
        *,
        body: Any = None,
        headers: Mapping[str, str] | None = None,
        expect_etag: bool = False,
    ) -> Response: ...


class PolicyError(Exception):
    """A write was refused before it was attempted.

    Not a :class:`._errors.TailscaleError`, because nothing was sent. These are
    the collection's own decisions about a document, and a caller that catches
    both needs to tell them apart: one is fixable by editing a playbook, the
    other by waiting or by asking the operator to intervene.
    """


class Current(NamedTuple):
    """What the tailnet holds, and the fingerprint that guards writing it."""

    policy: Any
    etag: str


class Outcome(NamedTuple):
    """What a reconciliation decided, for the module to report.

    ``before`` and ``after`` are the two whole documents, which is what Ansible
    renders a diff from. They are carried rather than recomputed by the module
    because the module never sees either one otherwise: it passes a file in and
    receives a verdict back, and the current policy is read inside this function.
    """

    changed: bool
    differences: list[dict[str, Any]]
    etag: str
    before: Any
    after: Any
    warnings: list[str]


def opens_tailnet(document: Any) -> bool:
    """Whether writing this document would leave the tailnet open to everyone.

    A document that is not an object is treated as opening it, because the only
    way to arrive at one is a mistake and the safe reading of a mistake is the
    cautious one.

    Measured against the real API, by ``test_the_server_treats_an_empty_access_list_as_deny_all``,
    which asks the server's own evaluator rather than reading a stored document:
    a wide-open ACL allows, ``{"acls": []}`` denies, ``{"grants": []}`` denies, and
    ``{}`` allows. The absent case is therefore the only one that opens the
    tailnet, and it is the only one this refuses.

    The measurement needed a real subject, because the evaluator rejects a host it
    cannot resolve and a tailnet with no devices therefore cannot answer. The
    stored document cannot answer it either: the server accepts all four verbatim
    and normalises none, so they come back looking equally rule-free.

    The value has to be a list rather than the key merely being present. A
    ``null`` where a list belongs is a nil slice on the server, which is what an
    absent key is, and the same allow-all. A templating accident that renders an
    empty variable into ``acls`` therefore produces ``{"acls": null}``, which
    opens the tailnet, and reading the key's presence alone would let it through
    the one guard that exists to stop that.
    """
    if not isinstance(document, dict):
        return True
    return not any(isinstance(document.get(key), list) for key in _ACCESS_KEYS)


def check_widening(document: Any, *, allow_all_traffic: bool) -> None:
    """Refuse a document that opens the tailnet, unless the operator opted in.

    The opt-in is a separate flag rather than an inference from the document,
    because a document that is allow-all is indistinguishable from a document
    whose access rules were lost.
    """
    if opens_tailnet(document) and not allow_all_traffic:
        raise PolicyError(
            "This policy has neither an 'acls' nor a 'grants' key, which Tailscale "
            "reads as allowing every device in the tailnet to reach every other. An "
            "empty 'acls' list denies everything instead, and is almost always what "
            "is meant. Set allow_all_traffic on the task if opening the tailnet is "
            "genuinely the intent."
        )


def read(api: PolicyClient) -> Current:
    """Read the policy and the fingerprint that guards writing it."""
    response = api.call("policy_get", "GET", expect_etag=True)
    return Current(policy=_document(response.body), etag=response.etag)


#: Enough findings to act on without pasting a whole document into a message.
MAX_REPORTED = 5

#: One finding is a short clause. A single entry is capped as well as the list,
#: because `redact` bounds a whole string and a list of them is not bounded.
MAX_FINDING_CHARS = 300


def validate(api: PolicyClient, document: Any) -> list[str]:
    """Run the document against the server's own ACL tests.

    A failed validation answers **200**, with a ``data`` array naming the tests
    that failed, so a refusal here is not a status and the body has to be read. An
    earlier version ignored it, which meant the validate call proved nothing and a
    policy whose own tests failed was only caught by the write refusing it.

    A ``data`` entry is not by itself a failure. The vendored description gives
    three named 200 responses: tests failed, carrying ``errors`` per entry;
    warnings found, carrying ``warnings`` per entry; and success, an empty body.
    Refusing on the presence of an entry would turn every SCIM warning into a
    refusal of a perfectly valid policy, and would name the wrong cause. The
    discriminator is ``errors``.

    Returns the warnings, which are the server's own and are actionable, so the
    caller can surface them rather than discard them. Raises on errors.
    """
    rendered = render(document)
    response = api.call(
        "policy_validate",
        "POST",
        body=rendered.body,
        headers={"Content-Type": rendered.content_type},
    )
    findings = _findings_in(response.body)
    failures = [entry for entry in findings if _reasons_of(entry, "errors")]
    if failures:
        raise PolicyError(
            _findings_message("failed its own tests, so it was not written", findings, "errors")
        )
    warned = [entry for entry in findings if _reasons_of(entry, "warnings")]
    if not warned:
        return []
    return [
        _findings_message("was accepted, with a warning the server reported", warned, "warnings")
    ]


def _findings_in(body: Any) -> list[dict[str, Any]]:
    """The entries the endpoint reported, whichever kind they are."""
    if not isinstance(body, dict):
        return []
    data = body.get("data")
    if not isinstance(data, list):
        return []
    return [entry for entry in data if isinstance(entry, dict)]


def _reasons_of(entry: dict[str, Any], key: str) -> list[str]:
    reasons = entry.get(key)
    if not isinstance(reasons, list) or not reasons:
        return []
    return [str(reason) for reason in reasons]


def _who_of(entry: dict[str, Any]) -> str:
    return redact(str(entry.get("user") or entry.get("src") or "a test"))


def _findings_message(verdict: str, findings: list[dict[str, Any]], key: str) -> str:
    lines = [f"The policy {verdict}. Each line is one entry the server reported:"]
    for entry in findings[:MAX_REPORTED]:
        detail = "; ".join(_reasons_of(entry, key)) or "no reason given"
        # `who` comes from the document's own rules, so it is scrubbed and capped
        # on its own account rather than relying on the caller's `redact`.
        lines.append(
            f"  {_who_of(entry)[:MAX_FINDING_CHARS]}: {redact(detail)[:MAX_FINDING_CHARS]}"
        )
    remaining = len(findings) - MAX_REPORTED
    if remaining > 0:
        lines.append(f"  and {remaining} more")
    return "\n".join(lines)


def write(api: PolicyClient, document: Any, etag: str) -> None:
    """Replace the policy, guarded by the fingerprint the read returned."""
    if not etag or etag == NO_ETAG:
        raise PolicyError(
            "Refusing to write the policy unguarded. The read returned no ETag, so "
            "there is no way to tell whether the file changed in between, and writing "
            "without one would silently discard whatever another operator did. This "
            "is the API declining to offer concurrency control, not a transient "
            "failure, so a retry will not help."
        )
    rendered = render(document)
    api.call(
        "policy_set",
        "POST",
        body=rendered.body,
        headers={"Content-Type": rendered.content_type, "If-Match": etag},
    )


#: Reads and writes one reconciliation makes before it declares the document
#: contended. Three covers a hand edit landing once, and stops far short of a
#: loop that would hide a writer which never stops.
MAX_ATTEMPTS = 3


def _contended(refusal: TailscalePreconditionFailed) -> TailscalePreconditionFailed:
    """The failure for a document that changed under every attempt."""
    return TailscalePreconditionFailed(
        f"The policy file changed after this run read it on each of the {MAX_ATTEMPTS} "
        "attempts, so the document is contended: another writer keeps editing it. "
        "Nothing from this run was applied. Re-run once the other writer is quiet.",
        refusal.status,
        refusal.method,
        refusal.path,
        refusal.request_id,
    )


def reconcile(
    api: PolicyClient,
    desired: Any,
    *,
    allow_all_traffic: bool = False,
    check_mode: bool = False,
) -> Outcome:
    """Bring the tailnet's policy to `desired`, writing only when it differs.

    The order is the safety property: refuse an opening document before reading,
    read, compare, and only then validate and write. A second run over unchanged
    input returns ``changed=False`` without any request beyond the read, which is
    the whole point of canonicalising before comparing.

    A write the API refuses with a 412 did not happen, so the read behind it is
    stale rather than the write being wrong. The document is read again, the diff
    is recomputed against what it now holds, and the write is attempted again, up
    to :data:`MAX_ATTEMPTS` times. Every attempt compares and writes against the
    document it has just read, so the diff it reports and the write it makes are
    about the tailnet as it is, and a run never writes a document computed from a
    read another writer has since replaced. When every attempt loses the race the
    task fails and says the document is contended.

    The declared document stays authoritative across the retry. A section another
    writer adds while this run is in flight is not carried forward: this reconciles
    the whole document, so a section the file does not declare is removed on the
    next run whether or not a race happened, and keeping it for one run would leave
    the tailnet holding something the file cannot explain.
    """
    check_widening(desired, allow_all_traffic=allow_all_traffic)
    attempt = 0
    while True:
        attempt += 1
        current = read(api)
        differences = diff(desired, current.policy)
        if not differences:
            return Outcome(
                changed=False,
                differences=[],
                etag=current.etag,
                before=current.policy,
                after=current.policy,
                warnings=[],
            )
        if check_mode:
            return Outcome(
                changed=True,
                differences=differences,
                etag=current.etag,
                before=current.policy,
                after=desired,
                warnings=[],
            )
        reported = validate(api, desired)
        try:
            write(api, desired, current.etag)
        except TailscalePreconditionFailed as refusal:
            if attempt >= MAX_ATTEMPTS:
                raise _contended(refusal) from refusal
            continue
        return Outcome(
            changed=True,
            differences=differences,
            etag=current.etag,
            before=current.policy,
            after=desired,
            warnings=reported,
        )


def _document(body: Any) -> Any:
    """The policy as structures, whether the API sent JSON or HuJSON.

    Strict JSON arrives already parsed, because that is what the transport does
    with a body it can parse. HuJSON with comments cannot be, and comes back as
    the text it always was.
    """
    if isinstance(body, (dict, list)):
        return body
    return loads(body)
