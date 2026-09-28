# SPDX-License-Identifier: BSD-2-Clause
"""Typed API failures, each carrying the one action an operator can take next.

This module is internal to ``abn.tailscale``. The underscore on the package path
is the declaration: the kernel may be refactored in any release without a major
version bump.

A tailnet API is opaque when it fails. The whole error contract is a JSON object
with a single ``message`` field, and Tailscale answers a missing, a malformed and
an expired credential identically, so the actionable part lives in prose. That is
what this module composes: each documented failure becomes the one thing to do
next, and every message carries ``x-tailscale-request-id``, which is the only
handle Tailscale support has.

Nothing here is allowed to widen a leak. An exception carries the status, the
request line and a pre-sanitised message. It never carries a request header, the
token, or the response body: only the upstream ``message`` string is read, and it
is scrubbed of credential-shaped text, stripped of newlines and length-capped
before it is embedded. A message that reaches a log is permanent, and ``no_log``
scrubbing is the caller's responsibility, so nothing sensitive is put in the
message for that scrubbing to have to catch.

A caller turns any of these into an Ansible failure with a single handler:

    try:
        client.get("policy_get")
    except TailscaleError as exc:
        module.fail_json(msg=str(exc))
"""

from __future__ import annotations

import re
from collections.abc import Callable
from collections.abc import Mapping

from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import normalise_path
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import resolve
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import (
    scope_dependencies,
)

# Tailscale puts this on every response, error responses included, in the form
# REQ-<YYYYMMDDHHMMSSmmm><hex>. Lookup has to be case-insensitive because the Go
# client canonicalises response header names, so a case-sensitive read is a bug
# waiting for a header the server spells differently.
REQUEST_ID_HEADER = "x-tailscale-request-id"

# Over-redaction is the safe direction. The token pattern also eats a bare mention
# of the `tskey-` prefix in prose, which costs the operator nothing; failing to
# catch a token would put a working credential in a log line forever. The
# authorization pattern consumes the scheme word as well as the value, because the
# value is what follows it: stopping at the scheme would leave the credential
# itself in the log under a `Basic` or `Bearer` label. Quotes are allowed on
# either side of the colon because an API that echoes a request back does so in
# JSON, and a pattern written for the bare header form stops at the quote and
# leaves the credential behind it.
_CREDENTIAL_PATTERNS = (
    re.compile(r"tskey-[A-Za-z0-9._~+/=-]{6,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(
        r"(?i)\b(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?(?:bearer|basic|token)?\s*\S+"
    ),
)
_REDACTED = "[redacted]"

#: A request that never reached a status has no status, and 0 cannot be one.
NO_STATUS = 0

# A long or hostile message must not become an unbounded log line, and embedded
# newlines would let an upstream message forge extra lines in a transcript. The
# budget covers the rendered quote rather than the raw text, so the marker below
# lands at the end of the message instead of behind a closing quote.
_MAX_UPSTREAM_CHARS = 400
_TRUNCATION = " (truncated)"

# Matched against the upstream `message` field rather than the status alone,
# because the status carries no instruction and the message is the only place the
# API states one. The bracketed list is optional because it names a tag rather
# than the failure: the phrase is the signature, and the list rides along as
# detail when the API bothers to send it.
_REQUESTED_TAGS_RE = re.compile(r"requested tags(?: (\[.*?\]))? are invalid or not permitted")
_UNTAGGING_SIGNATURE = "tagged nodes cannot be untagged without reauth"
_NAME_TAKEN_RE = re.compile(r'name "([^"]*)" is already taken')
_CAPABILITY_SCOPE_SIGNATURE = "exactly one capability scope must be populated"
_MAGICDNS_SIGNATURE = "need at least one nameserver to enable MagicDNS"
# Tailscale answers a plan refusal with 402 on some endpoints, with 400 on others,
# and with 403 on the rest, where the status is indistinguishable from a scope the
# credential lacks. Measured against a free plan: every endpoint of the
# log-streaming family and the network flow log read answer "feature not
# available on current billing plan" with a 403, so the default 403 prose, which
# names a scope, would send the operator to re-mint a credential that is already
# correct. Matched against the upstream message rather than the status, because
# the status is the thing carrying no information.
_PLAN_PHRASES = (
    "not available on current billing plan",
    "current plan does not allow",
    "plan does not include",
)


class TailscaleError(Exception):
    """Base of every failure raised from a Tailscale Admin API call.

    ``message`` is the actionable prose on its own. ``str(exc)`` adds the request
    line and, when the API supplied one, the request id.
    """

    def __init__(
        self,
        message: str,
        status: int,
        method: str,
        path: str,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.method = method
        self.path = path
        self.request_id = request_id

    def __str__(self) -> str:
        lines = [self.message, f"  request: {self.method} {self.path}"]
        if self.request_id:
            lines.append(f"  tailscale request id: {self.request_id}")
        return "\n".join(lines)


class TailscaleUnreachable(TailscaleError):
    """The request never produced a status at all.

    A refused or reset connection, a name that does not resolve, a TLS handshake
    that did not complete, a timeout, or a body that stopped before it was
    complete. A distinct class because there is nothing to map: no upstream
    message, no request id, and no status to answer 429 with later. ``status`` is
    :data:`NO_STATUS`, so a caller can tell "did not arrive" from "arrived and was
    refused" without inspecting the type.
    """

    def __init__(self, message: str, method: str, path: str) -> None:
        super().__init__(message, status=NO_STATUS, method=method, path=path)


class TailscaleBadRequest(TailscaleError):
    """HTTP 400. The request itself is what the API refused."""


class TailscaleAuthError(TailscaleError):
    """HTTP 401. The API did not accept the credential."""


class TailscalePlanError(TailscaleError):
    """HTTP 402. The tailnet's plan or billing state forbids the operation."""


class TailscalePermissionError(TailscaleError):
    """HTTP 403. The credential is valid but not authorised for the operation."""


class TailscaleNotFound(TailscaleError):
    """HTTP 404. The resource was not found."""


class TailscalePreconditionFailed(TailscaleError):
    """HTTP 412. The policy file changed since this run read it."""


class TailscaleRateLimited(TailscaleError):
    """HTTP 429. The API is refusing requests for rate."""


class TailscaleNotImplemented(TailscaleError):
    """HTTP 501. The API does not implement the operation."""


class TailscaleServerError(TailscaleError):
    """A 5xx other than 501. The API failed to serve the request."""


class TailscaleApiError(TailscaleError):
    """A status this collection maps to no specific remedy."""


def _clean(text: str) -> str:
    """Collapse whitespace and strip credential-shaped text from outside prose.

    Applied to everything that came from outside, the request path included,
    because a leak here outlives the run and the caller's own scrubbing.
    """
    collapsed = " ".join(text.split())
    for pattern in _CREDENTIAL_PATTERNS:
        collapsed = pattern.sub(_REDACTED, collapsed)
    return collapsed


def _sanitise(text: str) -> str:
    """The bounded form of `_clean`, for text rendered without its own framing.

    A request path and a request id are appended to a message rather than quoted
    into it, so the marker cannot be pushed off the end and the cut is marked
    where it happened.
    """
    collapsed = _clean(text)
    if len(collapsed) > _MAX_UPSTREAM_CHARS:
        collapsed = collapsed[:_MAX_UPSTREAM_CHARS] + _TRUNCATION
    return collapsed


def redact(text: str) -> str:
    """Text from outside this collection, credential-stripped and length-capped.

    Public because another kernel file has to render upstream prose exactly this
    way. A second copy of the credential patterns is how one of the two would
    eventually stop matching something.
    """
    return _sanitise(text)


def _quoted(upstream: str) -> str:
    """Render upstream prose for inclusion, or say plainly that there was none."""
    cleaned = _clean(upstream)
    if not cleaned:
        return "The API returned no message."
    opening = 'The API said: "'
    budget = _MAX_UPSTREAM_CHARS - len(opening) - 1
    if len(cleaned) > budget:
        return opening + cleaned[:budget] + _TRUNCATION
    return opening + cleaned + '".'


def _unauthenticated(
    status: int, method: str, path: str, upstream: str, request_id: str | None
) -> str:
    # The advice below assumes the canonical wording. Quoting what the API
    # actually returned is what lets the operator see when that assumption does
    # not hold, and it is the only place the redaction of a credential echoed
    # back to us becomes visible.
    return " ".join(
        [
            "The Tailscale API rejected the request because it did not accept the credential. "
            "Tailscale answers a missing, a malformed and an expired credential identically, "
            'with "API token invalid", so the message the API returned cannot tell them apart. '
            "Check all three: the credential reached the request, it is spelled correctly, and it "
            "has not expired.",
            _quoted(upstream),
        ]
    )


def _unauthorised(
    status: int, method: str, path: str, upstream: str, request_id: str | None
) -> str:
    if _refused_by_plan(upstream):
        # Not a fallback for an unmapped status. A 403 whose body names the
        # billing plan is a plan refusal wearing a permissions status, and
        # answering it with scope advice tells the operator to change the one
        # thing that is already correct.
        return _plan_forbidden(status, method, path, upstream, request_id)

    operation = resolve(method, path)
    scope = operation.scopes[0] if operation is not None else None

    # The API's own reason comes first when it gave one, because a 403 does not
    # always mean a missing scope. The scope recorded for an operation is where a
    # credential's permissions usually fall short, not the only way a 403 arrives:
    # "actor cannot set scopes: [all]" came from a credential holding every
    # permission in the tailnet, and a message asserting that it needed
    # `auth_keys` sent the reader after a permission problem that did not exist.
    said = upstream if _clean(upstream) else ""
    lines = ["The Tailscale API refused the request: the credential is not authorised for it."]
    if said:
        lines.append(f"The API's reason: {_quoted(upstream)}")
    if scope is None:
        lines.append(
            "The request line does not correspond to an operation this collection's table "
            "knows, so the scope it needs cannot be named from here."
        )
    elif not said:
        # Only inferable when the API said nothing, and then only as a starting
        # point rather than as its reason.
        lines.append(f"It most likely needs the `{scope}` scope.")
    lines.append(
        "A token's scopes are fixed when it is issued, so granting a scope does not rescue an "
        "existing token: mint a new one from the OAuth client or trust credential, or, for a "
        "user-owned API access token, raise the owning user's role in the admin console, "
        "because such a token carries its owner's permissions."
    )
    if operation is not None and scope is not None:
        # `scope` is derived from `operation`, so the first test implies the
        # second, but nothing in the code said so and nothing checked it.
        dependencies = scope_dependencies(scope)
        if dependencies:
            listed = ", ".join(f"`{name}`" for name in dependencies)
            lines.append(
                f"`{scope}` additionally requires {listed}, which is the most common reason a "
                "credential that looks correctly scoped is still refused."
            )
        if len(operation.scopes) > 1:
            others = ", ".join(f"`{name}`" for name in operation.scopes[1:])
            lines.append(f"This operation is also gated on {others} for the parts they cover.")
    return " ".join(lines)


def _refused_by_plan(upstream: str) -> bool:
    """Whether the API's own words name the billing plan rather than a permission.

    Read from the message because the status cannot carry it: a plan refusal and
    an insufficient scope are both a 403 on the endpoints measured, and the two
    need opposite advice.
    """
    lowered = upstream.lower()
    return any(phrase in lowered for phrase in _PLAN_PHRASES)


def _plan_forbidden(
    status: int, method: str, path: str, upstream: str, request_id: str | None
) -> str:
    return " ".join(
        [
            "The Tailscale API refused the request because the tailnet's plan or billing state "
            "does not allow the operation.",
            "Resolving it takes a billing change, not a different request.",
            _quoted(upstream),
        ]
    )


def _concurrent_policy_edit(
    status: int, method: str, path: str, upstream: str, request_id: str | None
) -> str:
    return " ".join(
        [
            "The Tailscale API rejected the write because the policy file changed after this "
            "run read it: the If-Match hash no longer matched.",
            "Something else edited the policy between the read and the write, so nothing was "
            "applied. Re-run to reconcile against the new file.",
        ]
    )


def _rate_limited(
    status: int, method: str, path: str, upstream: str, request_id: str | None
) -> str:
    return " ".join(
        [
            "The Tailscale API rate limited the request.",
            "Tailscale publishes no rate limits and documents no backoff interval, so there is "
            "nothing to compute from the response: wait, then re-run.",
        ]
    )


def _not_implemented(
    status: int, method: str, path: str, upstream: str, request_id: str | None
) -> str:
    operation = resolve(method, path)
    if operation is not None and operation.name == "device_delete":
        return " ".join(
            [
                "The Tailscale API does not implement this operation: deleting a device is not "
                "supported for a device that was shared into this tailnet from another one.",
                "A shared device belongs to the tailnet it came from, so remove it there.",
            ]
        )
    return " ".join(
        [
            "The Tailscale API reports that it does not implement this operation.",
            "That is a statement about the server rather than about the request, so no change "
            "to the playbook can affect it.",
            _escalate(request_id),
        ]
    )


def _tag_not_owned(tags: str | None) -> str:
    # The bracketed list is detail: the signature is the phrase, and an operator
    # who has just been told to fix `tagOwners` does not need it restated.
    if tags:
        refused = f"{tags} is not a tag this tailnet may assign"
    else:
        refused = "the tags it named are not tags this tailnet may assign"
    return " ".join(
        [
            f"The Tailscale API rejected the tag assignment: {refused}.",
            "A tag exists only where the policy file's `tagOwners` grants it, and a tag with "
            "no owner cannot be applied to a device.",
            "Add the tag to `tagOwners` in the policy this collection manages, then re-run.",
        ]
    )


def _untagging_refused(
    status: int, method: str, path: str, upstream: str, request_id: str | None
) -> str:
    return " ".join(
        [
            "The Tailscale API refused to take the last tag off a device: a tagged device",
            "cannot be untagged without re-authenticating, because the tag is its owner and",
            "a device with no owner has no identity in the policy.",
            "Add the tags the device should have rather than removing the one it has, or",
            "have the device re-authenticate from the Tailscale app or the login screen,",
            "which is what makes the tag go. Setting the same tags the device already",
            "carries is not this failure.",
        ]
    )


def _name_taken(status: int, method: str, path: str, upstream: str, request_id: str | None) -> str:
    taken = _NAME_TAKEN_RE.search(upstream)
    return " ".join(
        [
            f"The Tailscale API refused the rename because the name {taken.group(1) if taken else 'it named'}"
            " is already taken in this tailnet.",
            "Device names are unique across a tailnet, and a name is held for a while after",
            "the device that had it is gone, so a name that looks free in the machines page",
            "can still be refused here. Pick a different name, or wait for the name to be",
            "released.",
        ]
    )


def _escalate(request_id: str | None) -> str:
    """The support advice, which is only actionable once an id exists.

    Printing it for a response that carried no id would send an operator looking
    for a handle the failure does not have.
    """
    if not request_id:
        return "If the operation is documented as available, this is a defect in the API."
    return (
        "If the operation is documented as available, quote the request id above to Tailscale "
        "support."
    )


def _malformed_capability_body(
    status: int, method: str, path: str, upstream: str, request_id: str | None
) -> str:
    return " ".join(
        [
            'The Tailscale API replied "exactly one capability scope must be populated".',
            "That wording names a permissions problem but is almost always a malformed request "
            "body: Tailscale emitted it when content-type handling broke and the server could "
            "not parse what was sent.",
            "Send HuJSON as `application/hujson` and JSON as `application/json`. HuJSON "
            "labelled as JSON fails on the first comment and surfaces here.",
        ]
    )


def _magic_dns_without_resolver(
    status: int, method: str, path: str, upstream: str, request_id: str | None
) -> str:
    return " ".join(
        [
            "The Tailscale API refused the DNS configuration: MagicDNS is enabled while the "
            "nameserver list is empty.",
            "MagicDNS resolves names through a resolver, so at least one entry in `nameservers` "
            "has to be present. Add one, or turn MagicDNS off.",
        ]
    )


def _bad_request(status: int, method: str, path: str, upstream: str, request_id: str | None) -> str:
    tags = _REQUESTED_TAGS_RE.search(upstream)
    if tags is not None:
        # Every other path that embeds upstream prose cleans it first. This one
        # did not, so a token echoed inside a tag list survived into the message,
        # and a long list ran past the length budget.
        return _tag_not_owned(_sanitise(tags.group(1)) if tags.group(1) else None)

    if _UNTAGGING_SIGNATURE in upstream:
        return _untagging_refused(status, method, path, upstream, request_id)

    if _NAME_TAKEN_RE.search(upstream):
        # The name is quoted back from the message, and it came from a task rather
        # than from the tailnet, so it is scrubbed and capped on its own account
        # rather than relying on the caller's `redact`.
        return _name_taken(status, method, path, _sanitise(upstream), request_id)

    if _CAPABILITY_SCOPE_SIGNATURE in upstream:
        return _malformed_capability_body(status, method, path, upstream, request_id)
    if _MAGICDNS_SIGNATURE in upstream:
        return _magic_dns_without_resolver(status, method, path, upstream, request_id)

    return " ".join(
        [
            "The Tailscale API rejected the request as malformed, and this collection has no "
            "specific remedy for the message it returned.",
            _quoted(upstream),
        ]
    )


def _not_found(status: int, method: str, path: str, upstream: str, request_id: str | None) -> str:
    return " ".join(
        [
            "The Tailscale API could not find the resource this request named.",
            "The response does not distinguish the three ordinary causes: it does not exist, it "
            "exists in a different tailnet than the one addressed, or it is an ephemeral "
            "device that deleted itself on disconnect, which is a normal race rather than an "
            "error when it happens partway through a run.",
        ]
    )


def _server_error(
    status: int, method: str, path: str, upstream: str, request_id: str | None
) -> str:
    if request_id:
        escalate = "Re-run, and quote the request id above to Tailscale support if it persists."
    else:
        escalate = "Re-run."
    return " ".join(
        [
            "The Tailscale API failed to serve the request.",
            "This is a server-side failure, so the request is not its cause and no change to the "
            f"playbook will fix it. {escalate}",
        ]
    )


def _unmapped(status: int, method: str, path: str, upstream: str, request_id: str | None) -> str:
    return " ".join(
        [
            f"The Tailscale API returned HTTP {status}, which this collection maps to no "
            "specific remedy.",
            _quoted(upstream),
        ]
    )


# One uniform signature across the builders, so the dispatch tables are plain
# lookups. A builder takes the status and the request id even when it uses
# neither, because the alternative is a dispatch that special-cases the few that
# do, and a builder is a function of everything known about the response.
# pylint infers that the elements of a Callable subscript are not types and reports
# unsupported operand for |. This is a module-level alias, so the union is evaluated
# at import, where it works on the Python this collection targets.
Builder = Callable[[int, str, str, str, str | None], str]  # pylint: disable=unsupported-binary-operation

_MESSAGE_BUILDERS: dict[int, Builder] = {
    400: _bad_request,
    401: _unauthenticated,
    402: _plan_forbidden,
    403: _unauthorised,
    404: _not_found,
    412: _concurrent_policy_edit,
    429: _rate_limited,
    501: _not_implemented,
}

_ERROR_TYPES: dict[int, type[TailscaleError]] = {
    400: TailscaleBadRequest,
    401: TailscaleAuthError,
    402: TailscalePlanError,
    403: TailscalePermissionError,
    404: TailscaleNotFound,
    412: TailscalePreconditionFailed,
    429: TailscaleRateLimited,
    501: TailscaleNotImplemented,
}


def _request_id_of(response_headers: Mapping[str, str] | None) -> str | None:
    if not response_headers:
        return None
    for name, value in response_headers.items():
        if str(name).lower() == REQUEST_ID_HEADER:
            return _sanitise(str(value)) or None
    return None


def unreachable(method: str, path: str, reason: BaseException) -> TailscaleUnreachable:
    """Build the failure for a request that never reached a status.

    ``reason`` names the socket-level problem, which is the only useful thing the
    operator can be told. It is cleaned like every other piece of text from
    outside, because a URL can carry a query string the caller should not have put
    there and it would outlive the run.

    What it says about the tailnet depends on the verb, and it must. A read that
    never arrived read nothing, which is safe to state. A write that never
    answered may already have been applied, and telling the operator nothing
    changed is the one claim this collection cannot make. For a policy write it
    is the dangerous direction: the operator would conclude the old policy is
    still live when it is not.
    """
    verb = str(method).upper()
    clean_path = _sanitise(normalise_path(path))
    if verb in ("GET", "HEAD"):
        consequence = (
            "  This is a connection, name resolution or TLS problem rather than a "
            "refusal, so nothing was read and nothing was changed."
        )
    else:
        consequence = (
            "  This is a connection, name resolution or TLS problem rather than a "
            "refusal. The request may have been applied before the answer was lost, "
            "so re-read the tailnet before assuming the previous state still holds."
        )
    return TailscaleUnreachable(
        " ".join(
            [
                "The request did not complete, so no answer arrived from the Tailscale API:",
                _quoted(_clean(str(reason))),
                consequence,
            ]
        ),
        verb,
        clean_path,
    )


def from_response(
    status: int,
    method: str,
    path: str,
    upstream_message: str | None = None,
    response_headers: Mapping[str, str] | None = None,
) -> TailscaleError:
    """Build the failure for one API response, ready to be raised.

    ``response_headers`` is read for the request id and nothing else. It is never
    retained, because an exception holding a header mapping would put the
    credential into every transcript that ever printed the failure.

    ``upstream_message`` is the body's ``message`` field, not the body. The rest
    of the body is never read: the richer ``data`` shape belongs to a 200
    response from the policy validator, and passing it here would carry user
    addresses into a log.
    """
    verb = str(method).upper()
    clean_path = _sanitise(normalise_path(path))
    prose = upstream_message or ""
    request_id = _request_id_of(response_headers)

    builder = _MESSAGE_BUILDERS.get(status)
    if builder is None:
        builder = _server_error if 500 <= status <= 599 else _unmapped

    error_type = _ERROR_TYPES.get(status)
    if error_type is None:
        error_type = TailscaleServerError if 500 <= status <= 599 else TailscaleApiError

    message = builder(status, verb, clean_path, prose, request_id)
    return error_type(message, status, verb, clean_path, request_id)
