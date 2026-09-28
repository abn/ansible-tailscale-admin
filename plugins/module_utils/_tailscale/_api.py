# SPDX-License-Identifier: BSD-2-Clause
"""The HTTP client for the Tailscale Admin API.

Internal to this collection. The path carries a leading underscore, which
declares the kernel private: it can be refactored in any release without a major
version bump. See ``.agents/rules/ansible.md``.

What this file is for
---------------------
* Build a request URL from an operation name, so no call site assembles a path.
* Attach the bearer, and nothing else, from :mod:`._auth`.
* Read the ``ETag`` off a response and keep no header mapping, because an object
  holding headers would carry the credential into every transcript that printed
  it.
* Turn a failure status into the right exception, through :mod:`._errors`.
* Spend a small, explicit budget on rate limiting.

Two rules here are policy rather than transcription, and both are deliberate.

**Only ``GET`` and ``HEAD`` are ever retried.** Every other verb surfaces its
failure instead. A retried write is the one thing that cannot be taken back: the
API may have applied the change and still answered with a 5xx or a dropped
connection, so a silent second attempt turns a visible failure into a divergence
between what the operator asked for and what the tailnet holds. Reading twice
costs nothing and changes nothing, so reads get the retry and writes do not.
``PUT`` and ``DELETE`` are idempotent in the HTTP sense, which is not the
question. The question is whether the collection can tell "did not happen" from
"happened, and the answer was lost", and for a write it cannot.

**The rate-limit budget is one retry.** A run should not sit in a retry loop
against a tailnet somebody is administering at the same time. One retry after the
server's own ``Retry-After`` covers the common case, which is a burst caused by a
concurrent run, and gives up on the rest, which is a tailnet under real pressure
that the operator needs to see rather than have hidden.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from http.client import HTTPException
from typing import Any
from typing import NamedTuple
from urllib.error import HTTPError
from urllib.parse import urlencode

from ansible.module_utils.urls import open_url
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import Authoriser
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import from_response
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import unreachable
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import OPERATIONS
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import Operation
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import build_path
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import (
    is_tailnet_scoped,
)

__all__ = [
    "NO_ETAG",
    "RATE_LIMIT_RETRIES",
    "RETRYABLE_METHODS",
    "Api",
    "ApiOptions",
    "RawResponse",
    "Response",
    "Transport",
    "post_form",
]

#: The only verbs a rate-limited request is repeated for. See the module docstring.
RETRYABLE_METHODS = frozenset({"GET", "HEAD"})

#: How many times a rate-limited request is repeated. One, on purpose.
RATE_LIMIT_RETRIES = 1

#: Used when a 429 arrives with no Retry-After the collection can act on.
DEFAULT_RETRY_AFTER_SECONDS = 1.0

#: A ceiling on a server-supplied Retry-After, so a mistaken or hostile value
#: cannot park a module run for an hour.
MAX_RETRY_AFTER_SECONDS = 30.0

#: What a response without an ETag reports, so a caller that must guard a write
#: can tell the difference between "no fingerprint" and "empty fingerprint".
NO_ETAG = ""

#: Everything that means the request never produced a status. `URLError` is a
#: subclass of `OSError` and covers a refused connection, a name that does not
#: resolve and a refused TLS handshake. The rest arrive from the response side:
#: `OSError` covers a connection accepted and then reset, and a read timeout,
#: because `urllib` only wraps the request and leaves `getresponse()` and `read()`
#: to raise what they raise. `IncompleteRead` is not an `OSError` and needs
#: `HTTPException` alongside it.
TRANSPORT_ERRORS = (OSError, HTTPException)


class RawResponse(NamedTuple):
    """What a transport hands back. Lives for the length of one call."""

    status: int
    text: str
    headers: Mapping[str, str]


class Response(NamedTuple):
    """A successful reply, reduced to what a caller may keep.

    No headers. The ``ETag`` is lifted out on the way in because a guarded write
    needs it, and it is a content fingerprint rather than a credential.
    """

    status: int
    body: Any
    etag: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ApiOptions:
    """Connection settings shared by every request.

    Keyword-only because it carries three defaults over two required fields, and
    positionally `ApiOptions(base, tailnet, False)` reads as `ca_path` rather
    than as `validate_certs`. Every construction site names its arguments anyway.
    """

    base_url: str
    tailnet: str
    validate_certs: bool = True
    ca_path: str = ""
    timeout: int = 30


#: A transport, keyword-only so a test double is a plain function.
Transport = Callable[..., RawResponse]


def open_transport(
    method: str,
    url: str,
    data: Any,
    headers: Mapping[str, str],
    *,
    validate_certs: bool,
    ca_path: str,
    timeout: int,
) -> RawResponse:
    """Perform one request through ``ansible.module_utils.urls``.

    The rules forbid reaching for ``requests`` or ``urllib.request`` directly, and
    this indirection is where that compliance is visible rather than assumed.

    ``open_url`` answers a success with a single response object carrying
    ``status``, ``headers`` and ``read``, and raises ``HTTPError`` for a status it
    considers a failure. That asymmetry is why the error is caught and turned back
    into a response: the status mapping in :mod:`._errors` works from a status, and
    the body of a refusal carries the server's own reason for it.

    The read is inside the ``try`` on purpose. ``urllib`` only wraps the request
    itself, so a connection reset after it was accepted, a body truncated
    mid-read, and a timeout all arrive as ``OSError`` or ``http.client.HTTPException``
    from ``getresponse()`` and ``read()`` rather than as ``URLError``. Catching only
    ``URLError`` left the three commonest network failures reaching the operator as
    a traceback. They are not caught here, because a request that never produced a
    status is the caller's to retry or refuse, and pretending otherwise here is how
    it would be mistaken for a refusal.
    """
    try:
        response = open_url(
            url,
            data=data,
            headers=dict(headers),
            method=method,
            validate_certs=validate_certs,
            ca_path=ca_path or None,
            timeout=timeout,
        )
        status = int(response.status)
        headers_sent = dict(response.headers or {})
        text = response.read().decode("utf-8", "replace")
    except HTTPError as error:
        status = int(error.code)
        headers_sent = dict(error.headers or {})
        text = error.read().decode("utf-8", "replace")
    return RawResponse(status=status, text=text, headers=headers_sent)


def post_form(
    base_url: str,
    path: str,
    form: Mapping[str, str],
    *,
    validate_certs: bool = True,
    ca_path: str = "",
    timeout: int = 30,
) -> tuple[int, str]:
    """Post a form body, returning only the status and the text.

    Shaped for :class:`._auth.Authoriser`, which takes a transport rather than
    importing one. No headers come back because the token endpoint's response
    carries nothing this collection needs from them.
    """
    raw = open_transport(
        "POST",
        base_url.rstrip("/") + path,
        urlencode(form),
        {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        validate_certs=validate_certs,
        ca_path=ca_path,
        timeout=timeout,
    )
    return raw.status, raw.text


class Api:
    """One authenticated connection to one tailnet."""

    __slots__ = ("_authoriser", "_options", "_sleep", "_transport")

    def __init__(
        self,
        options: ApiOptions,
        authoriser: Authoriser,
        transport: Transport = open_transport,
        *,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._options = options
        self._authoriser = authoriser
        self._transport = transport
        self._sleep = sleep

    def __repr__(self) -> str:
        return f"Api({self._options.base_url!r}, tailnet={self._options.tailnet!r})"

    @property
    def tailnet(self) -> str:
        return self._options.tailnet

    def call(
        self,
        name: str,
        method: str,
        *,
        params: Mapping[str, str] | None = None,
        query: Mapping[str, str | Sequence[str]] | None = None,
        body: Any = None,
        headers: Mapping[str, str] | None = None,
        expect_etag: bool = False,
    ) -> Response:
        """Make one request and return its body, or raise.

        ``name`` is an operation from the vendored description and ``method`` is
        the verb that operation documents, so neither can drift from the API. A
        caller passing a verb the operation does not have is a programming error
        and is refused rather than sent.

        ``params`` fills the operation's path parameters and ``query`` carries
        the filters the description declares as query parameters. They are
        separate because a filter is not part of the operation's identity: two
        requests for the same log window are the same operation, which is what
        keeps a filtered read from having to be a second row in the table. A value
        that is a sequence is repeated under its own name, because the
        description declares several filters as arrays and the API reads each
        occurrence as one element.

        ``expect_etag`` is for the one caller that must guard a later write. When
        the response carries no ``ETag`` the returned ``etag`` is :data:`NO_ETAG`,
        and treating that as a reason to stop is the caller's decision, not this
        module's.
        """
        verb = method.upper()
        operation = OPERATIONS.get(name)
        if operation is None:
            raise ValueError(f"unknown operation: {name}")
        if operation.method.upper() != verb:
            # A call site that sends the wrong verb would not fail loudly. The
            # operation name and the verb come from the same vendored entry, so
            # a disagreement between them is a programming error worth naming.
            raise ValueError(
                f"operation {name} is a {operation.method.upper()} operation, not {verb}"
            )
        path = self._path(name, operation, params)
        # Carried separately from the path so that a failure can report the
        # operation rather than the filters. A filter can hold a user address,
        # and the request line in a message outlives the run.
        failure_path = path
        path = path + _query_of(query)

        attempt = 0
        while True:
            try:
                raw = self._once(verb, path, body=body, headers=headers)
            except TRANSPORT_ERRORS as error:
                # A dropped connection is the failure a transient network blip
                # actually produces, and the reasoning above applies to it
                # unchanged: a read that never reached the server changed
                # nothing, so retrying it is free, while a write that may or may
                # not have landed must surface. The budget stays at one, because
                # a tailnet the operator cannot reach is a problem to report
                # rather than one to sit in a loop against.
                if verb not in RETRYABLE_METHODS or attempt >= RATE_LIMIT_RETRIES:
                    raise unreachable(verb, failure_path, error) from None
                attempt += 1
                self._sleep(DEFAULT_RETRY_AFTER_SECONDS)
                continue
            if raw.status == 429 and verb in RETRYABLE_METHODS and attempt < RATE_LIMIT_RETRIES:
                attempt += 1
                self._sleep(_retry_after(raw.headers))
                continue
            if raw.status >= 400:
                raise from_response(
                    raw.status,
                    verb,
                    failure_path,
                    upstream_message=_message_of(raw.text),
                    response_headers=raw.headers,
                )
            return Response(
                status=raw.status,
                body=_body_of(raw.text),
                etag=_header(raw.headers, "etag") if expect_etag else NO_ETAG,
            )

    def _path(self, name: str, operation: Operation, params: Mapping[str, str] | None) -> str:
        supplied = dict(params or {})
        if "tailnet" not in supplied and is_tailnet_scoped(operation):
            supplied["tailnet"] = self._options.tailnet
        return build_path(name, **supplied)

    def _once(
        self,
        verb: str,
        path: str,
        *,
        body: Any,
        headers: Mapping[str, str] | None,
    ) -> RawResponse:
        request_headers: dict[str, str] = {
            "Authorization": f"Bearer {self._authoriser.bearer().expose()}",
            "Accept": "application/json",
        }
        if headers:
            request_headers.update(headers)

        data: Any = None
        if body is not None:
            # A str body is already rendered. HuJSON is sent as text under its own
            # content type because the canonical form pairs the two deliberately,
            # and encoding it again here would turn the document into a JSON string
            # literal and relabel it as plain JSON, which the server would then
            # parse strictly and reject at the first comment.
            data = body if isinstance(body, str) else json.dumps(body)
            request_headers.setdefault("Content-Type", "application/json")

        options = self._options
        return self._transport(
            verb,
            options.base_url.rstrip("/") + path,
            data,
            request_headers,
            validate_certs=options.validate_certs,
            ca_path=options.ca_path,
            timeout=options.timeout,
        )


def _query_of(query: Mapping[str, str | Sequence[str]] | None) -> str:
    """A request's query string, or an empty string.

    ``doseq`` is what turns a sequence value into repeated parameters rather than
    one, and it is required rather than convenient: the description declares
    several filters as arrays of strings, and the API reads each occurrence of the
    name as one element, so a single joined value would be one filter that matches
    nothing. A string is excluded from that treatment explicitly, because it is
    itself a sequence and would otherwise be exploded into its characters.

    An empty mapping, and a mapping whose values are all empty sequences, both
    produce nothing, so a caller with no filters to send does not have to
    distinguish "no filters" from "no filter selected".
    """
    if not query:
        return ""
    return "?" + urlencode(
        {
            name: [str(item) for item in value]
            if isinstance(value, Sequence) and not isinstance(value, str)
            else value
            for name, value in query.items()
        },
        doseq=True,
    )


def _header(headers: Mapping[str, str], name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return str(value)
    return NO_ETAG


def _retry_after(headers: Mapping[str, str]) -> float:
    try:
        seconds = float(_header(headers, "retry-after").strip())
    except ValueError:
        return DEFAULT_RETRY_AFTER_SECONDS
    if seconds < 0.0:
        return DEFAULT_RETRY_AFTER_SECONDS
    return min(seconds, MAX_RETRY_AFTER_SECONDS)


def _message_of(text: str) -> str | None:
    """The body's ``message`` field, and nothing else.

    The richer ``data`` shape belongs to a 200 from the policy validator and
    carries user addresses, so it is never read on the way to constructing an
    error.
    """
    if not text:
        return None
    try:
        document = json.loads(text)
    except ValueError:
        return None
    if isinstance(document, dict):
        value = document.get("message")
        if isinstance(value, str) and value.strip():
            return value
    return None


def _body_of(text: str) -> Any:
    if not text.strip():
        return None
    try:
        return json.loads(text)
    except ValueError:
        return text
