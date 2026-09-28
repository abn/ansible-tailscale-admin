# SPDX-License-Identifier: BSD-2-Clause
"""Credential resolution and access-token acquisition for the Tailscale API.

Internal to this collection. The path carries a leading underscore, which
declares the kernel private: it can be refactored in any release without a major
version bump. See ``.agents/rules/ansible.md``.

Two kinds of credential reach this collection, and they are not interchangeable.
An API access token is its own bearer: it is sent as written and nothing else
happens. An OAuth client is not. Its secret is exchanged at the token endpoint
for an access token that lives about an hour, and it is that access token, never
the secret, which authenticates a call. The exchange endpoint is absent from the
vendored OpenAPI description, so the path is written from Tailscale's own
documentation rather than generated.

The transport is injected rather than imported. This module builds a form body
and reads a JSON document, and knows nothing about sockets, TLS or
``open_url``, which is what lets it be tested without a network and keeps
``_api`` the only place that performs HTTP.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import NamedTuple
from typing import TypeGuard

__all__ = [
    "TOKEN_PATH",
    "AccessToken",
    "ApiToken",
    "Authoriser",
    "CredentialError",
    "Credentials",
    "OauthClient",
    "Secret",
    "from_options",
]

#: Written from Tailscale's OAuth documentation, not from the vendored schema,
#: which describes only bearer authentication. Relative to the API root, because
#: it is joined onto base_url, which already ends in the /api/v2 prefix.
TOKEN_PATH = "/oauth/token"

#: Re-mint this far ahead of the stated expiry. A token that expires mid-request
#: produces a 401 that reads as a permissions problem, and the server's
#: ``expires_in`` is not a promise about clock agreement.
EXPIRY_MARGIN_SECONDS = 60.0

#: The injected transport: posts a form body, returns the status and the body.
Post = Callable[[str, dict[str, str]], tuple[int, str]]


class Secret:
    """A string that must not reach a log, an exception or a traceback.

    Every way a value can be interpolated is overridden, because the realistic
    leak is not deliberate: it is an f-string in a debug path, or a dict rendered
    into a failure message by something further up. The value is reachable only
    through :meth:`expose`, which makes each read of it a deliberate act that
    review can point at.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def expose(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return self.__repr__()

    def __bool__(self) -> bool:
        return bool(self._value)


class CredentialError(Exception):
    """The options given cannot form a usable credential.

    Deliberately not a :class:`TailscaleError`. That type carries a status, a
    method and a path because it describes a request the API refused, and none of
    those exist here: this is raised while reading the module's own arguments,
    before anything is sent. Reporting it as an upstream failure would
    misattribute the cause, and a caller that catches both needs to know they are
    different kinds of problem.
    """


class Credentials:
    """Base for the credential kinds. Not constructed directly.

    ``bearer`` is the only question the authoriser ever asks, so a new kind of
    credential is added by implementing it rather than by extending a chain of
    ``isinstance`` tests beside the authoriser. A subclass that forgets would
    otherwise be sent down the wrong path and fail with a message about a
    missing transport, which says nothing about the real mistake.
    """

    __slots__ = ()

    def bearer(self, exchange: Callable[[OauthClient], AccessToken]) -> Secret:
        raise NotImplementedError(
            f"a credential kind must implement bearer(); {type(self).__name__} does not"
        )


class ApiToken(Credentials):
    """An API access token, which authenticates a call as itself."""

    __slots__ = ("token",)

    def __init__(self, token: Secret) -> None:
        self.token = token

    def __repr__(self) -> str:
        return "ApiToken(<redacted>)"

    def bearer(self, exchange: Callable[[OauthClient], AccessToken]) -> Secret:
        return self.token


class OauthClient(Credentials):
    """An OAuth client, whose secret must be exchanged before it can be used."""

    __slots__ = ("client_id", "secret")

    def __init__(self, client_id: str, secret: Secret) -> None:
        self.client_id = client_id
        self.secret = secret

    def __repr__(self) -> str:
        return f"OauthClient({self.client_id!r}, <redacted>)"

    def bearer(self, exchange: Callable[[OauthClient], AccessToken]) -> Secret:
        return exchange(self).value

    def form(self) -> dict[str, str]:
        """The token-endpoint request body.

        No scope is requested. The client was created with the scopes it may
        grant and the module exposes no way to narrow them, so asking for a
        subset would assert something about the client's configuration that this
        collection cannot verify and the operator cannot see.
        """
        return {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.secret.expose(),
        }


class AccessToken(NamedTuple):
    """A bearer token and the monotonic instant after which it must not be used."""

    value: Secret
    expires_at: float


def _present(value: str | None) -> TypeGuard[str]:
    """Whether an option carries anything.

    Whitespace counts as absent, because a token that is only whitespace is what
    an undefined template variable looks like, and sending it produces a 401 that
    reads as a permissions problem rather than as a missing value.
    """
    return bool(value and value.strip())


def from_options(
    *,
    api_token: str | None = None,
    oauth_client_id: str | None = None,
    oauth_client_secret: str | None = None,
) -> Credentials:
    """Build the one credential the options describe, or explain why they do not.

    Values are stripped, so a token read from a file that ended in a newline works
    without the caller having to think about it.

    Raises rather than returning ``None``, so a caller cannot forget the case.
    """
    have_api = _present(api_token)
    have_id = _present(oauth_client_id)
    have_secret = _present(oauth_client_secret)

    if have_api and (have_id or have_secret):
        raise CredentialError(
            "api_token is mutually exclusive with oauth_client_id and "
            "oauth_client_secret. An API access token authenticates on its own "
            "while an OAuth client must be exchanged first, so supplying both "
            "leaves it ambiguous which one is in use."
        )
    if have_api:
        return ApiToken(Secret(api_token.strip()))
    if have_id and have_secret:
        return OauthClient(oauth_client_id.strip(), Secret(oauth_client_secret.strip()))
    if have_id or have_secret:
        missing = "oauth_client_secret" if have_id else "oauth_client_id"
        raise CredentialError(
            f"{missing} is required alongside the other half of the OAuth client. "
            "A client is an ID and a secret together and neither half works alone."
        )
    raise CredentialError(
        "No credential. Set api_token, or set oauth_client_id and "
        "oauth_client_secret together. Every Tailscale API call is "
        "authenticated, and a credential sitting in the environment is not read."
    )


class Authoriser:
    """Supplies a bearer token, exchanging and caching when it has to.

    An API access token needs no work beyond wrapping it. An OAuth client is
    exchanged once and the result reused until close to expiry, so a module that
    makes several calls in one run mints one token rather than one per call.
    """

    __slots__ = ("_clock", "_credentials", "_margin", "_post", "_token")

    def __init__(
        self,
        credentials: Credentials,
        post: Post | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        margin: float = EXPIRY_MARGIN_SECONDS,
    ) -> None:
        self._credentials = credentials
        self._post = post
        self._clock = clock
        self._margin = margin
        self._token: AccessToken | None = None

    def __repr__(self) -> str:
        return f"Authoriser({self._credentials!r})"

    def bearer(self) -> Secret:
        """A token that is valid for at least one more request."""
        return self._credentials.bearer(self._exchange_once)

    def _exchange_once(self, client: OauthClient) -> AccessToken:
        if self._token is not None and self._token.expires_at > self._clock() + self._margin:
            return self._token
        self._token = self._exchange(client)
        return self._token

    def _exchange(self, client: OauthClient) -> AccessToken:
        if self._post is None:
            # Only a client needs the transport, so it is optional for the sake of
            # an API token, which has nothing to exchange. Reaching here means a
            # caller built an authoriser for a client and gave it nothing to
            # exchange with.
            raise CredentialError(
                "An OAuth client needs a transport to reach the token endpoint, and "
                "none was supplied."
            )
        status, body = self._post(TOKEN_PATH, client.form())

        if status != 200:
            # The body describes the client and never the secret, so passing its
            # own explanation on is safe. An exchange that swallowed its reason
            # would be the difference between a fixable error and a shrug.
            raise CredentialError(
                f"The OAuth token endpoint answered {status}: "
                f"{_error_text(body, 'no detail given')}"
            )

        try:
            document = json.loads(body)
        except ValueError as error:
            raise CredentialError(
                f"The OAuth token endpoint answered with something that is not JSON: {error}"
            ) from None

        value = document.get("access_token") if isinstance(document, dict) else None
        if not isinstance(value, str) or not value.strip():
            raise CredentialError(
                "The OAuth token endpoint answered without an access token. The "
                "client may have been revoked, or the endpoint may be returning "
                "an error document with a success status."
            )

        seconds = document.get("expires_in") if isinstance(document, dict) else None
        lifetime = float(seconds) if isinstance(seconds, (int, float)) else 0.0
        if lifetime <= 0.0:
            # With no usable lifetime the only safe reading is that the token is
            # already stale, so it serves this request and is not cached.
            return AccessToken(Secret(value), self._clock())
        return AccessToken(Secret(value), self._clock() + lifetime)


def _error_text(body: str, fallback: str) -> str:
    """The endpoint's own explanation, or the fallback if it offered none."""
    try:
        document = json.loads(body)
    except ValueError:
        return fallback
    if isinstance(document, dict):
        for key in ("message", "error_description", "error"):
            value = document.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return fallback
