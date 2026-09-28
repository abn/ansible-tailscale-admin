# SPDX-License-Identifier: BSD-2-Clause
"""Tests for credential resolution and token acquisition."""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import TOKEN_PATH
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import AccessToken
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import ApiToken
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import Authoriser
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import OauthClient
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import Secret
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import from_options

API_TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
CLIENT_ID = "kABCD123456CNTRL"
CLIENT_SECRET = "tskey-client-abcdefghijklmnopqrstuvwxyz01"
ACCESS_TOKEN = "tskey-token-zyxwvutsrqponmlk0987654321"


class Clock:
    """A monotonic clock the test advances by hand."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class Post:
    """A recorded transport that answers from a queue of canned responses."""

    def __init__(self, *responses: tuple[int, str]) -> None:
        self.responses: list[tuple[int, str]] = list(responses)
        self.calls: list[tuple[str, dict[str, str]]] = []

    def __call__(self, path: str, form: dict[str, str]) -> tuple[int, str]:
        self.calls.append((path, form))
        if not self.responses:
            raise AssertionError(f"unexpected extra call to {path}")
        return self.responses.pop(0)


def token_response(token: str = ACCESS_TOKEN, expires_in: Any = 3600) -> tuple[int, str]:
    return 200, json.dumps(
        {"access_token": token, "token_type": "Bearer", "expires_in": expires_in}
    )


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def oauth() -> OauthClient:
    return OauthClient(CLIENT_ID, Secret(CLIENT_SECRET))


def test_a_secret_never_appears_in_its_own_representation() -> None:
    secret = Secret(API_TOKEN)

    assert API_TOKEN not in repr(secret)
    assert API_TOKEN not in str(secret)
    assert API_TOKEN not in f"{secret}"
    assert API_TOKEN not in f"{secret!r}"
    assert API_TOKEN not in f"{secret!s}"
    assert secret.expose() == API_TOKEN


def test_a_secret_never_appears_through_percent_formatting() -> None:
    # Deliberately not an f-string. Every other assertion here routes through
    # __format__, and this one routes through __str__ instead, so the two are not
    # interchangeable coverage. Refactoring it away would leave __str__ untested.
    secret = Secret(API_TOKEN)

    assert API_TOKEN not in "%s" % secret  # noqa: UP031
    assert API_TOKEN not in "%r" % secret  # noqa: UP031
    assert secret.expose() == API_TOKEN


def test_a_credential_never_appears_in_its_own_representation() -> None:
    for credentials in (
        ApiToken(Secret(API_TOKEN)),
        OauthClient(CLIENT_ID, Secret(CLIENT_SECRET)),
    ):
        for rendered in (
            repr(credentials),
            f"{credentials}",
            f"{credentials!r}",
            f"{credentials!s}",
        ):
            assert API_TOKEN not in rendered
            assert CLIENT_SECRET not in rendered


def test_an_authoriser_never_appears_in_its_own_representation(clock: Clock) -> None:
    authoriser = Authoriser(
        OauthClient(CLIENT_ID, Secret(CLIENT_SECRET)), Post(token_response()), clock=clock
    )

    assert CLIENT_SECRET not in repr(authoriser)
    assert ACCESS_TOKEN not in repr(authoriser)


def test_a_failure_message_never_carries_the_secret(oauth: OauthClient) -> None:
    post = Post((401, json.dumps({"error": "invalid_client"})))

    with pytest.raises(CredentialError) as caught:
        Authoriser(oauth, post).bearer()

    assert "invalid_client" in str(caught.value)
    assert CLIENT_SECRET not in str(caught.value)
    assert CLIENT_ID not in str(caught.value)


def test_an_api_token_authenticates_as_itself(clock: Clock) -> None:
    post = Post()

    bearer = Authoriser(from_options(api_token=API_TOKEN), post, clock=clock).bearer()

    assert bearer.expose() == API_TOKEN
    assert post.calls == [], "an API access token must never be exchanged"


def test_a_client_is_exchanged_at_the_token_endpoint(oauth: OauthClient, clock: Clock) -> None:
    post = Post(token_response())

    bearer = Authoriser(oauth, post, clock=clock).bearer()

    assert bearer.expose() == ACCESS_TOKEN
    assert post.calls == [
        (
            TOKEN_PATH,
            {
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            },
        )
    ]


def test_a_token_is_reused_until_it_is_close_to_expiry(oauth: OauthClient, clock: Clock) -> None:
    post = Post(token_response(), token_response("tskey-token-second"))

    authoriser = Authoriser(oauth, post, clock=clock)
    first = authoriser.bearer()
    clock.advance(3000.0)
    second = authoriser.bearer()

    assert first.expose() == ACCESS_TOKEN
    assert second.expose() == ACCESS_TOKEN, "still inside the hour, so no second exchange"
    assert len(post.calls) == 1


def test_a_token_is_reminted_once_it_is_within_the_margin(oauth: OauthClient, clock: Clock) -> None:
    post = Post(token_response(), token_response("tskey-token-second"))
    authoriser = Authoriser(oauth, post, clock=clock, margin=60.0)

    authoriser.bearer()
    clock.advance(3541.0)
    second = authoriser.bearer()

    assert second.expose() == "tskey-token-second"
    assert len(post.calls) == 2


def test_a_token_without_a_usable_lifetime_is_not_cached(oauth: OauthClient, clock: Clock) -> None:
    post = Post(token_response(expires_in=0), token_response("tskey-token-second"))
    authoriser = Authoriser(oauth, post, clock=clock)

    first = authoriser.bearer()
    second = authoriser.bearer()

    assert first.expose() == ACCESS_TOKEN
    assert second.expose() == "tskey-token-second"
    assert len(post.calls) == 2


@pytest.mark.parametrize("lifetime", [None, "soon", -1])
def test_a_nonsense_lifetime_is_treated_as_no_lifetime(
    oauth: OauthClient, clock: Clock, lifetime: Any
) -> None:
    body = json.dumps({"access_token": ACCESS_TOKEN, "expires_in": lifetime})
    post = Post((200, body), token_response("tskey-token-second"))

    authoriser = Authoriser(oauth, post, clock=clock)
    authoriser.bearer()

    assert authoriser.bearer().expose() == "tskey-token-second", "nothing worth caching"


def test_a_non_json_answer_is_reported_as_such(oauth: OauthClient) -> None:
    post = Post((200, "<html>gateway timeout</html>"))

    with pytest.raises(CredentialError, match="not JSON"):
        Authoriser(oauth, post).bearer()


def test_a_success_status_with_no_token_is_rejected(oauth: OauthClient) -> None:
    post = Post((200, json.dumps({"token_type": "Bearer"})))

    with pytest.raises(CredentialError, match="without an access token"):
        Authoriser(oauth, post).bearer()


def test_a_blank_token_is_rejected(oauth: OauthClient) -> None:
    post = Post((200, json.dumps({"access_token": "   "})))

    with pytest.raises(CredentialError, match="without an access token"):
        Authoriser(oauth, post).bearer()


def test_a_json_array_is_not_mistaken_for_a_token_document(oauth: OauthClient) -> None:
    post = Post((200, json.dumps([ACCESS_TOKEN])))

    with pytest.raises(CredentialError, match="without an access token"):
        Authoriser(oauth, post).bearer()


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ('{"message": "nope"}', "nope"),
        ('{"error_description": "bad client"}', "bad client"),
        ('{"error": "invalid_client"}', "invalid_client"),
        ('{"nothing": "useful"}', "no detail given"),
        ("not json at all", "no detail given"),
        ('{"message": "  "}', "no detail given"),
    ],
)
def test_a_failed_exchange_passes_the_endpoints_own_reason_on(
    oauth: OauthClient, body: str, expected: str
) -> None:
    with pytest.raises(CredentialError) as caught:
        Authoriser(oauth, Post((401, body))).bearer()

    assert "401" in str(caught.value)
    assert expected in str(caught.value)


def test_an_api_token_alone_is_a_credential() -> None:
    assert isinstance(from_options(api_token=API_TOKEN), ApiToken)


def test_a_client_id_and_secret_together_are_a_credential() -> None:
    credentials = from_options(oauth_client_id=CLIENT_ID, oauth_client_secret=CLIENT_SECRET)

    assert isinstance(credentials, OauthClient)
    assert credentials.client_id == CLIENT_ID


def test_supplying_both_kinds_is_refused() -> None:
    with pytest.raises(CredentialError, match="mutually exclusive"):
        from_options(
            api_token=API_TOKEN, oauth_client_id=CLIENT_ID, oauth_client_secret=CLIENT_SECRET
        )


def test_supplying_both_kinds_is_refused_even_with_only_half_a_client() -> None:
    with pytest.raises(CredentialError, match="mutually exclusive"):
        from_options(api_token=API_TOKEN, oauth_client_id=CLIENT_ID)


def test_a_client_id_without_its_secret_names_what_is_missing() -> None:
    with pytest.raises(CredentialError, match="oauth_client_secret is required"):
        from_options(oauth_client_id=CLIENT_ID)


def test_a_client_secret_without_its_id_names_what_is_missing() -> None:
    with pytest.raises(CredentialError, match="oauth_client_id is required"):
        from_options(oauth_client_secret=CLIENT_SECRET)


def test_no_credential_at_all_is_refused_with_both_ways_out() -> None:
    with pytest.raises(CredentialError) as caught:
        from_options()

    assert "api_token" in str(caught.value)
    assert "oauth_client_id" in str(caught.value)


@pytest.mark.parametrize("blank", ["", "   "])
def test_whitespace_is_not_a_credential(blank: str) -> None:
    with pytest.raises(CredentialError, match="No credential"):
        from_options(api_token=blank, oauth_client_id=blank, oauth_client_secret=blank)


def test_the_exchange_asks_for_no_scope_in_particular(oauth: OauthClient) -> None:
    form: dict[str, str] | None = oauth.form()

    assert form is not None
    assert "scope" not in form
    assert "tags" not in form


def test_an_access_token_carries_its_deadline() -> None:
    token = AccessToken(Secret(ACCESS_TOKEN), 1234.0)

    assert token.expires_at == 1234.0
    assert token.value.expose() == ACCESS_TOKEN


def test_a_token_read_from_a_file_keeps_its_trailing_newline_out_of_the_request() -> None:
    credentials = from_options(api_token=f"{API_TOKEN}\n")

    assert isinstance(credentials, ApiToken)
    assert credentials.token.expose() == API_TOKEN


def test_a_client_read_from_a_file_is_stripped_on_both_halves() -> None:
    credentials = from_options(
        oauth_client_id=f"{CLIENT_ID}\n", oauth_client_secret=f"  {CLIENT_SECRET}  "
    )

    assert isinstance(credentials, OauthClient)
    assert credentials.client_id == CLIENT_ID
    assert credentials.secret.expose() == CLIENT_SECRET


def test_an_api_token_needs_no_transport() -> None:
    """The transport exists only to exchange a client, so an API token must not need one."""
    assert Authoriser(from_options(api_token=API_TOKEN)).bearer().expose() == API_TOKEN


def test_a_client_with_no_transport_says_so() -> None:
    authoriser = Authoriser(
        from_options(oauth_client_id=CLIENT_ID, oauth_client_secret=CLIENT_SECRET)
    )

    with pytest.raises(CredentialError, match="transport"):
        authoriser.bearer()
