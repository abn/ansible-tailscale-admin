# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the HTTP client, and for the transport contract underneath it.

The contract is the part worth pinning. ``open_url`` answers a success with a
single response object and raises ``HTTPError`` for a status it treats as a
failure. That asymmetry was got wrong once already, and every test double in this
repository agreed with the wrong version, so nothing caught it. These tests hold
the real shape.
"""

from __future__ import annotations

import io
import json
from email.message import Message
from http.client import IncompleteRead
from typing import Any
from urllib.error import HTTPError
from urllib.error import URLError

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale import _api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import ApiOptions
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import open_transport
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import post_form
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import TOKEN_PATH
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import Authoriser
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import Secret
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import from_options
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import NO_STATUS
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleBadRequest,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleNotFound,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscalePermissionError,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscalePreconditionFailed,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleRateLimited,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleUnreachable,
)

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
BASE = "https://api.tailscale.com/api/v2"


class Body:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def decode(self, *args: str) -> str:
        return self._data.decode("utf-8", "replace")


class Answer:
    """The shape open_url actually returns: one object, not a pair."""

    def __init__(self, status: int, text: str, headers: dict | None = None) -> None:
        self.status = status
        self.headers = headers or {}
        self._text = text

    def read(self) -> Body:
        return Body(self._text.encode())


def raising(status: int, text: str, headers: dict | None = None) -> HTTPError:
    message = Message()
    for name, value in (headers or {}).items():
        message[name] = value
    return HTTPError(
        url=BASE,
        code=status,
        msg="error",
        hdrs=message,
        fp=io.BytesIO(text.encode()),
    )


def answer(status: int, text: str, headers: dict | None = None) -> Any:
    """A stand-in that refuses, so the raised-HTTPError path is exercised."""

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise raising(status, text, headers)

    return refuse


@pytest.fixture
def slept() -> list[float]:
    """Records what the client asked to wait for, through the public keyword.

    `Api` takes `sleep=` for exactly this, and five retry tests were assigning
    the private slot instead, which couples them to an attribute name nothing
    promises.
    """
    return []


@pytest.fixture
def client(slept: list[float]) -> Any:
    """An Api whose credential needs no exchange, so no transport is injected."""
    options = ApiOptions(base_url=BASE, tailnet="-")
    return Api(options, Authoriser(from_options(api_token=TOKEN)), sleep=slept.append)


def test_a_success_is_read_off_the_response_object(mocker: Any) -> None:
    """The contract, held directly. A pair here would fail this test."""
    mocker.patch.object(_api, "open_url", lambda *a, **k: Answer(200, '{"ok":true}'))

    raw = open_transport("GET", f"{BASE}/x", None, {}, validate_certs=True, ca_path="", timeout=5)

    assert raw.status == 200
    assert json.loads(raw.text) == {"ok": True}


def test_an_error_status_arrives_as_a_raised_http_error(mocker: Any) -> None:
    mocker.patch.object(
        _api,
        "open_url",
        answer(403, '{"message":"nope"}'),
    )

    raw = open_transport("GET", f"{BASE}/x", None, {}, validate_certs=True, ca_path="", timeout=5)

    assert raw.status == 403, "a raised HTTPError is turned back into a status"
    assert json.loads(raw.text)["message"] == "nope", "so the server's reason survives"


def test_headers_come_from_wherever_the_status_did(mocker: Any) -> None:
    mocker.patch.object(_api, "open_url", answer(412, "{}", {"ETag": "x"}))

    raw = open_transport("POST", f"{BASE}/x", "{}", {}, validate_certs=True, ca_path="", timeout=5)

    assert raw.headers["ETag"] == "x"


def test_post_form_returns_only_the_status_and_the_text(mocker: Any) -> None:
    mocker.patch.object(_api, "open_url", lambda *a, **k: Answer(200, '{"access_token":"t"}'))

    status, text = post_form(BASE, "/api/v2/oauth/token", {"grant_type": "client_credentials"})

    assert (status, json.loads(text)["access_token"]) == (200, "t")


def test_an_etag_is_captured_when_asked_for(client: Api, mocker: Any, slept: list[float]) -> None:
    mocker.patch.object(_api, "open_url", lambda *a, **k: Answer(200, "{}", {"ETag": '"abc"'}))

    assert client.call("policy_get", "GET", expect_etag=True).etag == '"abc"'


def test_an_etag_is_not_captured_unless_asked_for(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    mocker.patch.object(_api, "open_url", lambda *a, **k: Answer(200, "{}", {"ETag": '"abc"'}))

    assert client.call("policy_get", "GET").etag == ""


def test_a_response_with_no_etag_header_reports_none(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    mocker.patch.object(_api, "open_url", lambda *a, **k: Answer(200, "{}"))

    assert client.call("policy_get", "GET", expect_etag=True).etag == ""


def test_a_verb_the_operation_does_not_have_is_refused(client: Api) -> None:
    with pytest.raises(ValueError, match="is a GET operation"):
        client.call("policy_get", "POST")


def test_an_unknown_operation_is_refused(client: Api) -> None:
    with pytest.raises(ValueError, match="unknown operation"):
        client.call("policy_nonexistent", "GET")


def test_a_path_parameter_is_required(client: Api) -> None:
    with pytest.raises(ValueError, match="needs"):
        client.call("device_get", "GET")


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (403, TailscalePermissionError),
        (404, TailscaleNotFound),
        (412, TailscalePreconditionFailed),
        (429, TailscaleRateLimited),
    ],
)
def test_each_status_maps_to_its_own_error(
    client: Api, mocker: Any, status: int, expected: type[Exception]
) -> None:
    mocker.patch.object(_api, "open_url", answer(status, "{}"))

    with pytest.raises(expected):
        client.call("policy_get", "GET")


def test_a_rate_limited_read_is_retried_once(client: Api, mocker: Any, slept: list[float]) -> None:
    attempts = []

    def answer(*args: Any, **kwargs: Any) -> Any:
        attempts.append(1)
        if len(attempts) == 1:
            raise raising(429, "{}", {"Retry-After": "0"})
        return Answer(200, "{}")

    mocker.patch.object(_api, "open_url", answer)
    assert client.call("policy_get", "GET").status == 200
    assert len(attempts) == 2
    assert slept == [0.0], "it waits for as long as the server asked"


def test_a_rate_limited_read_is_not_retried_forever(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    mocker.patch.object(_api, "open_url", answer(429, "{}"))

    with pytest.raises(TailscaleRateLimited):
        client.call("policy_get", "GET")


def test_a_rate_limited_write_is_never_retried(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    """A retried write is the one thing that cannot be taken back."""
    attempts = []

    def answer(*args: Any, **kwargs: Any) -> Any:
        attempts.append(1)
        raise raising(429, "{}")

    mocker.patch.object(_api, "open_url", answer)

    with pytest.raises(TailscaleRateLimited):
        client.call("policy_set", "POST", body="{}")

    assert len(attempts) == 1, "a write is attempted exactly once"


def test_a_retry_after_beyond_the_ceiling_is_capped(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    mocker.patch.object(
        _api,
        "open_url",
        answer(429, "{}", {"Retry-After": "99999"}),
    )
    with pytest.raises(TailscaleRateLimited):
        client.call("policy_get", "GET")

    assert slept == [_api.MAX_RETRY_AFTER_SECONDS]


def test_a_retry_after_that_is_not_a_number_falls_back(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    mocker.patch.object(
        _api,
        "open_url",
        answer(429, "{}", {"Retry-After": "soon"}),
    )
    with pytest.raises(TailscaleRateLimited):
        client.call("policy_get", "GET")

    assert slept == [_api.DEFAULT_RETRY_AFTER_SECONDS]


def test_the_bearer_is_attached_and_never_retained(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    seen: dict = {}

    def answer(url: str, data: Any = None, headers: Any = None, **kwargs: Any) -> Any:
        seen.update(headers or {})
        return Answer(200, "{}")

    mocker.patch.object(_api, "open_url", answer)
    response = client.call("policy_get", "GET")

    assert seen["Authorization"] == f"Bearer {TOKEN}"
    assert not hasattr(response, "headers"), "a response must not carry headers into a transcript"


def test_a_json_body_is_sent_as_json(client: Api, mocker: Any, slept: list[float]) -> None:
    seen: dict = {}

    def answer(url: str, data: Any = None, headers: Any = None, **kwargs: Any) -> Any:
        seen["data"] = data
        seen.update(headers or {})
        return Answer(200, "{}")

    mocker.patch.object(_api, "open_url", answer)
    client.call("policy_set", "POST", body={"acls": []})

    assert json.loads(seen["data"]) == {"acls": []}
    assert seen["Content-Type"] == "application/json"


def test_a_text_body_is_sent_untouched(client: Api, mocker: Any, slept: list[float]) -> None:
    """HuJSON reaches the API as the text it was rendered as, comments and all."""
    seen: dict = {}

    def answer(url: str, data: Any = None, headers: Any = None, **kwargs: Any) -> Any:
        seen["data"] = data
        seen.update(headers or {})
        return Answer(200, "{}")

    mocker.patch.object(_api, "open_url", answer)
    client.call("policy_set", "POST", body='{\n // a comment\n "acls": []\n}\n')

    assert seen["data"] == '{\n // a comment\n "acls": []\n}\n'
    assert '"\\"' not in seen["data"], "a text body must not be re-encoded as a JSON string"


def test_a_caller_content_type_wins(client: Api, mocker: Any, slept: list[float]) -> None:
    seen: dict = {}

    def answer(url: str, data: Any = None, headers: Any = None, **kwargs: Any) -> Any:
        seen.update(headers or {})
        return Answer(200, "{}")

    mocker.patch.object(_api, "open_url", answer)
    client.call("policy_set", "POST", body="{}", headers={"Content-Type": "application/hujson"})

    assert seen["Content-Type"] == "application/hujson"


def test_a_non_json_body_comes_back_as_text(client: Api, mocker: Any, slept: list[float]) -> None:
    mocker.patch.object(_api, "open_url", lambda *a, **k: Answer(200, "not json"))

    assert client.call("policy_get", "GET").body == "not json"


def test_an_empty_body_comes_back_as_nothing(client: Api, mocker: Any, slept: list[float]) -> None:
    mocker.patch.object(_api, "open_url", lambda *a, **k: Answer(200, ""))

    assert client.call("policy_get", "GET").body is None


def test_the_error_path_reads_only_the_message_field(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    """The data shape of a validator carries addresses, so it is never read."""
    body = json.dumps(
        {"message": "refused", "data": [{"user": "a@example.com", "errors": ["1.2.3.4:22"]}]}
    )
    mocker.patch.object(_api, "open_url", answer(400, body))

    with pytest.raises(TailscaleBadRequest) as caught:
        client.call("policy_get", "GET")

    assert "refused" in caught.value.message
    assert "1.2.3.4" not in str(caught.value), "addresses must not reach a log"


def test_the_repr_carries_no_credential(client: Api) -> None:
    assert TOKEN not in repr(client)
    assert TOKEN not in repr(client._authoriser)


def test_the_tailnet_is_addressed_when_given(mocker: Any) -> None:
    seen: dict = {}
    options = ApiOptions(base_url=BASE, tailnet="-1234567890123")
    client = Api(options, Authoriser(from_options(api_token=Secret(TOKEN).expose())))

    def answer(url: str, data: Any = None, headers: Any = None, **kwargs: Any) -> Any:
        seen["url"] = url
        return Answer(200, "{}")

    mocker.patch.object(_api, "open_url", answer)
    client.call("policy_get", "GET")

    assert seen["url"] == f"{BASE}/tailnet/-1234567890123/acl"


def test_the_token_url_is_composed_without_doubling_the_prefix(mocker: Any) -> None:
    """The absolute URL the modules request for a token.

    The prefix lives at the end of base_url, and TOKEN_PATH sits inside it. A
    TOKEN_PATH that also carried /api/v2 produced
    https://api.tailscale.com/api/v2/api/v2/oauth/token, which 404s, so every
    documented OAuth example failed. The constant was previously asserted
    against itself, which is why that survived.
    """
    seen: list[str] = []

    def record(
        url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        seen.append(url)
        return Answer(200, '{"access_token":"t"}')

    mocker.patch.object(_api, "open_url", record)
    post_form(BASE, TOKEN_PATH, {"grant_type": "client_credentials"})

    assert seen == ["https://api.tailscale.com/api/v2/oauth/token"]
    assert "/api/v2/api/v2" not in seen[0]


def test_a_dropped_connection_on_a_read_is_retried(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    """A blip is the failure a read actually hits, and the retry rule is unchanged.

    The argument for not retrying applies to a write that may or may not have
    landed. A read that never reached the server changed nothing, so one retry
    is free and the operator never sees it.
    """
    attempts = []

    def drop_then_answer(*args: Any, **kwargs: Any) -> Any:
        attempts.append(1)
        if len(attempts) == 1:
            raise URLError("connection reset by peer")
        return Answer(200, "{}")

    mocker.patch.object(_api, "open_url", drop_then_answer)

    assert client.call("policy_get", "GET").status == 200
    assert len(attempts) == 2
    assert slept == [_api.DEFAULT_RETRY_AFTER_SECONDS]


def dropping(failure: BaseException) -> Any:
    """A transport that never answers, standing in for a socket-level failure.

    The argument is the exception rather than a message, because the common blips
    are several different types and catching only one of them is what left the
    others reaching the operator as a traceback.
    """

    def drop(*args: Any, **kwargs: Any) -> Any:
        raise failure

    return drop


#: A refused connection, a name that does not resolve, a refused TLS handshake.
#: All three arrive as URLError, which is a subclass of OSError.
CONNECT_REFUSED = URLError("connection refused")

#: Accepted, then closed before the response. `urllib` only wraps the request, so
#: this arrives from getresponse() and is neither URLError nor HTTPError.
RESET_MID_RESPONSE = ConnectionResetError("Connection reset by peer")

#: The body stopped before it was complete.
TRUNCATED_BODY = IncompleteRead(b'{"acls"', 12)

#: Headers or body arrived too slowly.
READ_TIMEOUT = TimeoutError("timed out")

BLIPS = [CONNECT_REFUSED, RESET_MID_RESPONSE, TRUNCATED_BODY, READ_TIMEOUT]
BLIP_IDS = ["refused", "reset", "truncated", "timeout"]


@pytest.mark.parametrize("failure", BLIPS, ids=BLIP_IDS)
def test_every_transport_failure_is_caught_not_only_urlliberror(
    client: Api, mocker: Any, slept: list[float], failure: BaseException
) -> None:
    """`issubclass` is the whole question, and the answer is no for three of them.

    Asserted rather than left implicit because the set is the fix: catching
    `URLError` alone reads as correct and silently misses a reset, a truncated
    body and a read timeout, which are what a real blip produces.
    """
    assert isinstance(failure, _api.TRANSPORT_ERRORS), (
        f"{type(failure).__name__} is what this fixes; it must be in TRANSPORT_ERRORS"
    )

    mocker.patch.object(_api, "open_url", dropping(failure))

    with pytest.raises(TailscaleUnreachable):
        client.call("policy_get", "GET")


@pytest.mark.parametrize("failure", BLIPS[1:], ids=BLIP_IDS[1:])
def test_a_response_side_failure_is_retried_on_a_read(
    client: Api, mocker: Any, slept: list[float], failure: BaseException
) -> None:
    attempts = []

    def fail_then_answer(*args: Any, **kwargs: Any) -> Any:
        attempts.append(1)
        if len(attempts) == 1:
            raise failure
        return Answer(200, "{}")

    mocker.patch.object(_api, "open_url", fail_then_answer)

    assert client.call("policy_get", "GET").status == 200
    assert len(attempts) == 2, "a read that never arrived changed nothing, so it is retried"


def test_a_response_side_failure_on_a_write_is_never_retried(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    attempts = []

    def fail(*args: Any, **kwargs: Any) -> Any:
        attempts.append(1)
        raise RESET_MID_RESPONSE

    mocker.patch.object(_api, "open_url", fail)

    with pytest.raises(TailscaleUnreachable):
        client.call("policy_set", "POST", body="{}")

    assert len(attempts) == 1, "a write that lost its answer may already have been applied"


def test_a_lost_write_answer_does_not_claim_nothing_changed(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    """Telling the operator nothing changed is the one claim this cannot make.

    The write may have been applied before the answer was lost, so the message has
    to send the operator back to the tailnet. For a policy write it is the
    dangerous direction: they would conclude the old policy is still live.
    """
    mocker.patch.object(_api, "open_url", dropping(RESET_MID_RESPONSE))

    with pytest.raises(TailscaleUnreachable) as caught:
        client.call("policy_set", "POST", body="{}")

    message = caught.value.message
    assert "may have been applied" in message
    assert "re-read" in message, "the operator needs a next step, not only a cause"
    assert "nothing was changed" not in message


def test_a_lost_read_answer_may_safely_claim_nothing_changed(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    mocker.patch.object(_api, "open_url", dropping(RESET_MID_RESPONSE))

    with pytest.raises(TailscaleUnreachable) as caught:
        client.call("policy_get", "GET")

    assert "nothing was read and nothing was changed" in caught.value.message
    assert "may have been applied" not in caught.value.message


def test_a_dropped_connection_is_not_retried_forever(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    mocker.patch.object(_api, "open_url", dropping(URLError("connection reset by peer")))

    with pytest.raises(TailscaleUnreachable):
        client.call("policy_get", "GET")

    assert len(slept) == _api.RATE_LIMIT_RETRIES, "the budget is the same one as for a 429"


def test_a_dropped_connection_on_a_write_is_never_retried(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    """A write that lost its answer may still have been applied."""
    attempts = []

    def drop(*args: Any, **kwargs: Any) -> Any:
        attempts.append(1)
        raise URLError("connection reset by peer")

    mocker.patch.object(_api, "open_url", drop)

    with pytest.raises(TailscaleUnreachable):
        client.call("policy_set", "POST", body="{}")

    assert len(attempts) == 1, "a write is attempted exactly once"
    assert slept == [], "and is not even waited on"


def test_an_unreachable_api_is_not_reported_as_a_refusal(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    """A traceback in place of a message is how this reached the operator before."""
    mocker.patch.object(_api, "open_url", dropping(URLError("Name or service not known")))

    with pytest.raises(TailscaleUnreachable) as caught:
        client.call("policy_get", "GET")

    failure = caught.value
    assert failure.status == NO_STATUS, "no status arrived, and none is invented"
    assert failure.request_id is None
    assert "no answer arrived" in failure.message
    assert "Name or service not known" in failure.message, "the socket reason is the useful part"


def test_a_credential_in_a_socket_error_is_stripped(
    client: Api, mocker: Any, slept: list[float]
) -> None:
    mocker.patch.object(
        _api, "open_url", dropping(URLError(f"failed: Authorization: Bearer {TOKEN}"))
    )

    with pytest.raises(TailscaleUnreachable) as caught:
        client.call("policy_get", "GET")

    assert TOKEN not in str(caught.value)


def _recording_client() -> tuple[Any, list[str]]:
    """A client whose transport records the URL it was asked for and answers 200.

    The transport is passed in rather than patched, because `Api` binds its default
    at import: patching the module attribute afterwards changes nothing.
    """
    seen: list[str] = []

    def record(method: str, url: str, data: Any, headers: Any, **k: Any) -> Any:
        seen.append(url)
        return _api.RawResponse(status=200, text="{}", headers={})

    options = ApiOptions(base_url=BASE, tailnet="-")
    client = Api(options, Authoriser(from_options(api_token=TOKEN)), record)
    return client, seen


def _refusing_client() -> Any:
    """A client whose transport answers 400, the way `open_transport` hands one back.

    A transport that raises an HTTPError would be read as a request that never
    arrived, because turning a raised error into a response is `open_transport`'s
    job rather than the client's.
    """

    def refuse(*args: Any, **kwargs: Any) -> Any:
        return _api.RawResponse(status=400, text='{"message":"bad filter"}', headers={})

    options = ApiOptions(base_url=BASE, tailnet="-")
    return Api(options, Authoriser(from_options(api_token=TOKEN)), refuse)


def test_a_query_string_is_appended_to_the_operation_path() -> None:
    client, seen = _recording_client()

    client.call("logging_network_get", "GET", query={"start": "2026-09-27T10:45:46Z"})

    assert seen == [f"{BASE}/tailnet/-/logging/network?start=2026-09-27T10%3A45%3A46Z"]


def test_a_sequence_value_is_repeated_under_its_own_name() -> None:
    """The API reads each occurrence as one element, and a joined value filters nothing."""
    client, seen = _recording_client()

    client.call(
        "logging_configuration_get",
        "GET",
        query={"start": "a", "end": "b", "event": ["API_KEY.CREATE", "API_KEY.REVOKE"]},
    )

    assert "event=API_KEY.CREATE&event=API_KEY.REVOKE" in seen[0]


def test_a_value_is_percent_encoded_rather_than_concatenated() -> None:
    """A `+` in a query string means a space, and an RFC 3339 offset is full of them."""
    client, seen = _recording_client()

    client.call("logging_configuration_get", "GET", query={"start": "2026-09-27T10:45:46+02:00"})

    assert "%2B02%3A00" in seen[0]
    assert "+02:00" not in seen[0], "a raw plus here would arrive as a space"


def test_no_filters_produce_no_query_string() -> None:
    client, seen = _recording_client()

    client.call("logging_network_get", "GET", query={})
    client.call("logging_network_get", "GET", query={"start": "a", "event": []})

    assert seen == [
        f"{BASE}/tailnet/-/logging/network",
        f"{BASE}/tailnet/-/logging/network?start=a",
    ]


def test_a_failure_reports_the_operation_and_not_the_filters() -> None:
    """A filter can hold a user address, and a request line in a message outlives the run."""
    with pytest.raises(TailscaleBadRequest) as caught:
        _refusing_client().call(
            "logging_configuration_get",
            "GET",
            query={"start": "a", "end": "b", "actor": ["someone@example.com"]},
        )

    assert caught.value.path == "/tailnet/-/logging/configuration"
    assert "someone@example.com" not in str(caught.value)
