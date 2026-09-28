# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the tailscale_log_streaming module, driven through the harness.

The write replaces the whole destination, so the property that matters is that an
option the task left out is carried over rather than reset, and that a second run
over the same task finds nothing to do. Both are asserted against a double that
behaves the way the real endpoint is documented to, including filling in fields of
its own, because that is the behaviour that would otherwise report a change for
ever.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.modules import tailscale_log_streaming

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
BASE = "https://api.tailscale.com/api/v2"

SECRET = "the-destination-token"

STORED = {
    "logType": "configuration",
    "destinationType": "elastic",
    "url": "https://logs.example.com:8080/config",
    "user": "ansible",
    "compressionFormat": "zstd",
    "uploadPeriodMinutes": 5,
}

#: The same document as the write is allowed to carry. `logType` is the field the
#: API sets for itself, and sending it back is what a whole-document write does by
#: default.
STORED_WITHOUT_READ_ONLY = {field: value for field, value in STORED.items() if field != "logType"}

STATUS = {
    "lastActivity": "2026-09-27T10:45:46Z",
    "lastError": "",
    "numEntriesSent": 8363,
    "numFailedRequests": 0,
}

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"


class Body:
    def __init__(self, text: str) -> None:
        self._text = text

    def decode(self, *args: str) -> str:
        return self._text


def _reply(status: int, text: str) -> Any:
    class Response:
        def __init__(self) -> None:
            self.status = status
            self.headers: dict = {}

        def read(self) -> Body:
            return Body(text)

    return Response()


class Tailnet:
    """A tailnet with one streaming destination, or none, per log type."""

    def __init__(
        self,
        stored: dict | None = None,
        *,
        status: dict | None = None,
        refuse: tuple[int, str] | None = None,
    ) -> None:
        self.destinations: dict[str, dict] = {"configuration": dict(stored)} if stored else {}
        self.status = STATUS if status is None else status
        self.refuse = refuse
        self.writes: list[dict] = []
        self.requests: list[str] = []
        self.deleted: list[str] = []

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        self.requests.append(f"{method} {url}")
        if self.refuse is not None:
            return _reply(self.refuse[0], self.refuse[1])
        log_type = _log_type_of(url)
        destination = self.destinations.get(log_type)

        if url.endswith("/status"):
            return (
                _reply(404, '{"message":"not configured"}')
                if destination is None
                else _reply(200, json.dumps(self.status))
            )
        if method == "GET":
            if destination is None:
                return _reply(404, '{"message":"log streaming has not been configured"}')
            return _reply(200, json.dumps(destination))
        if method == "PUT":
            self.writes.append(json.loads(str(data)))
            self.destinations[log_type] = self.stored_after(json.loads(str(data)))
            return _reply(200, "{}")
        if method == "DELETE":
            self.deleted.append(log_type)
            self.destinations.pop(log_type, None)
            return _reply(200, "{}")
        return _reply(404, '{"message":"not found"}')

    def stored_after(self, sent: dict) -> dict:
        """What the server keeps, which is the sent document plus what it sets itself.

        The endpoint is a replace rather than a merge, so the stored document is
        the body that was sent. `logType` is added because the description marks it
        read-only, which is how a server says it fills a field in for itself, and
        a field appearing out of nowhere is exactly what would make a naive
        comparison report a change for ever.
        """
        return {"logType": "configuration", **sent}


def _log_type_of(url: str) -> str:
    return url.split("/logging/")[1].split("/")[0]


@pytest.fixture
def server(mocker: Any) -> Any:
    tailnet = Tailnet(STORED)
    mocker.patch(_API_URL, tailnet)
    return tailnet


@pytest.fixture
def bare(mocker: Any) -> Any:
    tailnet = Tailnet()
    mocker.patch(_API_URL, tailnet)
    return tailnet


def _options(**extra: Any) -> dict[str, Any]:
    return {
        "api_token": TOKEN,
        "log_type": "configuration",
        "destination_type": "elastic",
        "url": "https://logs.example.com:8080/config",
        "user": "ansible",
        "compression_format": "zstd",
        "upload_period_minutes": 5,
        **extra,
    }


def test_the_credential_options_are_marked_no_log() -> None:
    """A `no_log` that is dropped is a leak Ansible can no longer redact.

    Asserted on the spec rather than on a result, because the module keeps the
    values out of the result by itself: a projection that omits them and a diff
    that shows a placeholder would survive `no_log` being removed, and the value
    would then reach the task output and every transcript of the invocation.
    """
    spec = tailscale_log_streaming.ARGUMENT_SPEC

    assert spec["token"]["no_log"] is True
    assert spec["s3_secret_access_key"]["no_log"] is True
    assert spec["s3_key_prefix"]["no_log"] is False, "a key prefix is a path, not a credential"


def test_a_destination_already_in_place_writes_nothing(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options())

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert result["changed"] is False
    assert result["unverified_options"] == []
    assert server.writes == []


def test_the_diff_of_an_unchanged_destination_is_empty(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options())

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert result["diff"]["before"] == result["diff"]["after"]


def test_a_changed_destination_is_written_with_the_whole_document(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options(user="someone-else"))

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert result["changed"] is True
    assert server.writes == [STORED_WITHOUT_READ_ONLY | {"user": "someone-else"}]
    assert result["stream_configuration"]["user"] == "someone-else"


def test_a_field_the_server_fills_in_is_not_a_change_on_the_second_run(
    module_args: Any, module_result: Any, bare: Any
) -> None:
    """The failure a whole-document endpoint invites, and the one this guards."""
    options = _options()

    module_args(options)
    with module_result.success() as first:
        tailscale_log_streaming.main()
    assert first["changed"] is True, "there was a destination to create"

    module_args(options)
    with module_result.success() as second:
        tailscale_log_streaming.main()

    assert second["changed"] is False, (
        f"the tailnet holds {bare.destinations['configuration']!r} and the second run "
        "must recognise it"
    )
    assert len(bare.writes) == 1


def test_an_option_the_task_left_out_is_carried_over(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """The write replaces, so sending a default for an unmentioned field would reset it."""
    module_args(_options(url="https://logs.example.com:8080/other"))

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert server.writes[0]["user"] == "ansible"
    assert result["diff"]["before"]["user"] == "ansible"


def test_a_field_the_api_sets_for_itself_is_not_sent_back(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """`logType` is read-only, so writing it back is a field this collection does not set."""
    module_args(_options(user="someone-else"))

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert "logType" not in server.writes[0]
    assert result["stream_configuration"]["logType"] == "configuration", "but it is still reported"


def test_the_log_type_is_in_the_path_and_not_the_body(
    module_args: Any, module_result: Any, bare: Any
) -> None:
    module_args(_options(log_type="network", destination_type="splunk"))

    with module_result.success():
        tailscale_log_streaming.main()

    assert f"GET {BASE}/tailnet/-/logging/network/stream" in bare.requests
    assert f"PUT {BASE}/tailnet/-/logging/network/stream" in bare.requests
    assert bare.writes[0].get("logType") is None
    assert bare.writes[0]["destinationType"] == "splunk"


def test_a_destination_is_created_where_there_was_none(
    module_args: Any, module_result: Any, bare: Any
) -> None:
    module_args(_options())

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert result["changed"] is True
    assert bare.writes[0]["destinationType"] == "elastic"
    assert "uploadPeriodMinutes" in bare.writes[0]


def test_absent_with_nothing_configured_changes_nothing(
    module_args: Any, module_result: Any, bare: Any
) -> None:
    module_args({"api_token": TOKEN, "log_type": "configuration", "state": "absent"})

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert result["changed"] is False
    assert bare.deleted == []
    assert result["stream_configuration"] == {}


def test_absent_deletes_a_destination(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN, "log_type": "configuration", "state": "absent"})

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert result["changed"] is True
    assert server.deleted == ["configuration"]
    assert result["diff"]["after"] == {}
    assert result["diff"]["before"]["destinationType"] == "elastic"


def test_absent_needs_no_destination_type(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "log_type": "configuration", "state": "absent"})

    with module_result.success():
        tailscale_log_streaming.main()

    assert server.deleted == ["configuration"]


def test_check_mode_reports_the_change_without_writing(
    module_args: Any, module_result: Any, bare: Any
) -> None:
    module_args(_options(user="someone-else"), check_mode=True)

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert result["changed"] is True
    assert bare.writes == [], "and it wrote nothing"
    assert bare.destinations == {}, "so the tailnet is as it was"
    assert result["diff"]["after"]["user"] == "someone-else"


def test_check_mode_over_a_destination_in_place_reports_no_change(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options(), check_mode=True)

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert result["changed"] is False
    assert server.writes == []


def test_the_publishing_status_is_read_and_returned(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options())

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert result["streaming_status"] == STATUS
    assert any(request.endswith("/stream/status") for request in server.requests)


def test_a_status_that_changes_on_its_own_is_not_a_change(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """The status is a moving target. Only the destination is reconciled."""
    options = _options()

    module_args(options)
    with module_result.success() as first:
        tailscale_log_streaming.main()
    server.status = {**STATUS, "numEntriesSent": 9999}

    module_args(options)
    with module_result.success() as second:
        tailscale_log_streaming.main()

    assert first["changed"] is False
    assert second["changed"] is False
    assert second["streaming_status"]["numEntriesSent"] == 9999


def test_a_status_the_api_has_not_got_is_empty(
    module_args: Any, module_result: Any, bare: Any
) -> None:
    """A check run on a tailnet with no destination asks about a status that cannot exist."""
    module_args(_options(), check_mode=True)

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert result["changed"] is True
    assert result["streaming_status"] == {}, "the API's not-found is a state, not a failure"
    assert any(request.endswith("/stream/status") for request in bare.requests)


def test_a_password_is_written_every_run_and_says_so(
    module_args: Any, module_result: Any, bare: Any
) -> None:
    """The API never returns a password, so there is nothing to compare one against."""
    options = _options(token=SECRET)

    module_args(options)
    with module_result.success() as first:
        tailscale_log_streaming.main()
    module_args(options)
    with module_result.success() as second:
        tailscale_log_streaming.main()

    assert first["changed"] is True
    assert second["changed"] is True, "and it says so rather than reporting a false quiet"
    assert second["unverified_options"] == ["token"]
    assert len(bare.writes) == 2, "both runs wrote the same document, which is harmless"
    assert bare.writes[0]["token"] == SECRET


def test_a_password_never_reaches_the_result(
    module_args: Any, module_result: Any, bare: Any
) -> None:
    module_args(_options(token=SECRET))

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert SECRET not in json.dumps(result, default=str)
    assert "token" not in result["stream_configuration"]


def test_the_diff_shows_a_password_as_a_placeholder(
    module_args: Any, module_result: Any, bare: Any
) -> None:
    """A change to a password has to be visible without its value reaching a transcript."""
    module_args(_options(token=SECRET))

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert result["diff"]["after"]["token"] == "(write-only)"
    assert SECRET not in json.dumps(result["diff"])


def test_a_password_a_destination_already_has_is_carried_over(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """The read never returns one, so the write would clear it without this."""
    server.destinations["configuration"]["token"] = SECRET
    module_args(_options(user="someone-else"))

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert server.writes[0]["token"] == SECRET
    assert result["unverified_options"] == []


def test_a_s3_destination_needs_a_bucket_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options(destination_type="s3", url="", s3_region="us-east-1"))

    with module_result.failure() as result:
        tailscale_log_streaming.main()

    assert "s3_bucket" in result["msg"]
    assert server.requests == [], "the API would only refuse it with a round trip"


def test_a_s3_destination_needs_its_authentication_type(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options(destination_type="s3", url="", s3_bucket="logs", s3_region="us-east-1"))

    with module_result.failure() as result:
        tailscale_log_streaming.main()

    assert "s3_authentication_type" in result["msg"]


def test_an_access_key_destination_needs_the_secret(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        _options(
            destination_type="s3",
            url="",
            s3_bucket="logs",
            s3_region="us-east-1",
            s3_authentication_type="accesskey",
            s3_access_key_id="AKIAEXAMPLE",
        )
    )

    with module_result.failure() as result:
        tailscale_log_streaming.main()

    assert "s3_secret_access_key" in result["msg"]


def test_a_role_destination_needs_the_role(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        _options(
            destination_type="s3",
            url="",
            s3_bucket="logs",
            s3_region="us-east-1",
            s3_authentication_type="rolearn",
        )
    )

    with module_result.failure() as result:
        tailscale_log_streaming.main()

    assert "s3_role_arn" in result["msg"]


def test_a_complete_s3_destination_is_written(
    module_args: Any, module_result: Any, bare: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "log_type": "configuration",
            "destination_type": "s3",
            "s3_bucket": "logs",
            "s3_region": "us-east-1",
            "s3_authentication_type": "rolearn",
            "s3_role_arn": "arn:aws:iam::123456789012:role/writer",
        }
    )

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert result["changed"] is True
    assert bare.writes[0]["s3Bucket"] == "logs"
    assert "url" not in bare.writes[0], "an absent url must not be sent as an empty one"


def test_an_upload_period_over_the_maximum_is_refused(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options(upload_period_minutes=1441))

    with module_result.failure() as result:
        tailscale_log_streaming.main()

    assert "1440" in result["msg"]
    assert server.requests == []


def test_a_destination_that_cannot_be_read_is_not_replaced_blind(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """A whole-document write over an unreadable document discards it."""

    def not_a_document(
        url: str, data: Any = None, headers: Any = None, method: str = "GET", **kw: Any
    ) -> Any:
        return _reply(200, "<html>not a document</html>")

    mocker.patch(_API_URL, not_a_document)
    module_args(_options(user="someone-else"))

    with module_result.failure() as result:
        tailscale_log_streaming.main()

    assert "not a JSON object" in result["msg"]


def test_a_plan_refusal_reaches_the_operator_and_writes_nothing(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """The API answers this family with a 403, which it otherwise uses for a scope."""
    writes: list[dict] = []

    def refuse(
        url: str, data: Any = None, headers: Any = None, method: str = "GET", **kw: Any
    ) -> Any:
        if method in ("PUT", "DELETE"):
            writes.append({"method": method, "url": url})
        return _reply(403, '{"message":"feature not available on current billing plan"}')

    mocker.patch(_API_URL, refuse)
    module_args(_options())

    with module_result.failure() as result:
        tailscale_log_streaming.main()

    message = result["msg"]
    assert "feature not available on current billing plan" in message
    assert "scope" not in message
    assert TOKEN not in message
    assert "Traceback" not in message
    assert writes == [], "and nothing was written"


def test_a_missing_credential_fails_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"log_type": "configuration", "state": "absent"})

    with module_result.failure() as result:
        tailscale_log_streaming.main()

    assert "api_token" in result["msg"]
    assert server.requests == []


def test_a_credential_never_reaches_the_result(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options())

    with module_result.success() as result:
        tailscale_log_streaming.main()

    assert TOKEN not in json.dumps(result, default=str)


def test_a_destination_type_is_required_when_present_is_intended(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "log_type": "configuration"})

    with module_result.failure() as result:
        tailscale_log_streaming.main()

    assert "destination_type" in result["msg"]
    assert server.requests == []
