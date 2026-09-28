# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the tailscale_logs module, driven through the harness.

A read is not a resource, so almost everything here is about what the module
refuses to claim. It must never report a change, it must not reconcile two
windows, and it must not report an empty window when the response was not a log
document at all.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.modules import tailscale_logs

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
BASE = "https://api.tailscale.com/api/v2"

WINDOW = {"start": "2026-09-27T10:45:46Z", "end": "2026-09-27T10:45:48Z"}

_AUDIT_ENTRY = {
    "eventTime": "2026-09-27T10:45:46.89873924Z",
    "type": "CONFIG",
    "origin": "CONFIG_API",
    "action": "CREATE",
    "actor": {"id": "kABCD123456CNTRL", "type": "OAUTH_CLIENT"},
    "target": {"id": "kEFGH789012CNTRL", "type": "API_KEY"},
}

_FLOW_ENTRY = {
    "logged": "2026-09-27T10:45:46.583893Z",
    "nodeId": "nBLYviWLGB21DEVEL",
    "virtualTraffic": [{"proto": "ipv4", "src": "100.64.0.1:1", "dst": "1.1.1.1:443"}],
}

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"


class Body:
    def __init__(self, text: str) -> None:
        self._text = text

    def decode(self, *args: str) -> str:
        return self._text


def _reply(status: int, text: str, headers: dict | None = None) -> Any:
    """What open_url answers with: one object, not a pair."""

    class Response:
        def __init__(self) -> None:
            self.status = status
            self.headers = headers if headers is not None else {}

        def read(self) -> Body:
            return Body(text)

    return Response()


class Tailnet:
    """A tailnet that answers the two log reads from canned documents."""

    def __init__(self, audit: Any = None, flow: Any = None) -> None:
        self.audit = audit if audit is not None else {"version": "1.1", "logs": [_AUDIT_ENTRY]}
        self.flow = flow if flow is not None else {"logs": [_FLOW_ENTRY]}
        self.requests: list[str] = []

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        self.requests.append(f"{method} {url}")
        if "/logging/network" in url:
            return _answer(self.flow)
        return _answer(self.audit)


def _answer(document: Any) -> Any:
    if isinstance(document, tuple):
        return _reply(document[0], document[1])
    return _reply(200, json.dumps(document))


@pytest.fixture
def server(mocker: Any) -> Any:
    tailnet = Tailnet()
    mocker.patch(_API_URL, tailnet)
    return tailnet


def _options(**extra: Any) -> dict[str, Any]:
    return {"api_token": TOKEN, "log_type": "configuration", **WINDOW, **extra}


def test_a_window_is_read_and_its_entries_returned(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options())

    with module_result.success() as result:
        tailscale_logs.main()

    assert result["logs"] == [_AUDIT_ENTRY]
    assert result["log_count"] == 1
    assert result["log_version"] == "1.1"
    assert result["window"] == WINDOW


def test_a_read_reports_no_change_and_no_diff(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """A read has nothing to reconcile, so there is no before and after to show."""
    module_args(_options())

    with module_result.success() as result:
        tailscale_logs.main()

    assert result["changed"] is False
    assert "diff" not in result, "a diff over two windows of log entries would be noise"


def test_the_window_travels_as_query_parameters(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options())

    with module_result.success():
        tailscale_logs.main()

    assert server.requests == [
        f"GET {BASE}/tailnet/-/logging/configuration"
        f"?start=2026-09-27T10%3A45%3A46Z&end=2026-09-27T10%3A45%3A48Z"
    ]


def test_the_log_type_chooses_the_endpoint(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """Two endpoints with two scopes, so the option selects rather than filters."""
    module_args(_options(log_type="network"))

    with module_result.success() as result:
        tailscale_logs.main()

    assert server.requests[0].startswith(f"GET {BASE}/tailnet/-/logging/network?")
    assert result["logs"] == [_FLOW_ENTRY]
    assert result["log_version"] == "", "the flow log response carries no version field"


def test_a_positive_offset_is_percent_encoded(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """A `+` in a query string means a space, so the API would see a value nobody wrote.

    Measured against the real API: `2026-09-27T10:45:46+02:00` sent unencoded
    arrives as `2026-09-27T10:45:46 02:00` and is refused naming the mangled
    value, which is the hardest kind of API error to read back to its cause.
    """
    module_args(_options(start="2026-09-27T10:45:46+02:00"))

    with module_result.success():
        tailscale_logs.main()

    assert "%2B02%3A00" in server.requests[0]
    assert "+02:00" not in server.requests[0]


def test_a_filter_is_repeated_under_its_own_name(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """The API reads each occurrence as one element, so a joined value filters nothing."""
    module_args(_options(event=["API_KEY.CREATE", "API_KEY.REVOKE"]))

    with module_result.success():
        tailscale_logs.main()

    request = server.requests[0]
    assert "event=API_KEY.CREATE" in request
    assert "event=API_KEY.REVOKE" in request
    assert "%5B" not in request, "the list must not be rendered as its own repr"


def test_every_filter_reaches_the_query(module_args: Any, module_result: Any, server: Any) -> None:
    module_args(_options(actor=["~alice", "u1CNTRL"], target=["API_KEY"]))

    with module_result.success():
        tailscale_logs.main()

    request = server.requests[0]
    assert "actor=~alice" in request
    assert "actor=u1CNTRL" in request
    assert "target=API_KEY" in request


def test_no_filter_is_sent_when_none_was_asked_for(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options(actor=[], event=[]))

    with module_result.success():
        tailscale_logs.main()

    assert "actor" not in server.requests[0]
    assert "event" not in server.requests[0]


def test_a_window_with_no_entries_is_an_empty_list(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """The API answers a null list rather than an empty one, measured."""
    mocker.patch(_API_URL, Tailnet(audit={"version": "1.1", "logs": None}))
    module_args(_options())

    with module_result.success() as result:
        tailscale_logs.main()

    assert result["logs"] == []
    assert result["log_count"] == 0


def test_a_response_that_is_not_a_log_document_fails(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """Reporting an empty window here would be a claim about the tailnet, not a reading."""
    mocker.patch(_API_URL, Tailnet(audit="<html>gateway timeout</html>"))
    module_args(_options())

    with module_result.failure() as result:
        tailscale_logs.main()

    assert "other than a JSON object" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_logs_field_that_is_not_a_list_fails(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    mocker.patch(_API_URL, Tailnet(audit={"version": "1.1", "logs": {"one": 1}}))
    module_args(_options())

    with module_result.failure() as result:
        tailscale_logs.main()

    assert "not a list" in result["msg"]


@pytest.mark.parametrize("option", ["start", "end"])
def test_a_value_that_is_not_a_timestamp_is_refused_before_any_request(
    module_args: Any, module_result: Any, server: Any, option: str
) -> None:
    module_args(_options(**{option: "2026-09-27"}))

    with module_result.failure() as result:
        tailscale_logs.main()

    assert option in result["msg"]
    assert "RFC 3339" in result["msg"]
    assert server.requests == [], "and it cost no request"


def test_a_bare_date_is_refused_rather_than_sent(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """The commonest mistake, and one the API would refuse with a round trip."""
    module_args(_options(start="yesterday"))

    with module_result.failure() as result:
        tailscale_logs.main()

    assert "start" in result["msg"]
    assert server.requests == []


def test_a_timestamp_the_api_owns_the_judgement_of_is_sent(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """A missing offset is not caught here: the API's parser is the authority on it."""
    module_args(_options(start="2026-09-27T10:45:46"))

    with module_result.success():
        tailscale_logs.main()

    assert len(server.requests) == 1


@pytest.mark.parametrize("option", ["actor", "target", "event"])
def test_a_filter_on_a_flow_log_is_refused_rather_than_ignored(
    module_args: Any, module_result: Any, server: Any, option: str
) -> None:
    """The API takes a parameter it has no meaning for without complaining."""
    module_args(_options(log_type="network", **{option: ["anything"]}))

    with module_result.failure() as result:
        tailscale_logs.main()

    assert option in result["msg"]
    assert "configuration" in result["msg"]
    assert server.requests == []


def test_a_missing_credential_fails_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"log_type": "configuration", **WINDOW})

    with module_result.failure() as result:
        tailscale_logs.main()

    assert "api_token" in result["msg"]
    assert server.requests == []


def test_a_credential_never_reaches_the_result(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options())

    with module_result.success() as result:
        tailscale_logs.main()

    assert TOKEN not in json.dumps(result, default=str)


def test_a_plan_refusal_reaches_the_operator_as_a_billing_answer(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """The API answers a plan refusal with the status it uses for a missing scope."""
    mocker.patch(
        _API_URL,
        Tailnet(flow=(403, '{"message":"feature not available on current billing plan"}')),
    )
    module_args(_options(log_type="network"))

    with module_result.failure() as result:
        tailscale_logs.main()

    message = result["msg"]
    assert "feature not available on current billing plan" in message
    assert "scope" not in message, "telling the operator to widen a scope it already holds"
    assert TOKEN not in message
    assert "Traceback" not in message


def test_a_missing_window_the_api_names_reaches_the_operator(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    mocker.patch(
        _API_URL,
        Tailnet(audit=(400, '{"message":"must specify an \\"end\\" query"}')),
    )
    module_args(_options())

    with module_result.failure() as result:
        tailscale_logs.main()

    assert 'must specify an "end" query' in result["msg"]


def test_a_tailnet_is_addressed_by_name_when_given(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options(tailnet="-1234567890123"))

    with module_result.success():
        tailscale_logs.main()

    assert server.requests[0].startswith(f"GET {BASE}/tailnet/-1234567890123/logging/configuration")
