# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the tailscale_webhook module, driven through the harness.

The double below is a model of the endpoints as measured against a real tailnet,
not a stub that accepts anything. Four of its behaviours are the reason this
module is shaped the way it is, and each has a test that fails if the module
forgets it:

* the server stores a subscription list in its own order with duplicates
  removed, so the declared order is not part of the state and the comparison has
  to be by set;
* an update replaces the subscription list rather than merging into it;
* a second endpoint on a URL is refused by the server with a 500, so the module
  has to find an existing endpoint before it creates one;
* the update operation takes the subscription list and nothing else, so a
  provider type change cannot be reconciled and is refused rather than ignored.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.modules import tailscale_webhook

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
BASE = "https://api.tailscale.com/api/v2"
URL = "https://hooks.example.com/tailscale/events"

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"


class Body:
    def __init__(self, text: str) -> None:
        self._text = text

    def decode(self, *args: str) -> str:
        return self._text


def _reply(status: int, text: str) -> Any:
    """What open_url answers with: one object, not a pair."""

    class Response:
        def __init__(self, status: int) -> None:
            self.status = status
            self.headers: dict = {}

        def read(self) -> Body:
            return Body(text)

    return Response(status)


class Tailnet:
    """The webhook endpoints, with the storage rules the real endpoints have.

    Deliberately not permissive. A double that stores the declared order, or that
    merges an update into the list it holds, cannot fail a test that removed the
    set comparison or the replace, and those two are the whole reason the module
    is not a straight field copy.
    """

    def __init__(self, current: list[dict[str, Any]] | None = None) -> None:
        self.endpoints: dict[str, dict[str, Any]] = {}
        self.creates: list[dict] = []
        self.patches: list[dict] = []
        self.deleted: list[str] = []
        self.requests: list[str] = []
        self._next = 1
        for document in current or []:
            endpoint_id = str(document["endpointId"])
            self.endpoints[endpoint_id] = dict(document)

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        path = url[len(BASE) :]
        self.requests.append(f"{method} {path}")
        query = path.partition("?")[0]
        parts = [part for part in query.split("/") if part]

        if method == "GET" and parts[0] == "tailnet" and parts[-1] == "webhooks":
            # An absent `webhooks` key rather than an empty list, as measured.
            listed = sorted(self.endpoints.values(), key=lambda entry: entry["endpointId"])
            return _reply(200, json.dumps({"webhooks": listed or None}))

        if method == "POST" and parts[0] == "tailnet" and parts[-1] == "webhooks":
            body = json.loads(str(data))
            if any(
                entry["endpointUrl"] == body.get("endpointUrl") for entry in self.endpoints.values()
            ):
                # Measured: a second endpoint on a URL is a 500, not a 400.
                return _reply(500, '{"message": "internal error"}')
            endpoint_id = f"w{self._next}CNTRL"
            self._next += 1
            stored = {
                "endpointId": endpoint_id,
                "endpointUrl": body["endpointUrl"],
                "providerType": body.get("providerType") or "",
                "subscriptions": sorted(set(body.get("subscriptions") or [])),
                "creatorLoginName": "creator@example.com",
                "created": "2026-09-27T10:00:00Z",
                "lastModified": "2026-09-27T10:00:00Z",
            }
            self.creates.append(body)
            self.endpoints[endpoint_id] = stored
            # The secret is in the create response only, never in a later read.
            return _reply(200, json.dumps({**stored, "secret": "tskey-webhook-probe-secret"}))

        if len(parts) == 2 and parts[0] == "webhooks":
            endpoint_id = parts[1]
            stored = self.endpoints.get(endpoint_id)
            if stored is None:
                return _reply(404, '{"message": "webhook not found"}')
            if method == "GET":
                return _reply(200, json.dumps(stored))
            if method == "PATCH":
                body = json.loads(str(data))
                wanted = body.get("subscriptions")
                # Measured: only the subscription list is updatable, and an empty
                # one is answered with "no updates requested".
                if not wanted:
                    return _reply(400, '{"message": "no updates requested"}')
                stored["subscriptions"] = sorted(set(wanted))
                self.patches.append(body)
                return _reply(200, json.dumps(stored))
            if method == "DELETE":
                del self.endpoints[endpoint_id]
                self.deleted.append(endpoint_id)
                return _reply(200, "null")

        return _reply(404, '{"message": "not found"}')


@pytest.fixture
def server(mocker: Any) -> Tailnet:
    tailnet = Tailnet()
    mocker.patch(_API_URL, tailnet)
    return tailnet


def _existing(provider: str = "slack", subscriptions: list[str] | None = None) -> Tailnet:
    return Tailnet(
        current=[
            {
                "endpointId": "w111CNTRL",
                "endpointUrl": URL,
                "providerType": provider,
                "subscriptions": subscriptions or ["nodeCreated", "userDeleted"],
                "creatorLoginName": "creator@example.com",
                "created": "2026-09-27T10:00:00Z",
                "lastModified": "2026-09-27T10:00:00Z",
            }
        ]
    )


@pytest.fixture
def existing(mocker: Any) -> Tailnet:
    tailnet = _existing()
    mocker.patch(_API_URL, tailnet)
    return tailnet


def _run(module_args: Any, module_result: Any, options: dict, **flags: Any) -> dict[str, Any]:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_webhook.main()
    return dict(result)


def _create(module_args: Any, module_result: Any, **overrides: Any) -> dict[str, Any]:
    options = {"api_token": TOKEN, "endpoint_url": URL, "subscriptions": ["nodeCreated"]}
    options.update(overrides)
    return _run(module_args, module_result, options)


def test_an_endpoint_that_does_not_exist_is_created(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    result = _create(
        module_args, module_result, provider_type="slack", subscriptions=["policyUpdate"]
    )

    assert result["changed"] is True
    assert server.creates == [
        {
            "endpointUrl": URL,
            "providerType": "slack",
            "subscriptions": ["policyUpdate"],
        }
    ]
    assert result["webhook"]["endpointId"] == "w1CNTRL"
    assert result["webhook"]["providerType"] == "slack"


def test_the_signing_secret_is_returned_only_by_the_run_that_created_the_endpoint(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    options = {"api_token": TOKEN, "endpoint_url": URL, "subscriptions": ["nodeCreated"]}

    first = _run(module_args, module_result, options)
    second = _run(module_args, module_result, options)

    assert first["changed"] is True
    assert first["secret"] == "tskey-webhook-probe-secret"
    assert second["changed"] is False
    assert second["secret"] is None


def test_a_second_run_over_the_same_declaration_is_quiet(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    """The property the whole shape exists for, and the order is not part of it.

    The server stores the subscription list in an order of its own, so a task that
    declares the same set in another order is already satisfied. A module that
    compared the declared list against the returned one would report a change for
    ever, which is the assertion below.
    """
    first = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "endpoint_url": URL, "subscriptions": ["nodeCreated", "userDeleted"]},
    )
    # The second run declares the reverse of the order the server returns, which
    # is the order the server chooses rather than the one the first run sent.
    second = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "endpoint_url": URL, "subscriptions": ["userDeleted", "nodeCreated"]},
    )

    assert first["changed"] is True
    assert second["changed"] is False, f"stored endpoint is {server.endpoints!r}"
    assert len(server.creates) == 1
    assert server.patches == []


def test_duplicate_events_are_not_a_change(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    """The server removes duplicates, so a repeated event converges."""
    first = _create(module_args, module_result, subscriptions=["nodeCreated", "nodeCreated"])
    second = _create(module_args, module_result, subscriptions=["nodeCreated"])

    assert first["changed"] is True
    assert second["changed"] is False
    assert server.patches == []


def test_an_endpoint_already_holding_the_url_is_not_created_again(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    """The lookup by URL is what stops a duplicate, which the server answers 500."""
    result = _create(module_args, module_result, subscriptions=["nodeCreated", "userDeleted"])

    assert result["changed"] is False
    assert existing.creates == []


def test_changing_subscriptions_replaces_the_list(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    """An update carries the whole list, not the difference."""
    result = _create(module_args, module_result, subscriptions=["userCreated"])

    assert result["changed"] is True
    assert existing.patches == [{"subscriptions": ["userCreated"]}]
    assert existing.endpoints["w111CNTRL"]["subscriptions"] == ["userCreated"]
    assert result["webhook"]["subscriptions"] == ["userCreated"]


def test_a_provider_type_change_is_refused(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    """The update endpoint has no field for it, so the two states cannot meet."""
    module_args(
        {
            "api_token": TOKEN,
            "endpoint_url": URL,
            "provider_type": "discord",
            "subscriptions": ["nodeCreated"],
        }
    )

    with module_result.failure() as result:
        tailscale_webhook.main()

    assert "provider type" in result["msg"]
    assert "Remove the endpoint" in result["msg"]
    assert existing.patches == []


def test_a_provider_type_that_already_matches_is_quiet(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    result = _create(
        module_args,
        module_result,
        provider_type="slack",
        subscriptions=["nodeCreated", "userDeleted"],
    )

    assert result["changed"] is False


def test_an_unknown_provider_type_is_refused(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "endpoint_url": URL,
            "provider_type": "slackk",
            "subscriptions": ["nodeCreated"],
        }
    )

    with module_result.failure() as result:
        tailscale_webhook.main()

    assert "slackk" in result["msg"]
    assert "discord" in result["msg"]
    assert server.requests == []


@pytest.mark.parametrize(
    "url", ["hooks.example.com", "http://hooks.example.com/x", "not-a-url", ""]
)
def test_a_url_the_api_would_refuse_is_refused_here(
    module_args: Any, module_result: Any, server: Tailnet, url: str
) -> None:
    module_args({"api_token": TOKEN, "endpoint_url": url, "subscriptions": ["nodeCreated"]})

    with module_result.failure() as result:
        tailscale_webhook.main()

    assert "HTTPS" in result["msg"]
    assert server.requests == [], "a bad URL costs no request"


def test_an_empty_subscription_list_is_refused_with_the_way_out(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    module_args({"api_token": TOKEN, "endpoint_url": URL, "subscriptions": []})

    with module_result.failure() as result:
        tailscale_webhook.main()

    assert "subscribed to nothing" in result["msg"]
    assert server.requests == []


def test_subscriptions_are_required_when_present(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    module_args({"api_token": TOKEN, "endpoint_url": URL})

    with module_result.failure() as result:
        tailscale_webhook.main()

    assert "subscriptions" in result["msg"]
    assert server.requests == []


def test_removing_an_endpoint_deletes_it(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "endpoint_url": URL, "state": "absent"}
    )

    assert result["changed"] is True
    assert existing.deleted == ["w111CNTRL"]
    assert existing.endpoints == {}
    assert result["webhook"] == {}
    assert result["diff"]["before"]["endpointUrl"] == URL
    assert result["diff"]["after"] is None


def test_removing_an_endpoint_that_is_already_gone_is_quiet(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    options = {"api_token": TOKEN, "endpoint_url": URL, "state": "absent"}

    first = _run(module_args, module_result, options)
    second = _run(module_args, module_result, options)

    assert first["changed"] is False
    assert second["changed"] is False
    assert server.deleted == []


def test_check_mode_creates_nothing_and_invents_no_id(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "endpoint_url": URL, "subscriptions": ["nodeCreated"]},
        check_mode=True,
    )

    assert result["changed"] is True
    assert "endpointId" not in result["webhook"]
    assert result["secret"] is None
    assert server.creates == []
    assert server.endpoints == {}


def test_check_mode_reports_a_subscription_change_without_writing(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "endpoint_url": URL, "subscriptions": ["userCreated"]},
        check_mode=True,
    )

    assert result["changed"] is True
    assert result["webhook"]["subscriptions"] == ["userCreated"]
    assert existing.patches == []
    assert existing.endpoints["w111CNTRL"]["subscriptions"] == ["nodeCreated", "userDeleted"]


def test_check_mode_removes_nothing(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "endpoint_url": URL, "state": "absent"},
        check_mode=True,
    )

    assert result["changed"] is True
    assert existing.deleted == []


def test_the_diff_holds_the_endpoint_before_and_after(
    module_args: Any, module_result: Any, existing: Tailnet
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "endpoint_url": URL, "subscriptions": ["userCreated"]},
        diff=True,
    )

    assert result["diff"]["before"]["subscriptions"] == ["nodeCreated", "userDeleted"]
    assert result["diff"]["after"]["subscriptions"] == ["userCreated"]
    assert result["diff"]["before"]["endpointId"] == "w111CNTRL"


def test_a_field_this_module_does_not_manage_cannot_report_a_change(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    tailnet = _existing()
    tailnet.endpoints["w111CNTRL"]["somethingNew"] = {"nested": True}
    mocker.patch(_API_URL, tailnet)

    result = _create(module_args, module_result, subscriptions=["nodeCreated", "userDeleted"])

    assert result["changed"] is False


def test_a_second_endpoint_on_one_url_is_refused_rather_than_chosen(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """The API refuses the duplicate, so the module will not pick one of two."""
    tailnet = _existing()
    tailnet.endpoints["w222CNTRL"] = dict(tailnet.endpoints["w111CNTRL"], endpointId="w222CNTRL")
    mocker.patch(_API_URL, tailnet)

    module_args({"api_token": TOKEN, "endpoint_url": URL, "subscriptions": ["nodeCreated"]})
    with module_result.failure() as result:
        tailscale_webhook.main()

    assert "will not choose" in result["msg"]


def test_a_list_that_is_not_an_object_is_not_read_as_an_empty_tailnet(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """A proxy answering 200 with an error page must not cause a create over it."""

    def html(
        url: str, data: Any = None, headers: Any = None, method: str = "GET", **kw: Any
    ) -> Any:
        return _reply(200, "<html>captive portal</html>")

    mocker.patch(_API_URL, html)
    module_args({"api_token": TOKEN, "endpoint_url": URL, "subscriptions": ["nodeCreated"]})
    with module_result.failure() as result:
        tailscale_webhook.main()

    assert "Nothing was written" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_missing_credential_fails_before_any_request(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    module_args({"endpoint_url": URL, "subscriptions": ["nodeCreated"]})

    with module_result.failure() as result:
        tailscale_webhook.main()

    assert "api_token" in result["msg"]
    assert server.requests == []


def test_a_credential_never_reaches_the_result(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    result = _create(module_args, module_result)

    assert TOKEN not in json.dumps(result, default=str)


def test_a_tailnet_is_addressed_by_name_when_given(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    result = _create(module_args, module_result, tailnet="-1234567890123")

    assert result["changed"] is True
    assert server.requests[0] == "GET /tailnet/-1234567890123/webhooks"
