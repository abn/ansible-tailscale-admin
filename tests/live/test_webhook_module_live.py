# SPDX-License-Identifier: GPL-3.0-or-later
"""`tailscale_webhook` against a real tailnet, through the module.

The endpoint URL is the one field a task can be identified by, and the API
validates its shape rather than its reachability: measured, an HTTPS URL is
accepted at creation whatever answers behind it, and only the scheme and the
parse are checked. So the suite points every endpoint at a reserved
documentation host and never calls the test operation, which is what lets it
cover the create, update and delete paths without a listener. Nothing here sends
an event, and no request is made to the endpoint URL.

Three measured facts shape what the suite asserts. The server stores the
subscription list in its own order with duplicates removed, so the second run
below declares the same set in another order and must be quiet. The update
operation replaces the list rather than merging into it. And the provider type is
fixed when the endpoint is created, so a task declaring a different one on an
existing endpoint is refused.

Every endpoint this suite creates carries the run id in its URL and is removed in
a `finally`, so a failed assertion leaves the tailnet as it was.
"""

from __future__ import annotations

import contextlib
import os
import time
from collections.abc import Iterator
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleNotFound,
)
from ansible_collections.abn.tailscale.plugins.modules import tailscale_webhook

pytestmark = pytest.mark.live_smoke

#: The prefix on every endpoint URL this suite creates. The domain is reserved for
#: documentation and answers nothing, which is fine: the API checks the URL's shape
#: and never connects to it at creation.
PREFIX = "https://webhook-live-probe.example.com"

#: The run id, so a concurrent or interrupted run's endpoints are not swept, and a
#: leak is identifiable. The same construction the harness uses for its containers.
RUN = f"{os.getpid()}-{int(time.time()) % 100000}"

#: Distinguishes the endpoints one run creates, so a test never finds another's.
_SEQUENCE = [0]


def _endpoints(api: Api) -> list[dict[str, Any]]:
    """Every webhook endpoint the tailnet holds, empty when it holds none."""
    body = api.call("webhook_list", "GET").body
    if not isinstance(body, dict):
        return []
    webhooks = body.get("webhooks") or []
    return webhooks if isinstance(webhooks, list) else []


def _sweep(api: Api) -> None:
    """Remove every endpoint this run created, by URL prefix."""
    for entry in _endpoints(api):
        url = str(entry.get("endpointUrl", ""))
        if url.startswith(f"{PREFIX}/{RUN}/"):
            with contextlib.suppress(TailscaleNotFound):
                api.call("webhook_delete", "DELETE", params={"endpointId": entry["endpointId"]})


@pytest.fixture
def probe_url(api: Api) -> Iterator[str]:
    """A URL unique to one test, with this run's endpoints removed afterwards.

    The URL is a fresh one rather than a fixed name because a webhook is addressed
    by it and the server refuses a second endpoint on a URL with a 500, so a leaked
    endpoint from an interrupted run must not turn the next run into that failure.
    """
    _SEQUENCE[0] += 1
    url = f"{PREFIX}/{RUN}/{_SEQUENCE[0]}"
    try:
        yield url
    finally:
        _sweep(api)


def _run(
    module_args: Any, module_result: Any, options: dict[str, Any], **flags: Any
) -> dict[str, Any]:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_webhook.main()
    return dict(result)


def test_a_new_endpoint_is_created_and_read_back(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api, probe_url: str
) -> None:
    result = _run(
        module_args,
        module_result,
        {
            **credentials,
            "endpoint_url": probe_url,
            "provider_type": "slack",
            "subscriptions": ["nodeCreated", "userDeleted"],
        },
    )

    assert result["changed"] is True
    assert result["secret"], "the create response carries the signing secret"
    endpoint_id = result["webhook"]["endpointId"]

    stored = api.call("webhook_get", "GET", params={"endpointId": endpoint_id}).body
    assert stored["endpointUrl"] == probe_url
    assert stored["providerType"] == "slack"
    assert set(stored["subscriptions"]) == {"nodeCreated", "userDeleted"}
    assert "secret" not in stored, "the secret is not returned by a later read"


def test_a_second_run_over_the_same_set_in_another_order_is_quiet(
    credentials: dict[str, str], module_args: Any, module_result: Any, probe_url: str
) -> None:
    """The server reorders the subscription list, and the order is not state."""
    first = {
        **credentials,
        "endpoint_url": probe_url,
        "subscriptions": ["nodeCreated", "userDeleted"],
    }
    # The server returns the set sorted, so this run declares the reverse of that
    # order: a module comparing the declared list against the returned one reports
    # a change here, and one comparing sets does not.
    second = {
        **credentials,
        "endpoint_url": probe_url,
        "subscriptions": ["userDeleted", "nodeCreated"],
    }

    created = _run(module_args, module_result, first)
    again = _run(module_args, module_result, second)

    assert created["changed"] is True
    assert again["changed"] is False, (
        "the server returns the events in its own order, so the same set is satisfied"
    )
    assert again["secret"] is None, "a run that created nothing reports no secret"


def test_changing_subscriptions_replaces_the_list(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api, probe_url: str
) -> None:
    created = _run(
        module_args,
        module_result,
        {**credentials, "endpoint_url": probe_url, "subscriptions": ["nodeCreated", "userDeleted"]},
    )
    endpoint_id = created["webhook"]["endpointId"]

    updated = _run(
        module_args,
        module_result,
        {**credentials, "endpoint_url": probe_url, "subscriptions": ["policyUpdate"]},
    )

    assert updated["changed"] is True
    stored = api.call("webhook_get", "GET", params={"endpointId": endpoint_id}).body
    assert stored["subscriptions"] == ["policyUpdate"], "the list is replaced, not merged"


def test_a_provider_type_change_is_refused(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api, probe_url: str
) -> None:
    created = _run(
        module_args,
        module_result,
        {
            **credentials,
            "endpoint_url": probe_url,
            "provider_type": "slack",
            "subscriptions": ["nodeCreated"],
        },
    )
    before = api.call(
        "webhook_get", "GET", params={"endpointId": created["webhook"]["endpointId"]}
    ).body

    module_args(
        {
            **credentials,
            "endpoint_url": probe_url,
            "provider_type": "discord",
            "subscriptions": ["nodeCreated"],
        }
    )
    with module_result.failure() as result:
        tailscale_webhook.main()

    assert "provider type" in result["msg"]
    assert "Traceback" not in result["msg"]
    after = api.call(
        "webhook_get", "GET", params={"endpointId": created["webhook"]["endpointId"]}
    ).body
    assert after == before, "and the endpoint was not touched"


def test_removing_an_endpoint_removes_it_and_a_second_run_is_quiet(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api, probe_url: str
) -> None:
    _run(
        module_args,
        module_result,
        {**credentials, "endpoint_url": probe_url, "subscriptions": ["nodeCreated"]},
    )
    gone = {**credentials, "endpoint_url": probe_url, "state": "absent"}

    removed = _run(module_args, module_result, gone)
    again = _run(module_args, module_result, gone)

    assert removed["changed"] is True
    assert again["changed"] is False
    assert [e for e in _endpoints(api) if e.get("endpointUrl") == probe_url] == []


def test_check_mode_creates_nothing(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api, probe_url: str
) -> None:
    result = _run(
        module_args,
        module_result,
        {**credentials, "endpoint_url": probe_url, "subscriptions": ["nodeCreated"]},
        check_mode=True,
    )

    assert result["changed"] is True
    assert result["secret"] is None
    assert [e for e in _endpoints(api) if e.get("endpointUrl") == probe_url] == []


def test_check_mode_reports_a_subscription_change_without_writing(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api, probe_url: str
) -> None:
    created = _run(
        module_args,
        module_result,
        {**credentials, "endpoint_url": probe_url, "subscriptions": ["nodeCreated"]},
    )

    result = _run(
        module_args,
        module_result,
        {**credentials, "endpoint_url": probe_url, "subscriptions": ["userCreated"]},
        check_mode=True,
    )

    assert result["changed"] is True
    stored = api.call(
        "webhook_get", "GET", params={"endpointId": created["webhook"]["endpointId"]}
    ).body
    assert stored["subscriptions"] == ["nodeCreated"], "and nothing was written"


def test_a_url_that_is_not_https_is_refused_without_a_request(
    credentials: dict[str, str], module_args: Any, module_result: Any, probe_url: str
) -> None:
    module_args(
        {**credentials, "endpoint_url": "http://example.com/hook", "subscriptions": ["nodeCreated"]}
    )
    with module_result.failure() as result:
        tailscale_webhook.main()

    assert "HTTPS" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_an_empty_subscription_list_is_refused(
    credentials: dict[str, str], module_args: Any, module_result: Any, probe_url: str
) -> None:
    module_args({**credentials, "endpoint_url": probe_url, "subscriptions": []})
    with module_result.failure() as result:
        tailscale_webhook.main()

    assert "subscribed to nothing" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_an_invalid_event_name_is_refused_before_a_request(
    credentials: dict[str, str], module_args: Any, module_result: Any, probe_url: str
) -> None:
    module_args({**credentials, "endpoint_url": probe_url, "subscriptions": ["notAnEvent"]})
    with module_result.failure() as result:
        tailscale_webhook.main()

    assert "notAnEvent" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_refused_credential_reaches_the_operator_without_echoing_it(
    credentials: dict[str, str], module_args: Any, module_result: Any, probe_url: str
) -> None:
    module_args(
        {
            **credentials,
            "oauth_client_secret": "not-the-secret",
            "endpoint_url": probe_url,
            "subscriptions": ["nodeCreated"],
        }
    )
    with module_result.failure() as result:
        tailscale_webhook.main()

    message = result["msg"]
    assert "401" in message
    assert "Traceback" not in message
    assert "not-the-secret" not in message
    assert credentials["oauth_client_id"] not in message
