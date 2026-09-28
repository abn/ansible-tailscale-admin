# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the tailscale_service_info module, driven through the harness.

The same contract as every read in the collection: no change is ever reported, the
API's own documents are returned unaltered, and a response that is not a Service
list is refused rather than reported as an empty tailnet.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.modules import tailscale_service_info

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"

SERVICES: list[dict[str, Any]] = [
    {
        "name": "svc:web",
        "displayName": "Web front end",
        "addrs": ["100.93.49.180", "fd7a:115c:a1e0::3456:3cb4"],
        "ports": ["tcp:443"],
        "tags": ["tag:web"],
    },
    {
        "name": "svc:lab",
        "addrs": ["100.93.49.181", "fd7a:115c:a1e0::3456:3cb5"],
        "ports": ["tcp:80"],
    },
]


class Body:
    def __init__(self, text: str) -> None:
        self._text = text

    def decode(self, *args: str) -> str:
        return self._text


def _reply(status: int, text: str) -> Any:
    """What open_url answers with: one object, not a pair."""

    class Response:
        def __init__(self) -> None:
            self.status = status
            self.headers: dict = {}

        def read(self) -> Body:
            return Body(text)

    return Response()


class Tailnet:
    """Answers the Service list from a canned document, or from anything else."""

    def __init__(self, document: Any = None) -> None:
        self.document = document if document is not None else {"vipServices": SERVICES}
        self.requests: list[str] = []

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        self.requests.append(f"{method} {url}")
        if isinstance(self.document, tuple):
            return _reply(self.document[0], self.document[1])
        return _reply(200, json.dumps(self.document))


@pytest.fixture
def server(mocker: Any) -> Any:
    tailnet = Tailnet()
    mocker.patch(_API_URL, tailnet)
    return tailnet


def test_every_service_is_returned_unaltered(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    module_args({"api_token": TOKEN})

    with module_result.success() as result:
        tailscale_service_info.main()

    assert result["changed"] is False
    assert result["services"] == SERVICES
    assert server.requests == ["GET https://api.tailscale.com/api/v2/tailnet/-/services"]


def test_a_tailnet_with_no_services_is_an_empty_list(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    mocker.patch(_API_URL, Tailnet({"vipServices": []}))
    module_args({"api_token": TOKEN})

    with module_result.success() as result:
        tailscale_service_info.main()

    assert result["changed"] is False
    assert result["services"] == []


def test_a_response_that_is_not_a_service_list_is_refused(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    mocker.patch(_API_URL, Tailnet({"message": "a proxy answered this"}))
    module_args({"api_token": TOKEN})

    with module_result.failure() as result:
        tailscale_service_info.main()

    assert "Service list" in result["msg"]
    assert "Traceback" not in result["msg"]
