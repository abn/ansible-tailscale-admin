# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the tailscale_device_info module, driven through the harness.

A read is not a resource, so what matters here is what the module returns and what
it refuses to claim: it must never report a change, and it must not report an empty
tailnet from a response that never listed one.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.modules import tailscale_device_info

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"

DEVICES: list[dict[str, Any]] = [
    {
        "nodeId": "nNIBBLER01CNTRL",
        "id": "111",
        "name": "nibbler.example.ts.net",
        "hostname": "nibbler",
        "addresses": ["100.64.0.5", "fd7a:115c:a1e0::5"],
        "tags": ["tag:lab"],
    },
    {
        "nodeId": "nCANVAS02CNTRL",
        "id": "222",
        "name": "canvas.example.ts.net",
        "hostname": "canvas",
        "addresses": ["100.64.0.6", "fd7a:115c:a1e0::6"],
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
    """Answers the device list from a canned document, or from anything else."""

    def __init__(self, document: Any = None) -> None:
        self.document = document if document is not None else {"devices": DEVICES}
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


def test_every_device_is_returned_unaltered(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    module_args({"api_token": TOKEN})

    with module_result.success() as result:
        tailscale_device_info.main()

    assert result["changed"] is False
    assert result["devices"] == DEVICES
    assert server.requests == ["GET https://api.tailscale.com/api/v2/tailnet/-/devices"]


def test_an_empty_tailnet_is_an_empty_list(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    mocker.patch(_API_URL, Tailnet({"devices": []}))
    module_args({"api_token": TOKEN})

    with module_result.success() as result:
        tailscale_device_info.main()

    assert result["changed"] is False
    assert result["devices"] == []


def test_a_check_run_reads_and_reports_the_same(
    module_args: Any, module_result: Any, server: Tailnet
) -> None:
    """A read has no write for check mode to hold back."""
    module_args({"api_token": TOKEN}, check_mode=True)

    with module_result.success() as result:
        tailscale_device_info.main()

    assert result["changed"] is False
    assert result["devices"] == DEVICES


def test_a_response_that_is_not_a_device_list_is_refused(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """An empty list is a claim about the tailnet, so a malformed body must not make it."""
    mocker.patch(_API_URL, Tailnet({"message": "a proxy answered this"}))
    module_args({"api_token": TOKEN})

    with module_result.failure() as result:
        tailscale_device_info.main()

    assert "device list" in result["msg"]
    assert "Traceback" not in result["msg"]
