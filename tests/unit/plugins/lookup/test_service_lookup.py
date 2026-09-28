# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the ``abn.tailscale.service`` lookup.

Loaded through ``lookup_loader`` for the same reason the device lookup is, so the
option fragment the loader resolves is the one a play would get.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible.errors import AnsibleError
from ansible.plugins.loader import lookup_loader

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"

SERVICES: dict[str, dict[str, Any]] = {
    "svc:web": {
        "name": "svc:web",
        "displayName": "Web front end",
        "comment": "fronted by nginx",
        "addrs": ["100.93.49.180", "fd7a:115c:a1e0::3456:3cb4"],
        "ports": ["tcp:443"],
        "tags": ["tag:web"],
    },
}


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
    """Answers a Service read by name, 404ing for one it does not hold."""

    def __init__(self) -> None:
        self.requests: list[str] = []

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        self.requests.append(f"{method} {url}")
        name = url.rsplit("/", 1)[-1]
        if name in SERVICES:
            return _reply(200, json.dumps(SERVICES[name]))
        return _reply(404, '{"message": "service not found"}')


@pytest.fixture
def server(mocker: Any) -> Tailnet:
    tailnet = Tailnet()
    mocker.patch(_API_URL, tailnet)
    return tailnet


def _run(terms: list[str], **kwargs: Any) -> list[Any]:
    lookup = lookup_loader.get("abn.tailscale.service")
    return lookup.run(terms, variables={}, api_token=TOKEN, **kwargs)


def test_a_service_resolves_to_the_address_by_default(server: Tailnet) -> None:
    assert _run(["svc:web"]) == ["100.93.49.180"]


def test_the_named_property_is_returned(server: Tailnet) -> None:
    assert _run(["svc:web"], want="display_name") == ["Web front end"]
    assert _run(["svc:web"], want="ipv6") == ["fd7a:115c:a1e0::3456:3cb4"]


def test_a_list_property_is_returned_as_a_list(server: Tailnet) -> None:
    assert _run(["svc:web"], want="ports") == [["tcp:443"]]
    assert _run(["svc:web"], want="tags") == [["tag:web"]]


def test_an_unknown_name_is_an_error(server: Tailnet) -> None:
    with pytest.raises(AnsibleError, match="holds no Service named"):
        _run(["svc:ghost"])
