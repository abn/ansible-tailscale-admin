# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the ``abn.tailscale.device`` lookup.

The lookup is loaded through ``lookup_loader`` rather than constructed directly,
because its options come from a documentation fragment the loader resolves. The
resolution itself is the device module's, so what is tested here is the lookup's
own layer: which property each ``want`` names, and that an ambiguous or missing
term is an error rather than a guess.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible.errors import AnsibleError
from ansible.plugins.loader import lookup_loader

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
    class Response:
        def __init__(self) -> None:
            self.status = status
            self.headers: dict = {}

        def read(self) -> Body:
            return Body(text)

    return Response()


class Tailnet:
    """Answers the device list from a canned document."""

    def __init__(self, document: Any = None) -> None:
        self.document = document if document is not None else {"devices": DEVICES}
        self.requests: list[str] = []

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        self.requests.append(f"{method} {url}")
        return _reply(200, json.dumps(self.document))


@pytest.fixture
def server(mocker: Any) -> Tailnet:
    tailnet = Tailnet()
    mocker.patch(_API_URL, tailnet)
    return tailnet


def _run(terms: list[str], **kwargs: Any) -> list[Any]:
    lookup = lookup_loader.get("abn.tailscale.device")
    return lookup.run(terms, variables={}, api_token=TOKEN, **kwargs)


def test_a_label_resolves_to_the_address_by_default(server: Tailnet) -> None:
    assert _run(["nibbler"]) == ["100.64.0.5"]


def test_a_whole_magicdns_name_resolves(server: Tailnet) -> None:
    assert _run(["canvas.example.ts.net"], want="ipv6") == ["fd7a:115c:a1e0::6"]


def test_an_address_selects_the_device_that_holds_it(server: Tailnet) -> None:
    assert _run(["100.64.0.6"], want="name") == ["canvas.example.ts.net"]


def test_the_id_selects_the_device_it_names(server: Tailnet) -> None:
    assert _run(["nNIBBLER01CNTRL"], want="hostname") == ["nibbler"]


def test_several_terms_answer_in_order(server: Tailnet) -> None:
    assert _run(["nibbler", "canvas"], want="name") == [
        "nibbler.example.ts.net",
        "canvas.example.ts.net",
    ]


def test_tags_are_returned_as_a_list(server: Tailnet) -> None:
    assert _run(["nibbler"], want="tags") == [["tag:lab"]]
    assert _run(["canvas"], want="tags") == [[]]


def test_a_term_matching_nothing_is_an_error(server: Tailnet) -> None:
    with pytest.raises(AnsibleError, match="No device in the tailnet matches"):
        _run(["ghost"])


def test_a_name_two_devices_share_is_an_error(server: Tailnet) -> None:
    server.document["devices"].append(
        {"nodeId": "nTWIN03CNTRL", "id": "333", "name": "nibbler.other.ts.net", "addresses": []}
    )

    with pytest.raises(AnsibleError, match="2 devices match"):
        _run(["nibbler"])


def test_a_missing_address_family_is_an_error(server: Tailnet) -> None:
    server.document["devices"][1]["addresses"] = ["100.64.0.6"]

    with pytest.raises(AnsibleError, match="holds no ipv6 address"):
        _run(["canvas"], want="ipv6")
