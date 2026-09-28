# SPDX-License-Identifier: BSD-2-Clause
"""The fact modules and the lookups against a real tailnet.

Both are reads, so what only the real API can answer is whether the documents
arrive in the shape the modules promise: the device list carrying both address
families and the two identifiers, the Service list carrying the addresses the
server assigned, and a lookup resolving each by the name a task would give it.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from ansible.plugins.loader import lookup_loader
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleNotFound,
)
from ansible_collections.abn.tailscale.plugins.modules import tailscale_device_info
from ansible_collections.abn.tailscale.plugins.modules import tailscale_service_info
from ansible_collections.abn.tailscale.tests.live.conftest import Device
from ansible_collections.abn.tailscale.tests.live.conftest import Teardown

pytestmark = pytest.mark.live_smoke

#: A Service this file creates, prefixed so a leak is identifiable as this run's.
SERVICE = f"svc:ac-info-{os.getpid()}"


@contextmanager
def a_service(api: Api, teardown: Teardown) -> Iterator[dict[str, Any]]:
    """A Service that exists for the block and is removed afterwards.

    Created through the API rather than through ``tailscale_service``, because
    these tests read the Service list and a bug in the writer would then be
    reported as a bug in the reader. Removed in a ``finally`` as well as at session
    teardown, because the next ``PUT`` to a leftover Service is an update, and an
    update has to carry the addresses the server assigned.
    """

    def remove() -> None:
        try:
            api.call("service_delete", "DELETE", params={"serviceName": SERVICE})
        except TailscaleNotFound:
            return

    teardown.register(f"service {SERVICE}", remove)
    remove()
    api.call(
        "service_set",
        "PUT",
        params={"serviceName": SERVICE},
        body={"name": SERVICE, "ports": ["tcp:443"]},
    )
    try:
        body = api.call("service_get", "GET", params={"serviceName": SERVICE}).body
        yield body if isinstance(body, dict) else {}
    finally:
        remove()


def _label(entry: dict[str, Any]) -> str:
    """The device's own label, which is the part of the MagicDNS name a task names."""
    return str(entry.get("name", "")).split(".", 1)[0]


def _has_both_families(addresses: list[str]) -> bool:
    return any("." in address for address in addresses) and any(
        ":" in address for address in addresses
    )


def test_the_device_list_holds_a_generated_device(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    devices: list[Device],
) -> None:
    """The module returns the API's own device documents, with both families."""
    module_args({**credentials})
    with module_result.success() as result:
        tailscale_device_info.main()

    assert result["changed"] is False
    entry = next(entry for entry in result["devices"] if _label(entry) == devices[0].name)
    assert devices[0].node_id in {entry.get("id"), entry.get("nodeId")}
    assert _has_both_families(entry["addresses"]), entry["addresses"]


def test_the_service_list_holds_a_created_service(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    teardown: Teardown,
) -> None:
    """The list carries the addresses the server assigned, which the task never sent."""
    with a_service(api, teardown):
        module_args({**credentials})
        with module_result.success() as result:
            tailscale_service_info.main()

    assert result["changed"] is False
    entry = next(entry for entry in result["services"] if entry.get("name") == SERVICE)
    assert entry["ports"] == ["tcp:443"]
    assert _has_both_families(entry["addrs"]), entry["addrs"]


def test_the_device_lookup_resolves_a_generated_device(
    credentials: dict[str, str], devices: list[Device]
) -> None:
    """A template names the device by its label; the lookup answers its address."""
    lookup = lookup_loader.get("abn.tailscale.device")
    found = lookup.run([devices[0].name], variables={}, **credentials, want="ipv4")

    assert len(found) == 1
    assert ":" not in found[0], found[0]
    assert found[0] in devices[0].ips


def test_the_service_lookup_resolves_a_created_service(
    credentials: dict[str, str], api: Api, teardown: Teardown
) -> None:
    with a_service(api, teardown):
        lookup = lookup_loader.get("abn.tailscale.service")
        found = lookup.run([SERVICE], variables={}, **credentials, want="ipv4")

    assert len(found) == 1
    assert ":" not in found[0], found[0]
