# SPDX-License-Identifier: BSD-2-Clause
"""That a run of the stress suite leaves the tailnet as it found it.

Every other file under ``tests/live`` asserts that a module does the right thing
to a resource. This one asserts that the harness itself does the right thing to the
tailnet, which is the property nothing else can see: by the time any module test
runs, the damage a previous test did has already been done.

It exists because the first version of the harness got this wrong. It removed the
container and deleted the auth key and registered neither, on the reasoning that
an ephemeral node goes away when its container does. It does not. The node record
stays in the tailnet, keyed by its node id, and a registration outlives the
credential that made it, so sixteen runs left sixteen unapproved unowned nodes
named ``ac-stress-0`` through ``ac-stress-0-10``, each run's nodes taking the next
free suffix. Nobody noticed for a day.

Run it with a device count of one, so it is a single generated device.

It runs under ``make live-smoke`` rather than ``make live-stress``, because the
stress target globs ``test_*_module_live.py`` and this asserts something about the
harness rather than about a module. The stress run is where the devices it checks
are generated.

Also here: that the harness can tell its own resources from a sibling run's. Six
lanes hold this tailnet at once, and the first version of the cleanup matched on
a fixed prefix, so each run deleted the others' live OAuth client. The symptom was
a run failing with "It needs the `auth_keys` scope" on a request the API had just
permitted, which reads as a permissions problem and is not one.

And that two live runs on one machine cannot overlap: the lock the live targets
hold for the whole run is exercised here, against a path of this test's own so it
does not contend with the run that is holding the real one.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from ansible_collections.abn.tailscale.tests.live.conftest import _LIVE_PIDS
from ansible_collections.abn.tailscale.tests.live.conftest import PREFIX
from ansible_collections.abn.tailscale.tests.live.conftest import PROBE_TAG
from ansible_collections.abn.tailscale.tests.live.conftest import RUN_ID
from ansible_collections.abn.tailscale.tests.live.conftest import _delete_device_named
from ansible_collections.abn.tailscale.tests.live.conftest import _write_policy

pytestmark = pytest.mark.live_smoke


def _all_devices(api: Any) -> list[dict[str, Any]]:
    body = api.call("device_list", "GET").body
    devices = body.get("devices", body) if isinstance(body, dict) else []
    return [d for d in devices or [] if str(d.get("name", "")).startswith(f"{PREFIX}-")]


def test_every_node_this_run_created_names_this_run(devices: list[Any], api: Any) -> None:
    """A node's hostname carries this run's id, so cleanup can tell runs apart.

    Without it a cleanup matching on a prefix reaches whatever it finds first, and
    with six lanes on one tailnet that is somebody else's live credential. The
    assertion is that every node this run generated is unambiguously attributable
    to it, and that a node from another run is left where it is.
    """
    assert devices, "no device, so there is nothing to attribute"
    for device in devices:
        host = device.name.split(".", 1)[0]
        assert host.startswith(f"{PREFIX}-{RUN_ID}-"), (
            f"{device.name} does not name the run that created it, so a cleanup "
            "cannot tell it from another run's"
        )
        assert RUN_ID in host, "and the run id is in the name, not merely the prefix"


def test_a_run_does_not_delete_another_runs_credential() -> None:
    """The stale-client sweep skips a client whose process is still running.

    Exercised without a second run: the sweep is handed a client description
    carrying a live process id and must return nothing for it, and one carrying a
    dead one and must return that one. A unit test of the predicate rather than of
    the whole run, because the failure it prevents is a sibling's live credential
    being removed and only a concurrent pair of runs reproduces that.
    """
    live = f"{PREFIX} suite {os.getpid()}"
    dead = f"{PREFIX} suite 999999"
    foreign = "someone elses client"

    assert _sweep_would_take(live) is False, "a running lane's client must survive"
    assert _sweep_would_take(dead) is True, "a finished run's client must not"
    assert _sweep_would_take(foreign) is False, "a client nobody here made must not"


def _sweep_would_take(description: str) -> bool:
    """The stale-client predicate, as the sweep applies it.

    Mirrors :func:`_stale_clients` rather than calling it, because that one needs
    an API and this is about the rule. If the two ever disagree, the two
    assertions below are the ones that stop mattering, so the rule is small
    enough to read twice.
    """
    marker = f"{PREFIX} suite "
    if not description.startswith(marker):
        return False
    suffix = description[len(marker) :].strip()
    if not suffix:
        return True
    return suffix.split("-", 1)[0] not in _LIVE_PIDS


def test_restoring_a_policy_that_did_not_change_is_accepted(api: Any) -> None:
    """The harness's restore must not be refused on a policy it did not change.

    This looks like a nothing and is here because of what it cost. Four runs of
    the policy suite died in fixture setup with a 412, and the measurement taken
    at the time said the API refuses a write whose rendered document is already
    stored. It does not. On a quiet tailnet the same write is accepted, and the
    412s were four other lanes writing the same policy at the same time. A guard
    was built on that measurement and has been removed.
    """
    _write_policy(api, _policy_of_document(api))


def test_the_harness_generates_a_device_and_owns_it(devices: list[Any], api: Any) -> None:
    """The device exists, it is the suite's, and it carries the suite's tag.

    Checked before anything is torn down, because that is the only moment at which
    the harness's own bookkeeping is visible. A device the suite generated but
    cannot name is a device nobody can clean up.
    """
    assert devices, "the harness generated no device, so nothing here is proven"
    device = devices[0]

    listed: dict[str, Any] = {}
    for entry in _all_devices(api):
        for key in (entry.get("nodeId"), entry.get("id")):
            if key:
                listed[str(key)] = entry
    assert device.node_id in listed, (
        f"{device.name} is not in the device list, so the suite holds an id for a "
        "node the API does not know about"
    )
    entry = listed[device.node_id]
    assert entry.get("tags") == [PROBE_TAG], "and it carries the tag the auth key granted it"
    assert entry.get("user") in (None, ""), (
        "a tagged device has no owning user; one that does is a different thing"
    )


def test_a_device_is_registered_as_a_node_the_api_can_delete(devices: list[Any], api: Any) -> None:
    """The teardown deletes by node id, so the id has to be the API's own.

    An earlier version of the harness took the name and looked it up at teardown
    time, by which point the name was ambiguous: a second run's node took the next
    free suffix and a lookup by prefix matched whichever the API listed first.
    Holding the id removes the ambiguity.
    """
    assert devices, "no device, so there is no id to check"
    device = devices[0]

    fetched = api.call("device_get", "GET", params={"deviceId": device.node_id})
    assert fetched.status == 200, "the id the harness holds is one the API accepts"
    assert fetched.body is not None, "and it resolves to a node"


def test_the_policy_the_suite_installs_is_present_and_owned(api: Any) -> None:
    """The `tagOwners` entry the harness adds, and who owns it.

    A suite that leaves a tag owner behind is a tailnet carrying a `tagOwners`
    entry for a tag nothing owns, which is a document an operator did not write
    and has to notice.

    This asserts the harness installed the entry, not that it will remove it,
    because removal happens after the last test in a session and nothing in
    pytest can assert after that. The restore itself is a session teardown, and
    the leak it prevents was found by reading the tailnet, not by a test: sixteen
    runs of the earlier harness left sixteen nodes behind the same way.
    """
    current = _policy_of_document(api)
    assert PROBE_TAG in current.get("tagOwners", {}), (
        "the suite is supposed to have installed this tag owner, so this test is "
        "not running in a session that generated a device"
    )
    assert current["tagOwners"][PROBE_TAG] == ["autogroup:admin"]


def _policy_of_document(api: Any) -> dict[str, Any]:
    from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import loads

    body = api.call("policy_get", "GET").body
    return body if isinstance(body, dict) else loads(str(body))


def test_a_node_is_removed_by_name_at_teardown() -> None:
    """The device cleanup looks the node up when it runs, not when it is registered.

    A container can register its node after the discovery window closes, and the
    node outlives the container. Registering the cleanup by node id, after the
    wait, meant a late registration was never cleaned at all.
    """
    name = f"{PREFIX}-{RUN_ID}-late"
    calls: list[tuple[str, dict[str, Any]]] = []

    class FakeApi:
        def call(self, operation: str, method: str, **kwargs: Any) -> Any:
            calls.append((operation, kwargs.get("params") or {}))
            body = (
                {"devices": [{"id": "nLate00000001", "name": f"{name}.example.ts.net"}]}
                if operation == "device_list"
                else None
            )
            return SimpleNamespace(body=body, status=200)

    fake: Any = FakeApi()
    _delete_device_named(fake, name)

    assert [entry[0] for entry in calls] == ["device_list", "device_delete"], (
        "the node was found by name and then deleted"
    )
    assert calls[1][1] == {"deviceId": "nLate00000001"}


def test_a_node_that_never_registered_is_not_an_error() -> None:
    """A container that never appeared leaves nothing to delete."""
    calls: list[str] = []

    class EmptyApi:
        def call(self, operation: str, method: str, **kwargs: Any) -> Any:
            calls.append(operation)
            return SimpleNamespace(body={"devices": []}, status=200)

    empty: Any = EmptyApi()
    _delete_device_named(empty, f"{PREFIX}-{RUN_ID}-absent")

    assert calls == ["device_list"], "nothing was deleted and nothing raised"


def test_the_live_lock_refuses_a_second_holder(tmp_path: Path) -> None:
    """The live lock admits one holder and frees when that holder exits.

    The live targets hold the lock for the whole pytest run, so this drives the
    helper against a path of its own; contending on the real path would deadlock
    the suite against itself. No second tailnet run is needed: the first holder
    is a sleep and the lock is a file, so contention and release are local facts.
    """
    helper = _repository_root() / ".contrib" / "scripts" / "live-lock.sh"
    lock = tmp_path / "live.lock"
    environment = {**os.environ, "TS_LIVE_LOCK": str(lock)}

    holder = subprocess.Popen([str(helper), "sleep", "60"], env=environment, text=True)
    try:
        _await_lock_holder(holder, lock)

        contender = subprocess.run(
            [str(helper), "true"], env=environment, capture_output=True, text=True, check=False
        )

        assert contender.returncode != 0, "a second holder must be refused, not run"
        assert "already holds" in contender.stdout, contender.stdout
        assert str(holder.pid) in contender.stdout, "the refusal names the holder"
    finally:
        holder.terminate()
        holder.wait(timeout=10)

    released = subprocess.run(
        [str(helper), "true"], env=environment, capture_output=True, text=True, check=False
    )
    assert released.returncode == 0, (
        f"the lock must free when the holder exits: {released.stderr.strip()}"
    )


def _await_lock_holder(holder: subprocess.Popen[str], lock: Path) -> None:
    """Wait until the holder has recorded itself, so the refusal is not raced."""
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        assert holder.poll() is None, "the holder exited before it took the lock"
        if lock.exists() and lock.read_text(encoding="utf-8").splitlines()[:1] == [str(holder.pid)]:
            return
        time.sleep(0.05)
    raise AssertionError(f"no holder recorded in {lock} within 10s")


def _repository_root() -> Path:
    """The checkout root, found by the marker every collection carries."""
    for parent in Path(__file__).resolve().parents:
        if (parent / "galaxy.yml").is_file():
            return parent
    raise AssertionError(f"no galaxy.yml above {__file__}, so no checkout root")
