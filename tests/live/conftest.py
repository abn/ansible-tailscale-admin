# SPDX-License-Identifier: BSD-2-Clause
"""The live stress harness: a throwaway tailnet state, built and torn down.

Run by ``make live-stress``. Takes an admin API key from a file, mints an OAuth
token from it, generates real devices by joining containers, and guarantees that
everything it created is gone when it finishes.

Why the key file and not a bare token
-------------------------------------
A token on a command line is in the shell history and in ``ps``. A file at mode
600 is neither, and the file is the thing an operator can rotate. The token read
out of it is exchanged immediately for an OAuth token, so the admin credential is
used exactly once and is never what the tests run on.

Why devices are containers
--------------------------
The ACL evaluator rejects a subject it cannot resolve. A tailnet with no devices
therefore cannot answer the question "does this policy deny or allow", which is
the question the allow-all guard turns on. A joined container is a real device
with a real Tailscale IP, so the server's own evaluator decides.

The cleanup contract
--------------------
Two levels, because a suite that leaks on the failure path is worse than no suite.

*Session* scope: the OAuth client and every generated device. Registered before
they exist, and torn down in reverse order whatever happens, including a
``KeyboardInterrupt``. A leaked container is a machine still on someone's tailnet.

*Function* scope: whatever a single test changed. The ``preserved`` fixture
restores it in a ``finally``, so a failed assertion leaves the tailnet as it was.
This is the level that matters for the resources a test mutates in place, since
the policy, DNS and settings endpoints are all whole-document writes.

Deliberately not attempted
-------------------------
Deleting the tailnet, deleting the OAuth client that owns the run, or anything
outside the tailnet under test. Those are not this harness's to remove.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import time
from collections.abc import Callable
from collections.abc import Iterator
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import ApiOptions
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import post_form
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import ApiToken
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import Authoriser
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import OauthClient
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import Secret
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleNotFound,
)
from ansible_collections.abn.tailscale.tests.live.harness import _Harness
from ansible_collections.abn.tailscale.tests.live.harness import harness_for

BASE_URL = os.environ.get("TS_API_BASE", "https://api.tailscale.com/api/v2")

#: How long to wait for a generated device to appear in the API. A container that
#: is running has usually registered already, and a tailnet's control plane
#: propagates a new device in a second or two. The margin is for a busy one.
DEVICE_APPEAR_TIMEOUT = 60.0

#: How long to wait for a device to disappear after a delete, for the same reason.
DEVICE_GONE_TIMEOUT = 30.0

#: The scopes the suite's own client needs. Every scope, because it manages
#: policy, DNS, devices, keys and users, and a narrower client would make a
#: coverage failure look like a permissions problem.
SUITE_SCOPES = "all"

#: A tag the generated devices carry. It exists so a device can be addressed by
#: tag in a test, and it is created in the policy rather than assumed, because a
#: tag only exists where `tagOwners` grants it.
PROBE_TAG = "tag:stress"

#: The prefix on everything this harness creates, so a leak is identifiable and a
#: cleanup can refuse to delete anything it did not create.
PREFIX = "ac-stress"

#: Identifies this run, for resources whose name has to be unique and whose cleanup
#: must not reach another's. A run-scoped suffix rather than a fixed name, because a
#: fixed name with a prefix-matching cleanup deletes a concurrent run's live
#: credentials. The process id and the time are unique enough for one machine.
RUN_ID = f"{os.getpid()}-{int(time.time()) % 100000}"

_CONTAINER_IMAGE = "docker.io/tailscale/tailscale:latest"


class HarnessError(RuntimeError):
    """The tailnet could not be prepared, so no test can run."""


@dataclass
class Device:
    """One generated device: a container, and what the API calls it."""

    name: str
    container: str
    node_id: str
    ips: list[str]
    key_id: str | None = None

    @property
    def ip(self) -> str:
        if not self.ips:
            raise HarnessError(f"{self.name} has no Tailscale IP, so it is not usable")
        return self.ips[0]


@dataclass
class Teardown:
    """Registered cleanups, newest first.

    Reverse order because a teardown can depend on an earlier one: a device
    cannot be deleted before the key that registered it is expired, and a policy
    must be writable before it can be restored.
    """

    steps: list[tuple[str, Callable[[], None]]] = field(default_factory=list)

    def register(self, label: str, action: Callable[[], None]) -> None:
        self.steps.append((label, action))

    def run(self) -> list[str]:
        """Run every teardown, collecting failures rather than stopping.

        A teardown that raises must not prevent the rest, or one broken cleanup
        turns a single leak into every resource the suite created.
        """
        problems: list[str] = []
        for label, action in reversed(self.steps):
            try:
                action()
            except Exception as error:
                problems.append(f"{label}: {type(error).__name__}: {error}")
        self.steps.clear()
        return problems


def _run(command: list[str], *, check: bool = True, timeout: int = 120) -> str:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode != 0:
        raise HarnessError(
            f"{' '.join(command[:3])} failed with {result.returncode}: "
            f"{(result.stderr or result.stdout).strip()[:400]}"
        )
    return result.stdout


def _podman() -> str:
    for candidate in ("podman", "docker"):
        if shutil.which(candidate):
            return candidate
    raise HarnessError("neither podman nor docker is available, so no device can be generated")


@pytest.fixture(scope="session")
def admin_token() -> str:
    """The admin API key, read from a file rather than taken from the environment.

    A file keeps it out of the shell history and out of `ps`. Refuses a
    world-readable one, because a key that other processes on the machine can read
    is a key that has to be rotated.
    """
    path = os.environ.get("TS_KEY_FILE")
    if not path:
        pytest.skip("set TS_KEY_FILE to a file holding an admin API key")
    key_file = Path(path).expanduser()
    if not key_file.is_file():
        raise HarnessError(f"{key_file} is not a file")
    mode = key_file.stat().st_mode & 0o777
    if mode & 0o077:
        raise HarnessError(
            f"{key_file} is mode {mode:o}, so it is readable by others; chmod 600 it"
        )
    token = key_file.read_text(encoding="utf-8").strip()
    if not token:
        raise HarnessError(f"{key_file} is empty")
    return token


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> _Harness:
    """The module harness, shared with the unit suite so there is one implementation.

    A live test drives a module exactly as ``ansible-playbook`` would: the real
    ``AnsibleModule``, the real argument validation, check mode and diff mode.
    """
    return harness_for(monkeypatch)


@pytest.fixture
def module_args(harness: _Harness) -> Callable[..., None]:
    """Set the arguments the next module run reads.

    ``module_args({"tailnet": "-"}, check_mode=True)``
    """
    return harness.set_args


@pytest.fixture
def module_result(harness: _Harness) -> _Harness:
    """Capture how the module under test finished.

    ``with module_result.success() as result:`` for a run that should succeed,
    ``with module_result.failure() as result:`` for one that should fail.
    """
    return harness


@pytest.fixture(scope="session")
def teardown() -> Iterator[Teardown]:
    """Session cleanup, registered before each resource exists and run at the end.

    The fixture yields rather than returning, so a test that fails still reaches
    the teardown. A container left running is a machine still on the tailnet.
    """
    ledger = Teardown()
    yield ledger
    problems = ledger.run()
    if problems:
        # Printed rather than raised: the session may already be failing, and a
        # teardown problem is the more urgent fact.
        print("\n  CLEANUP INCOMPLETE, these were not removed:")
        for problem in problems:
            print(f"    {problem}")


@pytest.fixture(scope="session")
def tailnet_id(admin_token: str, teardown: Teardown) -> str:
    """The tailnet under test, resolved through the admin key."""
    api = _admin_api(admin_token)
    response = api.call("users_list", "GET")
    body = response.body if isinstance(response.body, dict) else json.loads(str(response.body))
    users = body.get("users") or []
    if not users:
        raise HarnessError("the credential's first user carries no tailnetId")
    return str(users[0]["tailnetId"])


def _admin_api(token: str) -> Api:
    options = ApiOptions(base_url=BASE_URL, tailnet="-")
    return Api(options, Authoriser(ApiToken(Secret(token))))


@pytest.fixture(scope="session")
def suite_client(admin_token: str, tailnet_id: str, teardown: Teardown) -> OauthClient:
    """An OAuth client for this run, and exchanged for a token on use.

    Minted rather than reused so a run cannot inherit a client's scopes from
    whatever it was last set to, and deleted at the end so it does not outlive
    the suite. A client is a credential that keeps working after the tests stop.

    A client the environment names is used as it is, and is not deleted here. A
    suite that deleted a credential it did not create would leave the next run
    without one. Set `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_CLIENT_SECRET` to use one,
    which is what `make live-smoke` already exports, and which keeps the run on a
    credential belonging to the tailnet rather than to a person.
    """
    given_id = os.environ.get("TS_OAUTH_CLIENT_ID", "").strip()
    given_secret = os.environ.get("TS_OAUTH_CLIENT_SECRET", "").strip()
    if given_id and given_secret:
        print(f"\n  using the OAuth client named in the environment: {given_id[:8]}")
        return OauthClient(given_id, Secret(given_secret))
    if given_id or given_secret:
        raise HarnessError(
            "only one of TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET is set, so there is no "
            "client to use; set both, or neither and let the suite mint one"
        )

    api = _admin_api(admin_token)
    name = f"{PREFIX} suite {RUN_ID}"

    # Only this run's own leftovers, and only ones whose process is gone. Another
    # lane's client carries a different suffix and is left alone, which is the
    # whole point of the suffix.
    for existing, description in _stale_clients(api, tailnet_id):
        api.call("keys_delete", "DELETE", params={"keyId": existing})
        print(f"  removed a client left by a finished run: {description}")

    response = api.call(
        "keys_create",
        "POST",
        body={
            "keyType": "client",
            "description": name,
            "scopes": SUITE_SCOPES.split(),
        },
    )
    body = response.body if isinstance(response.body, dict) else {}
    client_id, secret = body.get("id"), body.get("key")
    if not client_id or not secret:
        raise HarnessError(f"the client was not minted: {json.dumps(body)[:200]}")

    def remove() -> None:
        fresh = _admin_api(admin_token)
        fresh.call("keys_delete", "DELETE", params={"keyId": client_id})

    teardown.register(f"OAuth client {client_id[:8]}", remove)
    return OauthClient(client_id, Secret(secret))


def _stale_clients(api: Api, tailnet_id: str) -> list[tuple[str, str]]:
    """Clients this suite minted in a run that is no longer running.

    A client belongs to the process that made it, and the description carries that
    process's id. So a client whose process is not among the live ones is
    abandoned and safe to remove, and a concurrent lane's client is not, because
    its process is still running.

    The list is read with ``all=true``, because the API leaves every OAuth client
    out of the default response when the request is made on a user-owned key. Read
    without it the sweep found nothing, so it never removed anything and every
    interrupted run leaked a working credential. Measured: the same request
    answers with one key without the filter and with the clients under it.
    """
    response = api.call("keys_list", "GET", params={"tailnet": tailnet_id}, query={"all": "true"})
    body = response.body if isinstance(response.body, dict) else json.loads(str(response.body))
    marker = f"{PREFIX} suite "
    found: list[tuple[str, str]] = []
    for key in body.get("keys") or []:
        if key.get("keyType") != "client":
            continue
        description = str(key.get("description") or "")
        if not description.startswith(marker):
            continue
        suffix = description[len(marker) :].strip()
        if suffix and suffix.split("-", 1)[0] in _LIVE_PIDS:
            continue
        found.append((str(key["id"]), description))
    return found


#: Process ids currently running a suite, sampled once at import. Read from procfs
#: rather than tracked, because a lane that starts after this import must still be
#: protected from this one's cleanup.
def _live_process_ids() -> frozenset[str]:
    import pathlib as _pathlib

    live: set[str] = set()
    for entry in _pathlib.Path("/proc").iterdir():
        if entry.name.isdigit():
            live.add(entry.name)
    return frozenset(live)


_LIVE_PIDS = _live_process_ids()


@pytest.fixture(scope="session")
def api(suite_client: OauthClient, tailnet_id: str) -> Api:
    """A client on the suite's own OAuth token, which is what the modules use.

    The modules are driven with the client id and secret rather than this object,
    so the credential path under test is the OAuth exchange and not a bare token.
    """
    options = ApiOptions(base_url=BASE_URL, tailnet=tailnet_id)
    return Api(
        options,
        Authoriser(suite_client, lambda path, form: post_form(options.base_url, path, form)),
    )


@pytest.fixture(scope="session")
def credentials(suite_client: OauthClient) -> dict[str, str]:
    """The module arguments that authenticate as the suite's client.

    Returned rather than passed in, so no test has to know how the credential is
    carried, and so switching from a token to a client is one fixture's change.
    """
    return {
        "oauth_client_id": suite_client.client_id,
        "oauth_client_secret": suite_client.secret.expose(),
    }


@pytest.fixture(scope="session")
def probe_policy(api: Api, teardown: Teardown) -> dict[str, Any]:
    """A policy that grants ``tag:stress`` an owner, written and restored.

    A tag only exists where ``tagOwners`` grants it, so a device cannot carry one
    until the policy says so. This is the same rule the collection refuses a
    device tag against, which makes it a live test of that refusal too.

    The original policy is restored at the end of the session, so the tag owner
    this adds does not outlive the run. An earlier version wrote the tag and left
    it, which meant a tailnet the suite had run against kept a `tagOwners` entry
    naming a tag nothing owned.
    """
    current = _policy_of(api)
    # Registered before the write, so a failure between the two leaves nothing
    # behind rather than a policy with a tag owner and no tag.
    teardown.register("the policy as it was before the suite", lambda: _write_policy(api, current))
    return _with_granted_tag(api)


def _with_granted_tag(api: Api) -> dict[str, Any]:
    """The tailnet's own policy with :data:`PROBE_TAG` granted to its admins.

    Two things this deliberately does not do, both because the alternative
    destroys a tailnet the suite is only a guest on.

    It does not rebuild the document. It used to carry ``grants``, ``tagOwners``
    and ``ssh`` forward and write those three, which deletes every other field the
    tailnet's policy holds: a run against a tailnet whose policy had ``acls`` left
    it with none, and one that had ``nodeAttrs`` or ``ssh`` lost them the same way.

    It does not widen access. A policy with neither ``acls`` nor ``grants`` has no
    subject for the ACL evaluator to resolve, so the allow-all grant is supplied
    only in that case, where the tailnet is not refusing anything that the grant
    would now permit. A tailnet with rules keeps them.

    It writes only when the tag is missing. The write is guarded by the
    fingerprint the read returned, and a whole-document write from another run
    moves that fingerprint, so a suite that wrote unconditionally would refuse
    itself for a reason that is not a lost edit.
    """
    current = _policy_of(api)
    if PROBE_TAG in (current.get("tagOwners") or {}):
        return current
    document = {
        **current,
        "tagOwners": {**(current.get("tagOwners") or {}), PROBE_TAG: ["autogroup:admin"]},
    }
    if not (document.get("acls") or document.get("grants")):
        document["grants"] = [{"src": ["*"], "ip": ["*"], "dst": ["*"]}]
    _write_policy(api, document)
    return document


def _policy_of(api: Api) -> dict[str, Any]:
    body = api.call("policy_get", "GET").body
    return body if isinstance(body, dict) else json.loads(str(body))


def _write_policy(api: Api, document: dict[str, Any]) -> None:
    from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._policy import write

    write(api, document, api.call("policy_get", "GET", expect_etag=True).etag)


@pytest.fixture(scope="session")
def device_address(devices: list[Device]) -> str:
    """A Tailscale IP that a real device on this tailnet holds right now.

    For a policy under test to be accepted, every selector in it has to name
    something the tailnet holds. Reading the address off a generated device is
    what makes the document portable: a literal would resolve only while that
    address happened to be allocated, and a run on a different tailnet, or after
    the device was removed, would be refused for a reason that has nothing to do
    with the module.
    """
    if not devices:
        pytest.skip("no generated device, so no address to write a rule against")
    return devices[0].ip


@pytest.fixture(scope="session")
def devices(
    api: Api,
    tailnet_id: str,
    probe_policy: dict[str, Any],
    teardown: Teardown,
) -> list[Device]:
    """Real devices, generated by joining containers.

    Each gets a single-use auth key carrying :data:`PROBE_TAG`, which is created
    here and not in ``probe_policy`` because the key's tags must match the
    policy's, and the API enforces that rather than the collection.
    """
    wanted = int(os.environ.get("TS_STRESS_DEVICES", "2"))
    if wanted < 1:
        return []
    runtime = _podman()
    made: list[Device] = []

    for index in range(wanted):
        # The run id is in the container and the node name, so two runs on one
        # machine do not collide on a name or on a container, and a leftover from
        # a finished run is identifiable rather than merely orphaned.
        name = f"{PREFIX}-{RUN_ID}-{index}"
        key = _auth_key(api, tailnet_id, name)
        container = _join(runtime, name, key)
        # Registered before the wait, so a device that never appears is still torn
        # down. A container that is running is a machine on the tailnet whether or
        # not the API has caught up.
        teardown.register(f"container {name}", lambda c=container: _remove_container(runtime, c))
        teardown.register(
            f"auth key for {name}",
            lambda k=key["id"]: _delete_key(api, k),
        )
        # A node record outlives the container and the key that registered it, so it
        # is deleted here. It is looked up by name at teardown rather than held as an
        # id, so a node that registers after the discovery window still goes and
        # there is nothing to hold before the wait.
        teardown.register(f"device {name}", lambda n=name: _delete_device_named(api, n))
        device = _await_device(api, name, container)
        made.append(device)

    print(f"\n  generated {len(made)} device(s): {', '.join(d.name for d in made)}")
    return made


@pytest.fixture
def live_device(api: Api, tailnet_id: str, devices: list[Device], teardown: Teardown) -> Device:
    """A generated device the API will accept right now, joining one if it has gone.

    A policy write that drops the probe tag owner de-authorises the device a
    container registered, and an ephemeral device that logs out leaves the tailnet
    within seconds. A node id captured when the session started can therefore name
    nothing by the time a later suite runs, and which suite runs first is just
    alphabetical order. The device suites join their own per test; this is for the
    suites that only need one device to exist, and it is cheaper than making every
    policy document carry the tag owner that keeps the original alive.
    """
    if not devices:
        pytest.skip("no generated device, so there is nothing to check")

    existing = devices[0]
    if _find_device(api, existing.name) is not None:
        return existing

    _with_granted_tag(api)
    runtime = _podman()
    index = 0
    while True:
        name = f"{PREFIX}-{RUN_ID}-rejoin-{index}"
        if _find_device(api, name) is None:
            break
        index += 1

    key = _auth_key(api, tailnet_id, name)
    container = _join(runtime, name, key)
    teardown.register(f"container {name}", lambda c=container: _remove_container(runtime, c))
    teardown.register(f"auth key for {name}", lambda k=key["id"]: _delete_key(api, k))
    teardown.register(f"device {name}", lambda n=name: _delete_device_named(api, n))
    return _await_device(api, name, container)


def _delete_device_named(api: Api, name: str) -> None:
    """Remove this run's node by the hostname it registered under, if it is there.

    Looked up at teardown rather than held as an id, so a node that registered
    after the discovery window is still removed, and one that never appeared is
    not an error.
    """
    found = _find_device(api, name)
    if found is None:
        return
    _delete_device(api, str(found.get("id", "")), str(found.get("name", "")))


def _delete_device(api: Api, node_id: str, name: str) -> None:
    """Remove a node from the tailnet, by node id.

    Refuses a node whose name does not carry :data:`PREFIX`. A cleanup that
    deleted whatever it was handed would be able to remove a device a person added
    to the tailnet by hand, and the whole point of the prefix is that a leak is
    identifiable.
    """
    if not node_id:
        return
    host = name.split(".", 1)[0]
    if not host.startswith(f"{PREFIX}-{RUN_ID}-"):
        raise HarnessError(
            f"refusing to delete {name!r}: it is not a node this run created, so it "
            f"belongs to another run or to somebody else. This run is {RUN_ID}."
        )
    api.call("device_delete", "DELETE", params={"deviceId": node_id})


def _auth_key(api: Api, tailnet_id: str, name: str) -> dict[str, Any]:
    response = api.call(
        "keys_create",
        "POST",
        body={
            "capabilities": {
                "devices": {
                    "create": {
                        "reusable": False,
                        # Ephemeral, so a device that outlives its container does
                        # not sit on the tailnet waiting for a human to notice.
                        "ephemeral": True,
                        "preauthorized": False,
                        "tags": [PROBE_TAG],
                    }
                }
            },
            "expirySeconds": 3600,
            "description": f"{PREFIX} {name}",
        },
    )
    body = response.body if isinstance(response.body, dict) else {}
    if not body.get("key"):
        raise HarnessError(f"no auth key for {name}: {json.dumps(body)[:200]}")
    return {"id": str(body.get("id", "")), "key": str(body["key"])}


def _join(runtime: str, name: str, key: dict[str, Any]) -> str:
    """Start a container joined to the tailnet.

    ``TS_STATE_MEM`` keeps the state in the container's own filesystem rather than
    a bind mount, because a mounted directory is owned by the invoking user and
    tailscaled refuses to start against one it does not own. That refusal reads
    as a health problem and is not.
    """
    _run(
        [runtime, "rm", "-f", name],
        check=False,
    )
    _run(
        [
            runtime,
            "run",
            "-d",
            "--name",
            name,
            "--hostname",
            name,
            "--cap-add=NET_ADMIN",
            "--device=/dev/net/tun",
            "-e",
            f"TS_AUTHKEY={key['key']}",
            "-e",
            "TS_USERSPACE=true",
            "-e",
            "TS_STATE_MEM=true",
            "-e",
            "TS_ACCEPT_DNS=false",
            _CONTAINER_IMAGE,
        ]
    )
    return name


def _await_device(api: Api, name: str, container: str) -> Device:
    """Wait for a joined container to appear in the API, then read its identity.

    Polling rather than sleeping a fixed interval, because a busy tailnet can take
    a few seconds to propagate and a fixed sleep is either too short, which fails
    a test that would have passed, or too long, which slows every run.
    """
    deadline = time.monotonic() + DEVICE_APPEAR_TIMEOUT
    while time.monotonic() < deadline:
        found = _find_device(api, name)
        if found is not None:
            return Device(
                name=name,
                container=container,
                node_id=str(found.get("id", "")),
                ips=list(found.get("addresses") or []),
            )
        if not _container_running(container):
            raise HarnessError(
                f"the container for {name} exited before registering: "
                f"{_run(['podman', 'logs', '--tail', '5', name], check=False).strip()[:300]}"
            )
        time.sleep(1.0)
    raise HarnessError(f"{name} did not appear in the API within {DEVICE_APPEAR_TIMEOUT}s")


def _find_device(api: Api, name: str) -> dict[str, Any] | None:
    """The node this run's container registered, by its hostname.

    The hostname carries the run id, so this matches one node and not a sibling
    run's. It was a prefix match against a fixed name, which matched whichever
    node the API listed first, and two runs on one machine took the next free
    suffix on the tailnet side.
    """
    body = api.call("device_list", "GET").body
    devices = body.get("devices", body) if isinstance(body, dict) else []
    for entry in devices or []:
        host = str(entry.get("name", "")).split(".", 1)[0]
        if host == name:
            return entry
    return None


def _container_running(name: str) -> bool:
    return (
        _run(["podman", "inspect", "-f", "{{.State.Running}}", name], check=False).strip() == "true"
    )


def _remove_container(runtime: str, name: str) -> None:
    _run([runtime, "rm", "-f", name], check=False)


def _delete_key(api: Api, key_id: str) -> None:
    """Remove a credential outright.

    ``keys_delete`` rather than ``device_expire_key``: the latter takes a
    ``deviceId`` and expires the key a *device* registered with, so a key this
    suite minted but whose container has already gone has nothing to expire it
    through. The API refuses the wrong parameter, which is what the first version
    of this cleanup did.
    """
    if not key_id:
        return
    api.call("keys_delete", "DELETE", params={"keyId": key_id})


@pytest.fixture
def preserved(api: Api) -> Callable[[str], Any]:
    """Restore whatever a test changed, in a ``finally``.

    The policy, DNS and settings endpoints are all whole-document writes, so a
    test that changes one has to put the old document back rather than leave the
    next test to discover the difference. Usage::

        def test_something(api, preserved):
            with preserved("policy"):
                ...change it...

    The context manager yields the current document, so a test does not have to
    read it twice.
    """

    @contextlib.contextmanager
    def restore_whole_document(resource: str) -> Iterator[Any]:
        reader, writer = _whole_document_accessors(api, resource)
        current = reader()
        try:
            yield current
        finally:
            writer(current)

    return restore_whole_document


def _whole_document_accessors(
    api: Api, resource: str
) -> tuple[Callable[[], Any], Callable[[Any], None]]:
    if resource == "policy":

        def read() -> Any:
            return _policy_of(api)

        def write(document: Any) -> None:
            _write_policy(api, document)

        return read, write

    if resource == "dns":

        def read() -> Any:
            return api.call("dns_configuration_get", "GET").body

        def write(document: Any) -> None:
            api.call("dns_configuration_set", "POST", body=document)

        return read, write

    if resource == "settings":
        return _settings_reader(api), _settings_writer(api)

    if resource.startswith(_LOG_STREAM_PREFIX):
        log_type = resource[len(_LOG_STREAM_PREFIX) :]
        return _log_stream_reader(api, log_type), _log_stream_writer(api, log_type)

    raise ValueError(f"no whole-document accessor for {resource}")


#: A log streaming destination is named after its log type, because a tailnet has
#: one per log type and they are separate documents rather than two fields of one.
_LOG_STREAM_PREFIX = "log_stream:"


def _log_stream_reader(api: Api, log_type: str) -> Callable[[], Any]:
    """The destination as it is, or an empty document where there is none.

    A not-found is the state rather than a failure here, and the restore has to
    tell "there was none" from "there was one" to put the tailnet back the way the
    test found it.
    """

    def read() -> Any:
        try:
            return api.call("logging_stream_get", "GET", params={"logType": log_type}).body
        except TailscaleNotFound:
            return {}

    return read


def _log_stream_writer(api: Api, log_type: str) -> Callable[[Any], None]:
    """Put a destination back, or take it away where there was none.

    Deleting rather than writing an empty document, because the API has no
    document meaning "no destination", and a PUT of one would be a different write
    from the one that removed it.
    """

    def write(document: Any) -> None:
        if not document:
            try:
                api.call("logging_stream_delete", "DELETE", params={"logType": log_type})
            except TailscaleNotFound:
                return
            return
        api.call("logging_stream_set", "PUT", params={"logType": log_type}, body=document)

    return write


def _settings_reader(api: Api) -> Callable[[], Any]:
    def read() -> Any:
        return api.call("tailnet_settings_get", "GET").body

    return read


def _settings_writer(api: Api) -> Callable[[Any], None]:
    """Put a settings document back, field by field.

    Field by field because the endpoint is a PATCH and a whole-document PATCH
    carries fields this plan will not accept a change to. `networkFlowLoggingOn`
    and `postureIdentityCollectionOn` are both refused on a free plan with a 400,
    so a restore that sends the document as one body fails on a field the test never
    touched, and the tailnet is then left however the test left it.

    A refusal on the way back is swallowed, and the ones that matter are checked
    separately: a field the plan refuses cannot have been changed by this suite
    either, since the write that changed it would have been refused in the same
    way.
    """

    def write(document: Any) -> None:
        if not isinstance(document, dict):
            return
        for name, value in sorted(document.items()):
            try:
                api.call("tailnet_settings_update", "PATCH", body={name: value})
            except Exception:
                continue

    return write
