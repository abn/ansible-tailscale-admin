# SPDX-License-Identifier: BSD-2-Clause
"""The two device modules against a real tailnet, through the module.

Every assertion drives a module's ``main()``, never the kernel. The kernel has
unit tests; what this file is for is the module as a user meets it, and the three
things only the real API can answer.

**What the server stores.** A device name is rewritten rather than stored, tags and
routes come back in the server's own order, an untagged device and a cleared one
are the same document, and a deleted device that had already gone answers a 404.
Each of those is a way a comparison can report a change for ever, and each is
pinned here rather than assumed.

**What the server refuses.** A tag with no owner, and a tagged node asked to shed
its last tag, are both real 400s with a specific message, and a task that hits one
has to be told what actually has to change.

**Whether a device write is guarded.** It is not. Only the policy file carries an
``ETag``, and a device write carrying a stale one is accepted, so the measurement
is recorded here where it can be found rather than assumed by a reader.

The devices are containers this suite joined, so the only state a test has to put
back is the one a later test in this file would trip over. Each of those is named in
its own comment.
"""

from __future__ import annotations

import contextlib
import itertools
import json
import os
import time
from collections.abc import Callable
from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleNotFound,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscalePreconditionFailed,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._policy import write
from ansible_collections.abn.tailscale.plugins.modules import tailscale_device
from ansible_collections.abn.tailscale.plugins.modules import tailscale_device_routes
from ansible_collections.abn.tailscale.tests.live.conftest import Device
from ansible_collections.abn.tailscale.tests.live.conftest import HarnessError
from ansible_collections.abn.tailscale.tests.live.conftest import _await_device
from ansible_collections.abn.tailscale.tests.live.conftest import _join
from ansible_collections.abn.tailscale.tests.live.conftest import _podman
from ansible_collections.abn.tailscale.tests.live.conftest import _remove_container

pytestmark = pytest.mark.live_smoke

#: Tags of this lane's own, granted an owner in the policy. `tag:stress` belongs
#: to the harness and every lane running the stress suite holds a device carrying
#: it, so a selector on it would be ambiguous whenever two suites overlap. A tag of
#: its own is what makes "this task means one device" a statement about this file.
#: Two rather than one because changing a device's tags needs a tag to change it to,
#: and because a tag nobody else can grant is the one thing this file can rely on.
PROBE_TAG = "tag:lane-device"
ALT_TAG = "tag:lane-device-alt"
PROBE_TAGS = (PROBE_TAG, ALT_TAG)

#: How many times the policy write is retried after losing a race with another lane,
#: and how long between attempts. The wait matters more than the count: a retry with no
#: delay loses the same race several times inside one second.
POLICY_WRITE_ATTEMPTS = 10
POLICY_WRITE_PAUSE = 1.0

#: How many times a container is joined when the device it made has left the tailnet,
#: which another lane's policy write causes by dropping the tag the device carries.
JOIN_ATTEMPTS = 3

#: A prefix for every container this suite joins, unique to this process, and a
#: counter within it so that no two containers this run joins share a name.
#:
#: The harness finds a joined device by matching the container's name against the
#: device list, and an ephemeral device outlives the container that made it for a
#: while after the container is removed. A name reused by a later test, or by a later
#: run, would therefore match a device that is still on the tailnet from one of
#: them, which is a device this test did not create and whose state it does not
#: know. The process id separates runs and the counter separates tests.
RUN = f"ac-lane-{os.getpid()}"
_NAMES = itertools.count()


def _fresh_name() -> str:
    return f"{RUN}-d{next(_NAMES)}"


#: Routes nobody routes to. A subnet router has to advertise a route before an
#: admin can enable it, but the API accepts and stores one that is not advertised
#: yet, so a live test can enable something a container will never serve. The exit
#: node pair is what Tailscale's own documentation uses for the same purpose.
ROUTES = ["10.77.0.0/16", "10.78.0.0/16"]


def _key(api: Api, name: str, tag: str) -> dict[str, Any]:
    """A single-use auth key carrying `tag`, for one container to join with.

    Written here rather than taken from the harness because the harness's key is
    bound to its own tag, and a tag of this lane's own is what makes a tag selector
    deterministic. The shape is the harness's, including the ephemerality: a device
    that outlives its container must not sit on the tailnet waiting for a human to
    notice it.
    """
    response = api.call(
        "keys_create",
        "POST",
        body={
            "capabilities": {
                "devices": {
                    "create": {
                        "reusable": False,
                        "ephemeral": True,
                        "preauthorized": False,
                        "tags": [tag],
                    }
                }
            },
            "expirySeconds": 3600,
            "description": f"{name} device probe",
        },
    )
    body = response.body if isinstance(response.body, dict) else {}
    if not body.get("key"):
        raise HarnessError(f"no auth key for {name}: {body}")
    return {"id": str(body.get("id", "")), "key": str(body["key"])}


def _grant_probe_tags(api: Api) -> None:
    """Put an owner on each of this lane's tags, if one is not there already.

    Read and written here rather than through the harness's policy fixture, for two
    reasons. The harness's fixture does not retry, and the policy file is the only
    resource with a concurrency guard while every lane sharing this tailnet edits
    it, so a write can lose a race with a lane that started later. And a lane running
    a policy test writes a document of its own, which can drop a tag another lane's
    devices are carrying. A device whose tag has no owner is de-authorised and
    re-authenticates, and a container joined with a single-use key cannot, so it
    leaves the tailnet. Checking before writing keeps the number of policy writes
    down to the ones that are actually needed.
    """
    for attempt in range(POLICY_WRITE_ATTEMPTS):
        current = api.call("policy_get", "GET", expect_etag=True)
        document = current.body if isinstance(current.body, dict) else {}
        owners = dict(document.get("tagOwners") or {})
        if all(owners.get(tag) for tag in PROBE_TAGS):
            return
        wanted = {
            **document,
            "tagOwners": {**owners, **{tag: ["autogroup:admin"] for tag in PROBE_TAGS}},
        }
        try:
            write(api, wanted, current.etag)
        except TailscalePreconditionFailed:
            # Another lane is writing the policy right now, and a retry with no wait
            # would lose the same race several times inside one second.
            print(f"\n  the policy changed under the probe write, retrying ({attempt + 1})")
            time.sleep(POLICY_WRITE_PAUSE)
            continue
        return
    raise HarnessError(f"the probe tags could not be granted in {POLICY_WRITE_ATTEMPTS} attempts")


@pytest.fixture(scope="session")
def probe_policy_tag(api: Api) -> str:
    """Grant an owner to this lane's tags, and leave them in place.

    Left in place rather than restored, which is what the harness's own
    `probe_policy` fixture does: every lane's stress run needs a tag that exists,
    and a tag is a line in the policy rather than a resource with a lifecycle of
    its own. A tag with no owner cannot be applied to a device, so this is also what
    makes the API's refusal of an unowned tag testable.
    """
    _grant_probe_tags(api)
    return PROBE_TAG


@pytest.fixture(autouse=True)
def tags_stay_granted(api: Api, probe_policy_tag: str) -> None:
    """Re-assert the tag grant before each test, because the tailnet is shared.

    Another lane's policy test can write a document without this lane's tags, and a
    device whose tag has no owner leaves the tailnet rather than sitting on it
    misconfigured. Asserted before every test rather than once per session so that
    one lane's write cannot decide whether this file's next test has a device to
    talk to.
    """
    _grant_probe_tags(api)


@pytest.fixture(scope="session")
def join_device(api: Api, probe_policy_tag: str, teardown: Any) -> Callable[..., Any]:
    """Join a container carrying this lane's tag, and register its removal first.

    The teardown is registered before the container is started and before the key
    is created, so a device that never appears is still cleaned up. A container
    that is running is a machine on somebody's tailnet whether or not the API has
    caught up with it.

    Joined a second time when the device has left the tailnet by the time it would be
    used. A device's identity is the tag its auth key carried, so a policy write by
    another lane that drops the tag de-authorises the device and it goes. The grant
    is re-asserted before each attempt, and a device that is still missing after
    that is the tailnet's answer rather than something a retry fixes, so it fails
    rather than looping.
    """

    def joined(name: str) -> Device:
        for _attempt in range(JOIN_ATTEMPTS):
            device = _join_once(api, teardown, name, probe_policy_tag)
            _grant_probe_tags(api)
            node_id = _node_id_of(api, device)
            if node_id is not None:
                return replace(device, node_id=node_id)
            print(f"\n  {name} left the tailnet before it could be used, joining it again")
            _remove_container(_podman(), device.container)
        raise HarnessError(f"{name} could not be joined and kept in {JOIN_ATTEMPTS} attempts")

    return joined


def _join_once(api: Api, teardown: Any, name: str, tag: str) -> Device:
    key = _key(api, name, tag)
    runtime = _podman()
    teardown.register(f"auth key for {name}", lambda: _delete_key(api, key["id"]))
    container = _join(runtime, name, key)
    teardown.register(f"container {name}", lambda: _remove_container(runtime, container))
    return _await_device(api, name, container)


def _node_id_of(api: Api, device: Device) -> str | None:
    """The `nodeId` of a joined device, or ``None`` when it is no longer on the tailnet.

    The harness's device carries the legacy numeric `id`, because that is what its
    own assertions are written against. The preferred identifier is read here so that
    every task in this file addresses a device the way the API's own documentation
    says to address one, and a device that has gone answers ``None`` rather than the
    legacy id of something that is no longer there.
    """
    listed = api.call("device_list", "GET").body.get("devices", [])
    for entry in listed:
        if str(entry.get("name", "")).startswith(device.name):
            return str(entry.get("nodeId") or device.node_id)
    return None


def _delete_key(api: Api, key_id: str) -> None:
    if key_id:
        api.call("keys_delete", "DELETE", params={"keyId": key_id})


@pytest.fixture
def probe_device(join_device: Callable[..., Any], api: Api) -> Iterator[Device]:
    """A device of this test's own, joined fresh and removed when the test ends.

    Per test rather than per session, and that is a concession to the tailnet being
    shared: a container device's identity is the tag its auth key carried, so a
    policy write by another lane that drops the tag de-authorises the device and it
    leaves the tailnet, taking the rest of the file's assertions with it. A device
    per test bounds that to the one test that met it, and it removes the order
    dependence a shared device brings, because no test can change what another sees.

    Removed at the end of the test rather than at the end of the session, because a
    container's ephemeral record outlives the container by a minute or two and
    thirty of them accumulating is thirty devices on somebody's tailnet that nobody
    is using. The session ledger still holds the container and the key, so a test
    that dies before this runs leaves both cleaned up.
    """
    yield from _for_the_test(join_device, api)


@pytest.fixture
def rival_device(join_device: Callable[..., Any], api: Api) -> Iterator[Device]:
    """A second device carrying the same tag, so a tag selector is ambiguous.

    Without it the tag this lane owns would name exactly one device, and the refusal
    for a selector matching several would have nothing to refuse.
    """
    yield from _for_the_test(join_device, api)


def _for_the_test(join_device: Callable[..., Any], api: Api) -> Iterator[Device]:
    device = join_device(_fresh_name())
    try:
        yield device
    finally:
        _remove_container(_podman(), device.container)
        # A test that deletes the device under test has already done this, and a
        # delete of a device that is gone is the outcome the caller asked for.
        with contextlib.suppress(TailscaleNotFound):
            api.call("device_delete", "DELETE", params={"deviceId": device.node_id})


def _run(module_args: Any, module_result: Any, options: dict[str, Any], **flags: Any) -> dict:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_device.main()
    return dict(result)


def _run_routes(
    module_args: Any, module_result: Any, options: dict[str, Any], **flags: Any
) -> dict:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_device_routes.main()
    return dict(result)


def _tailnet_device(api: Api, device_id: str) -> dict[str, Any]:
    body = api.call("device_get", "GET", params={"deviceId": device_id}).body
    return body if isinstance(body, dict) else {}


# ------------------------------------------------------------- reconciliation


def test_key_expiry_is_reconciled_and_the_second_run_is_quiet(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """The invariant against a real API, for a property that is a value rather than
    an action.

    Asked for as the opposite of what the device holds, so the run is a change, and
    the API's own answer is read back rather than the request.
    """
    options = {
        **credentials,
        "device_id": probe_device.node_id,
        "key_expiry_disabled": not bool(
            _tailnet_device(api, probe_device.node_id)["keyExpiryDisabled"]
        ),
    }
    first = _run(module_args, module_result, options, diff=True)
    assert first["changed"] is True
    assert first["diff"]["after"], "a diff has to carry what it wrote"
    assert (
        _tailnet_device(api, probe_device.node_id)["keyExpiryDisabled"]
        is options["key_expiry_disabled"]
    )

    second = _run(module_args, module_result, options)
    assert second["changed"] is False, (
        f"stored device is {_tailnet_device(api, probe_device.node_id)}"
    )
    assert second["diff"]["before"] == second["diff"]["after"]


def test_tags_are_reconciled_as_a_set_and_the_second_run_is_quiet(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """The API returns the tags in its own order whatever order they arrived in, so
    an ordered comparison would report a change for ever. Asked for in the other
    order on purpose, and the second run is what shows it.

    """
    both = [PROBE_TAG, ALT_TAG]
    options = {**credentials, "device_id": probe_device.node_id, "tags": list(reversed(both))}
    first = _run(module_args, module_result, options)
    assert first["changed"] is True
    assert first["diff"]["after"] == {probe_device.node_id: {"tags": sorted(both)}}
    assert sorted(_tailnet_device(api, probe_device.node_id)["tags"]) == sorted(both)
    assert _run(module_args, module_result, options)["changed"] is False


def test_dropping_one_of_a_device_s_tags_is_a_change(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """The API replaces the whole list and refuses only the empty one, so removing a
    tag is an ordinary change. Asserted because a module that treated every removal
    as impossible would be wrong here."""
    both = {**credentials, "device_id": probe_device.node_id, "tags": [PROBE_TAG, ALT_TAG]}
    assert _run(module_args, module_result, both)["changed"] is True

    fewer = {**credentials, "device_id": probe_device.node_id, "tags": [PROBE_TAG]}
    assert _run(module_args, module_result, fewer)["changed"] is True
    assert _tailnet_device(api, probe_device.node_id)["tags"] == [PROBE_TAG]
    assert _run(module_args, module_result, fewer)["changed"] is False


def test_approval_is_reconciled_and_the_second_run_is_quiet(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """Both directions of the comparison, one of them on a device that is still there.

    The revocation direction is not driven against a live device, because it cannot
    be: measured against the real API, a device whose approval is revoked logs out
    within a couple of seconds, and an ephemeral device that logs out leaves the
    tailnet, so there is nothing left to read the change back from. What is asserted
    here for that direction is the comparison rather than the write, and a device
    that joined without preauthorisation already holds the state C(false) asks for.

    Approving is not destructive, so it is driven for real, in both directions of its
    own comparison: a change, then a run over the same task that is quiet.
    """
    assert _tailnet_device(api, probe_device.node_id)["authorized"] is False, (
        "a device that joined without preauthorisation arrives unapproved, which is "
        "the state this test needs for the quiet half"
    )
    revoked = {**credentials, "device_id": probe_device.node_id, "authorized": False}
    assert _run(module_args, module_result, revoked)["changed"] is False

    approved = {**credentials, "device_id": probe_device.node_id, "authorized": True}
    first = _run(module_args, module_result, approved)
    assert first["changed"] is True
    assert first["diff"]["after"] == {probe_device.node_id: {"authorized": True}}
    assert _tailnet_device(api, probe_device.node_id)["authorized"] is True
    assert _run(module_args, module_result, approved)["changed"] is False


def test_a_tag_the_tailnet_does_not_own_is_refused_with_the_policy_as_the_remedy(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """Measured: the API answers 400 and names nothing about the policy, so the
    module's message is the only place an operator learns that `tagOwners` is what
    has to change."""
    before = _tailnet_device(api, probe_device.node_id)
    module_args({**credentials, "device_id": probe_device.node_id, "tags": ["tag:notowned"]})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "tagOwners" in result["msg"]
    assert "Traceback" not in result["msg"]
    assert _tailnet_device(api, probe_device.node_id)["tags"] == before["tags"]


def test_taking_the_last_tag_off_is_refused_by_the_api_and_says_why(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """Measured: a tagged node cannot be untagged without re-authenticating, so
    `tags: []` on a tagged device is a failure and not a change. A module that
    treated it as a change would fail on every run for ever."""
    before = _tailnet_device(api, probe_device.node_id)
    module_args({**credentials, "device_id": probe_device.node_id, "tags": []})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "re-authenticate" in result["msg"]
    assert _tailnet_device(api, probe_device.node_id)["tags"] == before["tags"]


def test_a_tag_already_held_is_not_a_change(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    probe_device: Any,
) -> None:
    """The device joined with this lane's tag, so the tag is already there and asking
    for it has to be quiet."""
    result = _run(
        module_args,
        module_result,
        {**credentials, "device_id": probe_device.node_id, "tags": [PROBE_TAG]},
    )
    assert result["changed"] is False


# ------------------------------------------------------------- the name


def test_a_rename_stores_the_tailnets_own_spelling_of_the_label(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """The API appends a per-tailnet suffix and rewrites the label it is given, so
    what the module reports has to be what the tailnet holds rather than what the
    task sent."""
    result = _run(
        module_args,
        module_result,
        {**credentials, "device_id": probe_device.node_id, "name": f"{RUN}-renamed"},
    )
    assert result["changed"] is True
    stored = _tailnet_device(api, probe_device.node_id)
    assert result["devices"][0]["name"] == stored["name"]
    assert stored["name"].startswith(f"{RUN}-renamed.")
    assert stored["name"] != f"{RUN}-renamed", "the tailnet appends a suffix of its own"


def test_a_rename_then_the_same_task_again_is_quiet(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    probe_device: Any,
) -> None:
    """Convergence for a rename, which is the property the rewritten label could
    have broken: a module that compared the label it sent against the stored name
    would report a change on every run."""
    options = {**credentials, "device_id": probe_device.node_id, "name": f"{RUN}-quiet"}
    assert _run(module_args, module_result, options)["changed"] is True
    assert _run(module_args, module_result, options)["changed"] is False


def test_a_name_the_server_would_rewrite_is_refused_before_any_write(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """Measured: Tailscale lowercases the label, turns dots and underscores into
    dashes and drops a trailing one. A task asking for a name in any other form
    would differ from the tailnet for ever, so it is refused rather than sent."""
    before = _tailnet_device(api, probe_device.node_id)
    module_args({**credentials, "device_id": probe_device.node_id, "name": f"{RUN}-Rewritten"})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "change on every run" in result["msg"]
    assert _tailnet_device(api, probe_device.node_id)["name"] == before["name"]


def test_a_device_is_selected_by_the_label_it_holds(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """Selection by name, which is how an operator writes a device down. The
    container's hostname is the label, because nothing in this file has renamed it.

    Two runs, because the first is what makes the second's answer mean something: a
    selector that matched a device the task then approved is quiet the second time,
    and one that matched nothing would have failed rather than gone quiet. Started
    from whatever the device holds, so the first run is a change either way.
    """
    wanted = not bool(_tailnet_device(api, probe_device.node_id)["authorized"])
    options = {**credentials, "device_name": probe_device.name, "authorized": wanted}
    assert _run(module_args, module_result, options)["changed"] is True
    result = _run(module_args, module_result, options)
    assert result["changed"] is False
    assert result["devices"][0]["nodeId"] == probe_device.node_id


# ------------------------------------------------------------- selection


def test_a_selector_matching_several_devices_is_refused(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    probe_device: Any,
    rival_device: Any,
) -> None:
    """The failure this lane exists to prevent: two devices, one tag, and a write
    that would land on one of them by a guess."""
    module_args({**credentials, "tag": PROBE_TAG, "authorized": True})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "devices match" in result["msg"]
    assert "device_id" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_selector_matching_no_device_is_refused(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    module_args({**credentials, "device_name": f"{RUN}-never-joined", "authorized": True})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "No device in the tailnet matches" in result["msg"]


def test_a_device_is_selected_by_its_tailscale_address(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    probe_device: Any,
) -> None:
    """Nothing to reconcile, so the run is quiet and the assertion is about which
    device the selector resolved to rather than about a write."""
    result = _run(
        module_args,
        module_result,
        {**credentials, "address": probe_device.ip, "expire_key": False},
    )
    assert result["changed"] is False
    assert result["devices"][0]["nodeId"] == probe_device.node_id


def test_a_task_naming_nothing_is_refused_before_it_reads_the_tailnet(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """A selector that matched every device would be a write to the whole tailnet,
    so the argument spec refuses it before a credential is resolved."""
    module_args({**credentials, "authorized": True})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "one of the following is required" in result["msg"]
    for secret in credentials.values():
        assert secret not in result["msg"]


# ------------------------------------------------------------- deletion


def test_a_deleted_device_is_gone_and_the_same_task_again_is_quiet(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """The invariant for a deletion, and the one that is easiest to break: a second
    run over the same selector has to find nothing and report no change."""
    options = {**credentials, "device_id": probe_device.node_id, "state": "absent"}
    first = _run(module_args, module_result, options, diff=True)
    assert first["changed"] is True
    assert first["changed_devices"] == [{"id": probe_device.node_id, "properties": ["exists"]}]
    assert first["diff"] == {
        "before": {probe_device.node_id: {"exists": True}},
        "after": {},
    }

    second = _run(module_args, module_result, options)
    assert second["changed"] is False
    assert second["devices"] == []
    assert second["diff"] == {"before": {}, "after": {}}

    # And the tailnet agrees, which is the part a stubbed API cannot show.
    devices = api.call("device_list", "GET").body.get("devices", [])
    assert probe_device.node_id not in [entry.get("nodeId") for entry in devices]


def test_a_device_that_is_already_gone_is_not_a_failure(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """The selector names nothing, and under `state: absent` that is the state the
    operator asked for. The ID is one nothing holds, which is what a second run over
    a deletion leaves behind."""
    result = _run(
        module_args,
        module_result,
        {**credentials, "device_id": "nMISSING000000000CNTRL", "state": "absent"},
    )
    assert result["changed"] is False
    assert result["devices"] == []


def test_check_mode_deletes_nothing(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    result = _run(
        module_args,
        module_result,
        {**credentials, "device_id": probe_device.node_id, "state": "absent"},
        check_mode=True,
    )
    assert result["changed"] is True
    devices = api.call("device_list", "GET").body.get("devices", [])
    assert probe_device.node_id in [entry.get("nodeId") for entry in devices], (
        "a check run reported a deletion and left the device there"
    )


# ------------------------------------------------------------- key and address


def test_expiring_a_key_then_asking_again_is_quiet(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """Measured: expiring a key moves `expires` to the moment of the call and
    expiring it again leaves that timestamp alone, so the field is what tells the
    two apart."""
    options = {**credentials, "device_id": probe_device.node_id, "expire_key": True}
    first = _run(module_args, module_result, options)
    assert first["changed"] is True
    assert first["diff"]["after"] == {probe_device.node_id: {"expire_key": True}}

    stored = _tailnet_device(api, probe_device.node_id).get("expires")
    assert stored, "the API reports an expiry either way"
    assert _run(module_args, module_result, options)["changed"] is False, (
        f"the stored expiry is {stored}"
    )


def test_asking_for_the_address_a_device_already_holds_is_quiet(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """The no-change direction of the one option that breaks every existing
    connection to the device, so asking for the address it already holds has to be
    quiet rather than severing what is there.

    The IPv4 the device holds today, read from the API rather than from the harness's
    record of the join, because an address the device has been given since is the one
    this has to be quiet about.
    """
    address = _tailnet_device(api, probe_device.node_id)["addresses"][0]
    result = _run(
        module_args,
        module_result,
        {**credentials, "device_id": probe_device.node_id, "tailscale_ip": address},
    )
    assert result["changed"] is False


def test_changing_an_address_is_a_change_and_the_tailnet_stores_it(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """The address is taken from the one the device holds rather than written out, so
    the test asks for something inside whatever pool this tailnet allocates from
    rather than assuming the whole CGNAT range is available.
    """
    current = _tailnet_device(api, probe_device.node_id)["addresses"][0]
    head, _dot, last = current.rpartition(".")
    wanted = f"{head}.{int(last) + 1}"
    result = _run(
        module_args,
        module_result,
        {**credentials, "device_id": probe_device.node_id, "tailscale_ip": wanted},
    )
    assert result["changed"] is True
    assert wanted in _tailnet_device(api, probe_device.node_id)["addresses"]


def test_an_address_the_api_would_reject_is_refused_before_a_request(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """Measured: the API answers a malformed address with a message about malformed
    JSON, which names nothing about the value that was wrong."""
    module_args({**credentials, "device_id": "n1CNTRL", "tailscale_ip": "fd7a:115c:a1e0::1"})
    with module_result.failure() as result:
        tailscale_device.main()
    assert "IPv4" in result["msg"]
    assert "Traceback" not in result["msg"]


# ------------------------------------------------------------- routes


def test_routes_are_enabled_and_the_second_run_is_quiet(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """The routes are asked for in the opposite order to the one the server stores
    them in, which is the comparison that would otherwise report a change for ever.
    A container advertises nothing, so enabling a route on one is stored without
    being usable, which is the state the API documents for a route enabled before
    the device advertises it."""
    options = {
        **credentials,
        "device_id": probe_device.node_id,
        "enabled_routes": list(reversed(ROUTES)),
    }
    first = _run_routes(module_args, module_result, options, diff=True)
    assert first["changed"] is True
    assert first["diff"]["after"] == sorted(ROUTES)
    assert first["routes"]["enabled_routes"] == sorted(ROUTES)

    stored = api.call("device_routes_get", "GET", params={"deviceId": probe_device.node_id}).body
    assert stored["enabledRoutes"] == sorted(ROUTES)
    assert _run_routes(module_args, module_result, options)["changed"] is False


def test_clearing_the_routes_is_a_change_and_converges(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """An empty list is how a device stops acting as a subnet router, and it has to
    converge as a change rather than repeat for ever. The routes are enabled first,
    so the test does not depend on what another one left on the device."""
    enabled = {**credentials, "device_id": probe_device.node_id, "enabled_routes": ROUTES}
    assert _run_routes(module_args, module_result, enabled)["changed"] is True

    options = {**credentials, "device_id": probe_device.node_id, "enabled_routes": []}
    assert _run_routes(module_args, module_result, options)["changed"] is True
    stored = api.call("device_routes_get", "GET", params={"deviceId": probe_device.node_id}).body
    assert stored.get("enabledRoutes") in ([], None), stored
    assert _run_routes(module_args, module_result, options)["changed"] is False


def test_routes_report_what_the_device_advertises_alongside_what_is_enabled(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    probe_device: Any,
) -> None:
    """A container advertises nothing, so the advertised list comes back empty and is
    reported rather than dropped. Routes are advertised, not received: no API call
    can add to that list, so an operator needs to see it to know what is left to
    configure on the device itself.

    """
    result = _run_routes(
        module_args,
        module_result,
        {**credentials, "device_id": probe_device.node_id, "enabled_routes": []},
    )
    assert result["routes"] == {"advertised_routes": [], "enabled_routes": []}
    assert result["device"]["nodeId"] == probe_device.node_id


def test_routes_refuse_a_selector_matching_several_devices(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    probe_device: Any,
    rival_device: Any,
) -> None:
    module_args({**credentials, "tag": PROBE_TAG, "enabled_routes": ROUTES})
    with module_result.failure() as result:
        tailscale_device_routes.main()
    assert "devices match" in result["msg"]


def test_routes_in_check_mode_write_nothing(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """The routes are read before and after, rather than asserted to be a particular
    value, so the test says what it means whatever another test left on the device."""
    where = {"deviceId": probe_device.node_id}
    before = api.call("device_routes_get", "GET", params=where).body

    result = _run_routes(
        module_args,
        module_result,
        {**credentials, "device_id": probe_device.node_id, "enabled_routes": ROUTES},
        check_mode=True,
    )
    assert result["changed"] is (sorted(ROUTES) != sorted(before.get("enabledRoutes") or []))
    assert result["diff"]["after"] == sorted(ROUTES)
    assert api.call("device_routes_get", "GET", params=where).body == before


# ------------------------------------------------------------- concurrency


def test_a_device_write_is_not_guarded_by_an_etag(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    """Measured, and the reason the modules read before they write without asking
    for a fingerprint: only the policy file carries an ETag, so a device write with a
    stale one is accepted rather than refused.

    Recorded here because the collection's own invariant is that the policy file is
    the only concurrency-controlled resource, and this is the evidence. A future
    change that guards device writes would have to change this test.

    The write is an approval rather than a revocation, because a revoked device logs
    out and leaves the tailnet and there would be nothing left to assert against. The
    module's own reconciliation is shown on a property that does not disconnect the
    device.
    """
    api.call(
        "device_authorize",
        "POST",
        params={"deviceId": probe_device.node_id},
        body={"authorized": True},
        headers={"If-Match": '"a-fingerprint-from-another-run"'},
    )
    assert _tailnet_device(api, probe_device.node_id)["authorized"] is True, (
        "the write was refused, so device writes are guarded after all and the "
        "collection's invariant needs revisiting"
    )

    # The module reads what is there rather than what the task assumed, so the run
    # after somebody else's write is quiet rather than a second change.
    agreed = {**credentials, "device_id": probe_device.node_id, "authorized": True}
    assert _run(module_args, module_result, agreed)["changed"] is False

    keys = {
        **agreed,
        "key_expiry_disabled": not bool(
            _tailnet_device(api, probe_device.node_id)["keyExpiryDisabled"]
        ),
    }
    assert _run(module_args, module_result, keys)["changed"] is True
    assert _run(module_args, module_result, keys)["changed"] is False


# ------------------------------------------------------------- plumbing


def test_a_credential_never_reaches_a_failure(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """A task with no device to name fails on argument validation, before the
    credential is resolved, and the message must not carry it."""
    module_args({**credentials, "authorized": True})
    with module_result.failure() as result:
        tailscale_device.main()
    for secret in credentials.values():
        assert secret not in result["msg"]


def test_a_credential_never_reaches_a_result(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    probe_device: Any,
) -> None:
    wanted = not bool(_tailnet_device(api, probe_device.node_id)["authorized"])
    result = _run(
        module_args,
        module_result,
        {**credentials, "device_id": probe_device.node_id, "authorized": wanted},
    )
    assert result["changed"] is True, "the run has to change something to say anything"
    # The client id is not asserted against, and its appearing in the result is not a
    # leak: the API puts the creating client in the device document, and the id is
    # not a secret. The secret is the one that must never appear.
    assert credentials["oauth_client_secret"] not in json.dumps(result, default=str)
