# SPDX-License-Identifier: BSD-2-Clause
"""Selecting one Tailscale device, and reconciling what the API lets a client change.

Internal to this collection. The path carries a leading underscore, which declares
the kernel private: it can be refactored in any release without a major version
bump. See ``.agents/rules/ansible.md``.

A device cannot be declared
--------------------------
There is no create. A device appears when something authenticates to the tailnet,
so no task can say "this device should exist with these properties": a task can
only say something about a device that is already there. Everything here starts
from the devices the tailnet holds and is about choosing one of them.

Choosing is the whole risk
--------------------------
A tailnet can hold hundreds of devices, so a selector that is too broad, followed
by a write, is how a hostname, a tag or an approval lands on the wrong machine.
Two rules follow, and both are enforced here rather than left to a module:

* **A task names exactly one device.** A selector that matches none is an error,
  because a task naming a device that is not there has been given a stale
  playbook. A selector that matches several is an error too, because there is no
  defensible way to pick one of them: a rename applied to two devices because the
  task left out a hostname is not a guess anybody wants to discover afterwards.
* **Absence is the one case where a set is what was asked for.** Under
  ``state: absent`` the intent is that nothing matching the selector is left, so
  every match is removed and no match at all is the desired state.

What the server will not store
------------------------------
Three measured behaviours decide how a property is compared, and each would
otherwise report a change on every run for ever:

* **A device name is not stored as it is sent.** Tailscale rewrites the label it
  appends: uppercase is lowercased, an underscore and a dot both become a dash, and
  a trailing dash is dropped. The collection therefore accepts only a name already
  in the form the server keeps, and compares that form exactly. A name whose
  stored form cannot be predicted is refused rather than sent, because a rename
  that can never converge is worse than one that has to be spelled differently.
* **Tags and routes are sets.** The server returns them in its own order whatever
  order they arrived in, and returns an empty collection rather than an absent
  key. Comparing them as lists would report a change for a task whose input never
  varied.
* **An empty collection is stored, an absent one is not.** A device with no tags
  and a device whose tag list was cleared are the same document to the API, so
  both are read as the empty set.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from collections.abc import Sequence
from datetime import UTC
from datetime import datetime
from typing import Any
from typing import NamedTuple
from typing import Protocol

from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleNotFound,
)

__all__ = [
    "SELECTORS",
    "Applied",
    "DeviceClient",
    "DeviceError",
    "Selection",
    "apply",
    "check_name",
    "desired",
    "expired",
    "held",
    "identity",
    "listing",
    "local_name",
    "present",
    "remove",
    "resolve",
    "routes_wanted",
    "select",
]

#: The ways a task can name a device. Exactly one is required, because a task that
#: names a device two ways has two chances to be wrong and one device to be wrong
#: about. Held here rather than in either module so the two agree on what a
#: selector is and so the refusal for a task that named none is written once.
SELECTORS = ("device_id", "device_name", "address", "tag")

#: One DNS label, in the form the API stores it back. Uppercase, an underscore, a
#: leading or a trailing dash and two dashes in a row are all rewritten by the
#: server, so accepting them would mean comparing against a value the tailnet will
#: never hold. Measured: ``AC-Upper`` is stored as ``ac-upper``, ``under_score`` as
#: ``under-score``, ``trailing-`` as ``trailing``, and ``a.b.example.com`` as
#: ``a-b-example-com``.
_NAME_LABEL = re.compile(r"^[a-z0-9](?:-?[a-z0-9])*$")

#: A DNS label is 63 characters. Tailscale appends a suffix of its own to whatever
#: label is left, and the limit is on the whole name.
MAX_NAME_LENGTH = 63

#: The device properties the identity module reconciles, as it spells them. The
#: option names rather than the API's field names, because two of them have no
#: field of their own: the address is sent as ``ipv4``, and expiring a key is an
#: operation rather than a value.
MANAGED = ("name", "tags", "authorized", "key_expiry_disabled", "tailscale_ip", "expire_key")

#: What a deletion reports in a diff, since a device that is gone holds no
#: properties left to report. The one entry in a diff that means presence rather
#: than a value.
EXISTS = "exists"

#: A message naming what a task asked for must not carry an unbounded value into
#: a log line, and a device name is bounded already, so this only guards the
#: selectors that are not.
MAX_QUOTED = 200


class DeviceError(Exception):
    """A device task was refused before anything was written.

    Not a :class:`._errors.TailscaleError`, because nothing was sent. These are the
    collection's own decisions about which device a task means, and a caller that
    catches both needs to tell them apart: one is fixed by editing a playbook, the
    other by waiting or by asking the operator to intervene.
    """


class DeviceClient(Protocol):
    """The part of the client this file uses.

    Narrower than :class:`._api.Api` on purpose, for the reason given in
    :mod:`._policy`: depending on the whole client would make a test double into a
    second implementation of it.
    """

    def call(
        self,
        name: str,
        method: str,
        *,
        params: Mapping[str, str] | None = None,
        body: Any = None,
    ) -> Any: ...


class Selection(NamedTuple):
    """The devices a task named, and how it named them."""

    devices: list[dict[str, Any]]
    selector: str
    value: str


class Applied(NamedTuple):
    """What a run did to the devices it named."""

    devices: list[dict[str, Any]]
    changed: list[dict[str, Any]]
    before: dict[str, Any]
    after: dict[str, Any]


def identity(entry: Mapping[str, Any]) -> str:
    """The identifier a write addresses this device by.

    ``nodeId`` is what the API prefers and ``id`` is the legacy numeric form it
    still accepts, so a device matched on one is written through the other.
    """
    return str(entry.get("nodeId") or entry.get("id") or "")


def listing(api: DeviceClient) -> list[dict[str, Any]]:
    """Every device the tailnet holds.

    Read once per run and filtered here rather than by the API, because the
    decision about which device a task means is one this collection has to be able
    to explain, and a server-side filter answers with the rows that matched rather
    than with the count that was refused.

    The API's default field set carries every property the identity module
    reconciles, so no field selection is asked for. The route fields are not among
    them, which is why the routes are read from the device's own endpoint instead.
    """
    body = api.call("device_list", "GET").body
    if not isinstance(body, dict) or not isinstance(body.get("devices"), list):
        raise DeviceError(
            "The device list came back in a form this module could not read, so which "
            "devices this task would have changed is unknown and none were changed."
        )
    return [entry for entry in body["devices"] if isinstance(entry, dict)]


def local_name(entry: Mapping[str, Any]) -> str:
    """The device's own label, without the suffix the tailnet appends.

    The API returns the MagicDNS name, which is that label joined to a per-tailnet
    suffix, and no endpoint returns the label on its own. Everything compared about
    a name is the label, because it is the only part a task can ask for and the
    only part the server rewrites.
    """
    return str(entry.get("name") or "").partition(".")[0]


def check_name(name: str) -> None:
    """Refuse a device name the server would rewrite.

    The refusal is the point. A name outside this form is not a task that fails
    once, it is a task that reports a change on every run, because the tailnet
    holds something other than what was sent and every later run sees the same
    difference.
    """
    if len(name) > MAX_NAME_LENGTH:
        raise DeviceError(
            f"A device name is at most {MAX_NAME_LENGTH} characters, and "
            f"'{_quoted(name)}' is {len(name)}. Tailscale appends a suffix of its own "
            f"to the label."
        )
    if not _NAME_LABEL.match(name):
        raise DeviceError(
            f"'{_quoted(name)}' is not a device name Tailscale stores as it is sent, so a "
            "task asking for it would report a change on every run. Use lower case "
            "letters, digits and single dashes: no uppercase, no underscores, no dots, "
            "and no leading or trailing dash. Tailscale rewrites all of those, and a "
            "name it has rewritten is a name the tailnet never holds."
        )


def _quoted(value: str) -> str:
    return value[:MAX_QUOTED]


def _string_set(entry: Mapping[str, Any], key: str) -> set[str]:
    raw = entry.get(key)
    if not isinstance(raw, list):
        return set()
    return {str(item) for item in raw}


def _by_id(entry: Mapping[str, Any], value: str) -> bool:
    return value in (str(entry.get("nodeId") or ""), str(entry.get("id") or ""))


def _by_name(entry: Mapping[str, Any], value: str) -> bool:
    """Match the label, or the whole MagicDNS name.

    Both, because both are how the same device is written down: Tailscale shows the
    full name and a person who has joined it by hostname types the label. The label
    is the one that decides the properties, so accepting the full name as well costs
    one comparison and saves a task that would otherwise fail on a spelling.
    """
    return local_name(entry) == value or str(entry.get("name") or "") == value


def _by_address(entry: Mapping[str, Any], value: str) -> bool:
    return value in _string_set(entry, "addresses")


def _by_tag(entry: Mapping[str, Any], value: str) -> bool:
    return value in _string_set(entry, "tags")


#: One matcher per selector, as a mapping rather than a chain of branches, so a
#: selector added to SELECTORS without one here is a KeyError at import rather than
#: a task that matches nothing and is refused for the wrong reason.
_MATCHERS = {
    "device_id": _by_id,
    "device_name": _by_name,
    "address": _by_address,
    "tag": _by_tag,
}


def select(devices: Sequence[Mapping[str, Any]], params: Mapping[str, Any]) -> Selection:
    """The devices the task's single selector names, in the order the API listed them.

    Refuses a task that named no selector at all. An empty selector would match
    every device in the tailnet, and naming one is the whole point.
    """
    named = [selector for selector in SELECTORS if params.get(selector) is not None]
    if not named:
        raise DeviceError(
            "No device was named, so this task would apply to every device in the "
            "tailnet. Name one with exactly one of: " + ", ".join(SELECTORS) + "."
        )
    selector = named[0]
    value = str(params[selector])
    matcher = _MATCHERS[selector]
    return Selection(
        devices=[dict(entry) for entry in devices if matcher(entry, value)],
        selector=selector,
        value=value,
    )


def resolve(
    devices: Sequence[Mapping[str, Any]], params: Mapping[str, Any], *, many: bool
) -> Selection:
    """The devices a task named, refusing a count it did not ask for.

    ``many`` is set only by a deletion, where the intent is that nothing matching
    the selector is left. Everywhere else a task means one device, so a count of
    none or several is a playbook that has drifted from the tailnet or from itself,
    and the operator has to see that rather than have it guessed at.
    """
    selection = select(devices, params)
    if many:
        return selection
    if not selection.devices:
        raise DeviceError(
            f"No device in the tailnet matches {_describe(selection)}, so nothing was "
            f"changed. A device that has just been removed is the ordinary cause; a "
            f"mistyped value is the other one."
        )
    if len(selection.devices) > 1:
        raise DeviceError(
            f"{len(selection.devices)} devices match {_describe(selection)}, so this task "
            f"does not say which one it means. Name it more precisely, by device_id or by "
            f"address. Nothing was changed."
        )
    return selection


def _describe(selection: Selection) -> str:
    return f"{selection.selector} '{_quoted(selection.value)}'"


def expired(entry: Mapping[str, Any], now: datetime) -> bool:
    """Whether the device's node key has already expired.

    Measured rather than assumed: expiring a key moves ``expires`` to the moment of
    the call, and expiring it again leaves that timestamp where it is, so the field
    is the whole difference between a key that needs expiring and one that has. That
    is what lets the operation converge instead of reporting a change for ever.

    A timestamp that is absent or unreadable counts as *not* expired, so the first
    run writes and the run after it sees the timestamp that write produced. Reading
    it the other way would leave a device whose key state nobody can observe
    looking reconciled for good.
    """
    moment = _moment(entry.get("expires"))
    return moment is not None and moment <= now


def _moment(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text[-1:] in ("Z", "z"):
        # `fromisoformat` learned the military suffix in Python 3.11, and a module
        # runs on whatever the target host provides.
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # A timestamp with no offset is read as UTC, which is what the API sends.
        return parsed.replace(tzinfo=UTC)
    return parsed


def desired(entry: Mapping[str, Any], params: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    """The managed properties of one device that this run would change.

    Only the options the task gave are looked at. A device holds a great deal this
    collection does not manage, and comparing the whole document would let a field
    the operator never mentioned report a change on every run.
    """
    wanted: dict[str, Any] = {}

    if params.get("name") is not None:
        label = str(params["name"])
        if local_name(entry) != label:
            wanted["name"] = label

    if params.get("tags") is not None:
        tags = {str(tag) for tag in params["tags"]}
        if tags != _string_set(entry, "tags"):
            wanted["tags"] = sorted(tags)

    # The two booleans are written as one condition each rather than as a nested
    # pair, because the question is one comparison and splitting it says there are
    # two things to decide.
    if params.get("authorized") is not None and bool(params["authorized"]) != bool(
        entry.get("authorized")
    ):
        wanted["authorized"] = bool(params["authorized"])

    if params.get("key_expiry_disabled") is not None and bool(
        params["key_expiry_disabled"]
    ) != bool(entry.get("keyExpiryDisabled")):
        wanted["key_expiry_disabled"] = bool(params["key_expiry_disabled"])

    if params.get("tailscale_ip") is not None:
        address = str(params["tailscale_ip"])
        if address not in _string_set(entry, "addresses"):
            wanted["tailscale_ip"] = address

    if params.get("expire_key") and not expired(entry, now):
        wanted["expire_key"] = True

    return wanted


def held(entry: Mapping[str, Any], properties: Sequence[str], now: datetime) -> dict[str, Any]:
    """What each named property holds now, in the module's own spelling.

    A property this collection cannot read is reported as ``None`` rather than as
    the wanted value, so a diff never claims a device already holds something the
    tailnet was only asked to hold.
    """
    values: dict[str, Any] = {
        "name": local_name(entry),
        "tags": sorted(_string_set(entry, "tags")),
        "authorized": bool(entry.get("authorized")),
        "key_expiry_disabled": bool(entry.get("keyExpiryDisabled")),
        "tailscale_ip": _current_address(entry),
        "expire_key": expired(entry, now),
    }
    return {name: values[name] for name in properties if name in values}


def _current_address(entry: Mapping[str, Any]) -> str | None:
    """The IPv4 address a device holds today.

    The API returns both address families in one list and names neither, so the
    first entry is the IPv4 by Tailscale's own ordering. Reported as ``None`` when
    the list is empty, which is a device that holds no address rather than one whose
    address is unknown.
    """
    addresses = sorted(_string_set(entry, "addresses"))
    return addresses[0] if addresses else None


def apply(api: DeviceClient, entry: Mapping[str, Any], wanted: Mapping[str, Any]) -> None:
    """Write the properties that differ, one endpoint each.

    The order is fixed rather than taken from the option order, so that a run which
    fails part way leaves the same half-applied device every time.
    """
    device = {"deviceId": identity(entry)}
    if "name" in wanted:
        api.call("device_rename", "POST", params=device, body={"name": wanted["name"]})
    if "tags" in wanted:
        api.call("device_set_tags", "POST", params=device, body={"tags": wanted["tags"]})
    if "authorized" in wanted:
        api.call(
            "device_authorize",
            "POST",
            params=device,
            body={"authorized": wanted["authorized"]},
        )
    if "key_expiry_disabled" in wanted:
        api.call(
            "device_set_key_expiry",
            "POST",
            params=device,
            body={"keyExpiryDisabled": wanted["key_expiry_disabled"]},
        )
    if "tailscale_ip" in wanted:
        api.call("device_set_ip", "POST", params=device, body={"ipv4": wanted["tailscale_ip"]})
    if "expire_key" in wanted:
        api.call("device_expire_key", "POST", params=device)


def present(
    api: DeviceClient,
    devices: Sequence[Mapping[str, Any]],
    params: Mapping[str, Any],
    now: datetime,
    *,
    check_mode: bool = False,
) -> Applied:
    """Bring each named device to what the task asked for, writing only what differs.

    A device that was written is read again, so what is reported is the document
    the server stored rather than the one that was sent. For a name that is the
    difference between ``ac-lane`` and ``ac-lane.tail1234.ts.net``, and returning
    the request would report a name no tailnet holds. A check run has nothing to
    read back, so it reports the document as it stands and the diff alone says
    what a real run would change.

    A device that has gone by the time it is read back is reported as the document
    the run read. An ephemeral device removes itself when it disconnects, and
    expiring its key is one of the ways to bring that about, so failing the run
    would report a task that did what it was asked as a failure.
    """
    reported: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    before: dict[str, Any] = {}
    after: dict[str, Any] = {}

    for entry in devices:
        wanted = desired(entry, params, now)
        device = identity(entry)
        if not wanted:
            reported.append(dict(entry))
            continue
        if not check_mode:
            apply(api, entry, wanted)
            try:
                fresh = api.call("device_get", "GET", params={"deviceId": device}).body
            except TailscaleNotFound:
                fresh = entry
            reported.append(fresh if isinstance(fresh, dict) else dict(entry))
        else:
            reported.append(dict(entry))
        properties = sorted(wanted)
        changed.append({"id": device, "properties": properties})
        before[device] = held(entry, properties, now)
        after[device] = dict(wanted)

    return Applied(devices=reported, changed=changed, before=before, after=after)


def remove(
    api: DeviceClient, devices: Sequence[Mapping[str, Any]], *, check_mode: bool = False
) -> Applied:
    """Delete every named device, and report the ones that were there to delete.

    A device that has already gone is not a failure. An ephemeral device removes
    itself when it disconnects, so a delete that arrives after that has reached the
    outcome the operator asked for, and calling it an error would report a failed
    deletion for a device that is gone.
    """
    deleted: list[dict[str, Any]] = []
    for entry in devices:
        if not check_mode:
            try:
                api.call("device_delete", "DELETE", params={"deviceId": identity(entry)})
            except TailscaleNotFound:
                continue
        deleted.append(dict(entry))
    return Applied(
        devices=deleted,
        changed=[{"id": identity(entry), "properties": [EXISTS]} for entry in deleted],
        # A device that is gone appears before and not after, which is what a diff
        # renders as a removal. Nothing else belongs here: a delete changes no
        # property, and a diff across a whole device would bury the one line that
        # says a machine is no longer there.
        before={identity(entry): {EXISTS: True} for entry in deleted},
        after={},
    )


def routes_wanted(current: Any, wanted: Sequence[str]) -> list[str] | None:
    """The routes to enable, or ``None`` when the device already has them.

    Returned sorted because the server stores them in its own order, so comparing
    what was asked for with what came back as written would report a change on
    every run for an input that never varied. An empty list is a real answer and not
    an absence: it is how a device is stripped of the routes an admin enabled for
    it.
    """
    held_routes = current.get("enabledRoutes") if isinstance(current, dict) else None
    existing = {str(route) for route in held_routes} if isinstance(held_routes, list) else set()
    asked = {str(route) for route in wanted}
    if existing == asked:
        return None
    return sorted(asked)
