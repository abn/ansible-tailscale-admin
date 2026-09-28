#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_device
short_description: Manage a device in a tailnet
version_added: 0.1.0
description:
  - Reconciles the properties of a device that already exists in a Tailscale
    tailnet, and removes one on request.
  - A device cannot be created. One appears when something authenticates to the
    tailnet, so a task cannot declare that a device should exist. It can only say
    something about a device that is there, so this module selects one the tailnet
    already holds and reconciles what the API lets a client change about it.
  - A task names that device with exactly one of O(device_id), O(device_name),
    O(address) or O(tag). A selector matching no device is a failure, and so is
    one matching several, because there is no defensible way to choose between them
    and guessing is how a rename lands on the wrong machine. O(state=absent) is the
    one exception. There the intent is that nothing matching the selector is left,
    so every match is removed and no match at all is the desired state.
  - This module owns the properties of a device. The routes an admin enabled for it
    belong to M(abn.tailscale.tailscale_device_routes), which is a separate module
    because the API reads and writes them through their own endpoint.
  - Selecting by name means selecting by the label the device holds now, so a task
    that renames a device must not select it that way, because the name it selects
    on is the name it is changing. Select by O(device_id) or O(address) when the
    name is going to change.
  - O(expire_key) and O(tailscale_ip) reach further than the device's own record.
    Expiring a key makes the device authenticate again, and changing an address
    breaks every existing connection to it, including the one Ansible is running
    over when the device is the control node. Revoking O(authorized) is in the same
    class, and disconnects the device, which then has to authenticate again.
  - Only the options given are compared. A property this module does not manage
    cannot make a run report a change, however the server chooses to report it.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.check_mode_diff_mode
  - abn.tailscale._attributes.connection_delegation
options:
  state:
    description:
      - Whether the device should be present with the properties given, or gone
        from the tailnet.
      - Under C(absent) every device the selector matches is deleted, so a
        selector matching nothing reports no change and a selector matching several
        deletes all of them.
    type: str
    choices:
      - present
      - absent
    default: present
    version_added: 0.1.0
  device_id:
    description:
      - The device to manage, by the ID the admin console shows.
      - The preferred form is the C(nodeId), a string beginning with C(n). The
        legacy numeric C(id) is accepted too, and either names the same device.
    type: str
    version_added: 0.1.0
  device_name:
    description:
      - The device to manage, by the label part of its MagicDNS name, which is
        the name without the suffix the tailnet appends to it.
      - This is the Tailscale node name rather than the machine's own hostname, and
        the two need not agree. A machine whose hostname is C(DXP4800GT-9A5F) can
        be a device the tailnet calls C(risa), and it is by C(risa) that a task
        finds it. A device the tailnet has renamed is found by the label it holds
        now, not by the hostname it was given when it joined.
      - M(abn.tailscale.tailscale_device_info) returns C(name) and C(hostname)
        for every device, which is the quickest way to see which of the two a task
        should use.
    type: str
    version_added: 0.1.0
  address:
    description:
      - The device to manage, by a Tailscale IP it holds.
      - Either address family is accepted, and a device holding several matches on
        any one of them.
    type: str
    version_added: 0.1.0
  tag:
    description:
      - The device to manage, by a tag it carries.
      - A tag is a poor way to name one device, because a tag is usually held by
        several. The module refuses rather than choosing, so this is a selector
        for a tailnet where exactly one device carries the tag, and for
        O(state=absent) over a whole group of them.
    type: str
    version_added: 0.1.0
  name:
    description:
      - The label to give the device.
      - Tailscale rewrites a name it is sent, lowercasing it and turning dots and
        underscores into dashes, and the tailnet then holds something other than
        what the task asked for. The module therefore accepts only a name already
        in the form Tailscale keeps and refuses any other, rather than reporting a
        change on every run.
    type: str
    version_added: 0.1.0
  tags:
    description:
      - The tags the device should carry, which replaces whatever it carries now.
      - Compared without regard to order, because the API returns the tags in its
        own order.
      - The API refuses to take the last tag off a tagged device, on the grounds
        that a device has to authenticate again to shed its identity. Asking for
        an empty list on a device carrying a tag is therefore a failure and not a
        change.
      - A tag has to be granted to an owner in the policy file, which is
        M(abn.tailscale.tailscale_policy)'s business and not this module's.
    type: list
    elements: str
    version_added: 0.1.0
  authorized:
    description:
      - Whether the device is authorized to join the tailnet.
      - Revoking an approval logs the device out. Measured against the real API, a
        device whose approval is revoked is disconnected within seconds and has to
        authenticate again before it can reach anything, so C(false) is a way to
        de-approve a device and a way to force one to authenticate again, rather
        than a quiet administrative setting.
      - A device that joined without being pre-authorized arrives unapproved, so a
        task asking for C(false) on one is quiet.
    type: bool
    version_added: 0.1.0
  key_expiry_disabled:
    description:
      - Whether the device's keys are exempt from expiry.
      - This is the per-device setting. The tailnet-wide duration a new device
        gets is the C(devices_key_duration_days) option of
        M(abn.tailscale.tailscale_settings), and this option does not duplicate
        it.
      - Re-enabling expiry does not extend the key. The API restores the expiry
        the key would have had, which may already have passed, and a device whose
        key has passed has to authenticate again.
    type: bool
    version_added: 0.1.0
  tailscale_ip:
    description:
      - The Tailscale IPv4 address the device should hold.
      - The API accepts an IPv4 address only, and only one from the tailnet's pool.
      - Changing it breaks every existing connection to the device, and a device
        that is the control node of the connection Ansible is running over loses
        the connection it is running over.
    type: str
    version_added: 0.1.0
  expire_key:
    description:
      - Whether to expire the device's node key, which makes it authenticate again.
      - The expiry a device already carries is visible to the API, so a second run
        over the same task reports no change rather than expiring the key again.
    type: bool
    default: false
    version_added: 0.1.0
"""

EXAMPLES = r"""
- name: Approve a device that joined while approval was required
  abn.tailscale.tailscale_device:
    api_token: "{{ tailscale_api_token }}"
    device_name: build-host
    authorized: true

- name: Revoke a device's approval, which logs it out until it authenticates again
  abn.tailscale.tailscale_device:
    api_token: "{{ tailscale_api_token }}"
    address: 100.101.102.103
    authorized: false

- name: Rename a device, selected by the ID because its name is what changes
  abn.tailscale.tailscale_device:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    tailnet: "-1234567890123"
    device_id: n1234CNTRL
    name: build-host

- name: Apply one key setting to every device carrying a tag
  abn.tailscale.tailscale_device:
    api_token: "{{ tailscale_api_token }}"
    tag: tag:build
    key_expiry_disabled: true

- name: Expire a lost device's key so it has to authenticate again
  abn.tailscale.tailscale_device:
    api_token: "{{ tailscale_api_token }}"
    device_id: n1234CNTRL
    expire_key: true

- name: Remove a device from the tailnet
  abn.tailscale.tailscale_device:
    api_token: "{{ tailscale_api_token }}"
    device_name: retired-host
    state: absent

- name: Report what would change without writing it
  abn.tailscale.tailscale_device:
    api_token: "{{ tailscale_api_token }}"
    device_name: build-host
    authorized: true
  check_mode: true
"""

RETURN = r"""
devices:
  description:
    - The device documents this run concerned, in the API's own spelling.
    - Under O(state=present) this is the one device the selector named, read back
      after any write, so it is what the tailnet holds rather than what was sent.
      Under O(state=absent) it is the devices that were deleted, since a deleted
      device cannot be read. It is empty when the selector matched nothing under
      O(state=absent).
  returned: always
  type: list
  elements: dict
  sample:
    - id: "3133440773018733"
      nodeId: n6Ka9CB9UR11CNTRL
      hostname: build-host
      name: build-host.tail1234.ts.net
      tags:
        - tag:build
      authorized: true
changed_devices:
  description:
    - The devices this run changed, each with the properties it changed, named as
      this module's options spell them. Empty when the run changed none. A
      deletion lists C(exists), because a device that is gone holds no properties
      left to name.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: The identifier of the device that was changed.
      returned: always
      type: str
      sample: n6Ka9CB9UR11CNTRL
    properties:
      description: The names of the properties this run changed.
      returned: always
      type: list
      elements: str
      sample:
        - authorized
diff:
  description:
    - The value of each property this run changed, before and after, rendered by
      C(--diff) and keyed by device ID. It covers only those properties, because a
      diff across a whole device document would bury the line that matters. A
      device this run deleted appears under C(before) and not under C(after). Both
      sides are equal when nothing would change.
  returned: always
  type: dict
  contains:
    before:
      description: The value each changed property holds now.
      returned: always
      type: dict
    after:
      description: The value each changed property was set to, or would be set to.
      returned: always
      type: dict
"""

from datetime import UTC
from datetime import datetime
from ipaddress import IPv4Address

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import SELECTORS
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import DeviceError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import check_name
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import listing
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import present
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import remove
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import resolve
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import (
    connection_arguments,
)

#: No option carries a default except O(state) and O(expire_key), so an option left
#: out arrives as None and is dropped from the comparison. A default would make
#: "not mentioned" indistinguishable from "set to false", and every property here
#: is its own endpoint, so sending an unmentioned one would be asking for a change
#: the task never made.
ARGUMENT_SPEC = connection_arguments(
    state={"type": "str", "choices": ["present", "absent"], "default": "present"},
    device_id={"type": "str"},
    device_name={"type": "str"},
    address={"type": "str"},
    tag={"type": "str"},
    name={"type": "str"},
    tags={"type": "list", "elements": "str"},
    authorized={"type": "bool"},
    key_expiry_disabled={"type": "bool"},
    tailscale_ip={"type": "str"},
    # Matches the secret-name pattern on "key", and is not a secret.
    expire_key={"type": "bool", "default": False, "no_log": False},
)

#: Every pair of the four selectors, because a task naming a device two ways has two
#: chances to be wrong about which device it means. Derived from the kernel's own
#: list rather than written out, so a selector added there is a pair added here.
_SELECTOR_PAIRS = [
    (SELECTORS[first], SELECTORS[second])
    for first in range(len(SELECTORS))
    for second in range(first + 1, len(SELECTORS))
]


#: The properties a deletion would never apply, so a task that sets one alongside
#: O(state=absent) is refused rather than half-honoured. C(expire_key) is handled
#: apart from these, because it carries a default and only a task asking for it is
#: contradictory.
_NEVER_APPLIED_TO_A_DELETED_DEVICE = (
    "name",
    "tags",
    "authorized",
    "key_expiry_disabled",
    "tailscale_ip",
)


def check_task(params: dict) -> None:
    """Refuse a task that cannot be carried out, before any request is made.

    Three refusals, and each costs a request and a confusing error to discover from
    the server instead: a name the API rewrites, an address it will not accept, and
    properties a task cannot reconcile on a device it is removing.
    """
    if params.get("name") is not None:
        check_name(params["name"])
    if params.get("tailscale_ip") is not None:
        check_address(params["tailscale_ip"])
    if params.get("state") == "absent":
        named = [
            option
            for option in _NEVER_APPLIED_TO_A_DELETED_DEVICE
            if params.get(option) is not None
        ]
        if params.get("expire_key"):
            named.append("expire_key")
        if named:
            raise DeviceError(
                f"state is absent, so a device that is removed holds no properties, and "
                f"{', '.join(named)} would never be applied. Drop them from the task, or "
                f"reconcile them in a task that leaves the device in place. Nothing was "
                f"changed."
            )


def check_address(address: str) -> None:
    """Refuse an address the API would not accept.

    The API's own refusal is a 400 whose message names malformed JSON rather than
    the address, so a task with a typo in it would fail without saying which value
    was wrong.
    """
    try:
        IPv4Address(address)
    except ValueError:
        raise DeviceError(
            f"'{address}' is not an IPv4 address, and the API accepts an IPv4 address "
            "for a device only. A Tailscale IPv6 address cannot be set on one."
        ) from None


def run(module: AnsibleModule) -> None:
    try:
        check_task(module.params)
        api = build_client(module.params)
        absent = module.params["state"] == "absent"
        selection = resolve(listing(api), module.params, many=absent)
        if absent:
            outcome = remove(api, selection.devices, check_mode=module.check_mode)
        else:
            outcome = present(
                api,
                selection.devices,
                module.params,
                datetime.now(UTC),
                check_mode=module.check_mode,
            )
        module.exit_json(
            changed=bool(outcome.changed),
            devices=outcome.devices,
            changed_devices=outcome.changed,
            # The callback reads `result['diff']` and nothing else. A top-level
            # `before` and `after` look equivalent and render nothing at all.
            diff={"before": outcome.before, "after": outcome.after},
        )
    except (CredentialError, DeviceError) as error:
        module.fail_json(msg=str(error))
    except TailscaleError as error:
        module.fail_json(msg=str(error))


def main() -> None:
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        required_one_of=[list(SELECTORS)],
        mutually_exclusive=[
            *_SELECTOR_PAIRS,
            ("api_token", "oauth_client_id"),
            ("api_token", "oauth_client_secret"),
        ],
        required_together=[("oauth_client_id", "oauth_client_secret")],
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
