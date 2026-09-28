#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_device_attributes
short_description: Manage the custom posture attributes of a device
version_added: 0.1.0
description:
  - Reconciles the user-managed posture attributes of one device, which are the
    attributes a client writes under the C(custom:) namespace.
  - The endpoint merges, so an attribute this module is not given is left as the
    device already has it. Only the attributes named are compared, and the write
    names only those that differ.
  - An attribute is removed by naming it with O(attributes[].state=absent). The
    service-managed C(node:) attributes are read but never written, because the
    API accepts no user-managed attribute outside C(custom:).
  - A device cannot be created, so a task selects one the tailnet already holds,
    with exactly one of O(device_id), O(device_name), O(address) or O(tag). A
    selector matching no device is a failure, and so is one matching several.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.check_mode_diff_mode
  - abn.tailscale._attributes.connection_delegation
options:
  attributes:
    description:
      - The custom posture attributes this task manages, each with the key it is
        stored under and the value it should hold.
      - A key is in the C(custom:) namespace and no other.
      - A value is a string, an integer or a boolean, which are the three types
        the API accepts.
      - A key left out of this list is left as the device holds it.
    type: list
    elements: dict
    required: true
    version_added: 0.1.0
    suboptions:
      key:
        description:
          - The attribute key, prefixed with C(custom:).
          - Keys are at most 128 characters and hold letters, numbers,
            underscores and colons only.
        type: str
        required: true
        version_added: 0.1.0
      value:
        description:
          - The value the attribute should hold.
          - Required when O(attributes[].state=present), and ignored when it is
            C(absent).
        type: raw
        version_added: 0.1.0
      state:
        description:
          - Whether the attribute should be present with O(attributes[].value),
            or absent from the device.
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
        several. The module refuses rather than choosing.
    type: str
    version_added: 0.1.0
"""

EXAMPLES = r"""
- name: Record that a device has disk encryption on
  abn.tailscale.tailscale_device_attributes:
    api_token: "{{ tailscale_api_token }}"
    device_name: laptop-01
    attributes:
      - key: custom:diskEncryption
        value: true
      - key: custom:owner
        value: alice

- name: Drop an attribute the device no longer needs
  abn.tailscale.tailscale_device_attributes:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    tailnet: "-1234567890123"
    device_id: n1234CNTRL
    attributes:
      - key: custom:staleFlag
        state: absent

- name: Report what would change without writing it
  abn.tailscale.tailscale_device_attributes:
    api_token: "{{ tailscale_api_token }}"
    address: 100.64.0.5
    attributes:
      - key: custom:owner
        value: alice
  check_mode: true
"""

RETURN = r"""
device:
  description:
    - The device the attributes belong to, as the API returned it.
  returned: always
  type: dict
  sample:
    id: "3133440773018733"
    nodeId: n6Ka9CB9UR11CNTRL
    hostname: laptop-01
    name: laptop-01.tail1234.ts.net
attributes:
  description:
    - The custom attributes the device holds after the run, keyed as the API
      stores them. Service-managed C(node:) attributes are not included, because
      this module does not manage them.
  returned: always
  type: dict
  sample:
    custom:diskEncryption: true
    custom:owner: alice
changed_attributes:
  description:
    - The attribute keys this run wrote or removed, empty when it changed none.
  returned: always
  type: list
  elements: str
  sample:
    - custom:diskEncryption
diff:
  description:
    - The value of each attribute this run changed, before and after, rendered by
      C(--diff). It covers only those attributes. An attribute that is absent on
      one side appears as V(none), and an attribute this module is not given is
      absent rather than shown unchanged.
  returned: always
  type: dict
  contains:
    before:
      description: The value each changed attribute holds now.
      returned: always
      type: dict
    after:
      description: The value each changed attribute was set to, or would be set to.
      returned: always
      type: dict
"""

import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import SELECTORS
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import DeviceError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import identity
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import listing
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import resolve
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleNotFound,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import (
    connection_arguments,
)

ARGUMENT_SPEC = connection_arguments(
    attributes={
        "type": "list",
        "elements": "dict",
        "required": True,
        "options": {
            # Matches the secret-name pattern on "key", but it is the attribute's
            # name rather than a credential.
            "key": {"type": "str", "required": True, "no_log": False},
            # A value is a string, an integer or a boolean, and the API keeps the
            # type. `raw` is what stops Ansible turning a boolean into the string
            # "True" before it is compared with what the device holds.
            "value": {"type": "raw"},
            "state": {"type": "str", "choices": ["present", "absent"], "default": "present"},
        },
    },
    device_id={"type": "str"},
    device_name={"type": "str"},
    address={"type": "str"},
    tag={"type": "str"},
)

#: Every pair of the four selectors, because a task naming a device two ways has two
#: chances to be wrong about which device it means. Derived from the kernel's own
#: list rather than written out, so a selector added there is a pair added here.
_SELECTOR_PAIRS = [
    (SELECTORS[first], SELECTORS[second])
    for first in range(len(SELECTORS))
    for second in range(first + 1, len(SELECTORS))
]

#: The only namespace a user-managed attribute can live in. The API refuses any
#: other, so the refusal is made here where it can name the option.
_NAMESPACE = "custom:"

#: The API limit on a key, including the namespace prefix.
_MAX_KEY_LENGTH = 128

#: The characters the API accepts in a key, after the ``custom:`` namespace.
_KEY_PATTERN = re.compile(r"^custom:[A-Za-z0-9_:]+$")

#: The three types the API stores for a value. `bool` is checked before `int`
#: because it is a subclass of `int`, and a float is not a JSON safe integer.
_VALUE_TYPES = (str, bool, int)


def _check_key(key: str) -> None:
    """Refuse a key the API will not store.

    A malformed key is a request that can only fail, and the failure would arrive
    after a device has been selected and a read made. Refusing it here names the
    option's own spelling instead.
    """
    if len(key) > _MAX_KEY_LENGTH:
        raise DeviceError(
            f"An attribute key is at most {_MAX_KEY_LENGTH} characters including the "
            f"namespace, and '{key[:40]}' is {len(key)}."
        )
    if not _KEY_PATTERN.match(key):
        raise DeviceError(
            f"'{key[:40]}' is not an attribute key the API stores. A user-managed key "
            f"is prefixed with '{_NAMESPACE}' and holds only letters, numbers, "
            f"underscores and colons."
        )


def entries(params: dict) -> list[tuple[str, str, object]]:
    """The task's attributes as (key, state, value) triples, refused if malformed.

    A value is required for a present attribute, and the check is on its absence
    rather than on its truth: ``false`` and ``0`` are values a task may ask for.
    """
    shaped: list[tuple[str, str, object]] = []
    seen: set[str] = set()
    for entry in params["attributes"]:
        key = str(entry.get("key") or "")
        _check_key(key)
        # The API checks key uniqueness case-insensitively, so two entries that
        # differ only in case are one attribute and a task asking for both has no
        # single answer.
        folded = key.casefold()
        if folded in seen:
            raise DeviceError(
                f"'{key[:40]}' is named more than once in this task, and the API "
                f"treats two keys differing only in case as one attribute."
            )
        seen.add(folded)

        state = str(entry.get("state") or "present")
        if state == "absent":
            shaped.append((key, state, None))
            continue

        value = entry.get("value")
        if value is None:
            raise DeviceError(
                f"Attribute '{key[:40]}' is present but no value was given. Give one, "
                f"or set its state to absent to remove it."
            )
        if isinstance(value, float) or not isinstance(value, _VALUE_TYPES):
            raise DeviceError(
                f"Attribute '{key[:40]}' has a value the API does not store. A value is "
                f"a string, an integer or a boolean."
            )
        shaped.append((key, state, value))
    return shaped


def custom(document: object) -> dict:
    """The custom attributes of a device, out of a read of all its attributes.

    A device always carries service-managed ``node:`` attributes, which this
    module reads and never compares. They are dropped here so a change they
    undergo on their own cannot make a run report a change.
    """
    if not isinstance(document, dict):
        return {}
    attributes = document.get("attributes")
    if not isinstance(attributes, dict):
        return {}
    return {str(key): value for key, value in attributes.items() if str(key).startswith(_NAMESPACE)}


def delta(current: dict, wanted: list[tuple[str, str, object]]) -> dict:
    """The merge patch this run would send, naming only what differs.

    ``None`` is the API's way of deleting one attribute under JSON Merge Patch, so
    an absent attribute is a key mapped to ``None`` and a present one is a key
    mapped to an object carrying its value.
    """
    patch: dict = {}
    for key, state, value in wanted:
        if state == "absent":
            if key in current:
                patch[key] = None
        elif current.get(key) != value:
            patch[key] = {"value": value}
    return patch


def projected(current: dict, patch: dict) -> dict:
    """The custom attributes the device would hold if the patch were applied."""
    after = dict(current)
    for key, change in patch.items():
        if change is None:
            after.pop(key, None)
        else:
            after[key] = change["value"]
    return after


def rendered(patch: dict) -> dict:
    """The values of a patch, with a deletion shown as ``None``."""
    return {key: None if change is None else change["value"] for key, change in patch.items()}


def run(module: AnsibleModule) -> None:
    try:
        api = build_client(module.params)
        # The task's own spelling is checked before a device is selected or a read
        # is made, so a key the API cannot store fails without touching the tailnet.
        wanted = entries(module.params)
        selection = resolve(listing(api), module.params, many=False)
        device = selection.devices[0]
        device_id = identity(device)

        document = api.call("device_attributes_get", "GET", params={"deviceId": device_id}).body
        if not isinstance(document, dict):
            # A read this module cannot trust is not an empty device. Treating it as
            # one would let a proxy page or a captive portal make the next write
            # name every managed attribute, including ones the device already holds.
            module.fail_json(
                msg="The posture attributes read back were not a JSON object, so what "
                "the device holds is unknown and nothing was written."
            )
        current = custom(document)
        patch = delta(current, wanted)
        before = {key: current.get(key) for key in patch}

        if not patch:
            module.exit_json(
                changed=False,
                device=device,
                attributes=current,
                changed_attributes=[],
                diff={"before": before, "after": before},
            )
            return

        if module.check_mode:
            module.exit_json(
                changed=True,
                device=device,
                attributes=projected(current, patch),
                changed_attributes=sorted(patch),
                diff={"before": before, "after": rendered(patch)},
            )
            return

        api.call("device_attributes_batch_set", "PATCH", body={"nodes": {device_id: patch}})
        try:
            fresh = api.call("device_attributes_get", "GET", params={"deviceId": device_id}).body
        except TailscaleNotFound:
            # An ephemeral device can leave the tailnet between the write and the
            # read. The write happened, so the run reports what it set rather than
            # failing a task that did what it was asked.
            fresh = None
        after = custom(fresh) if isinstance(fresh, dict) else projected(current, patch)
        module.exit_json(
            changed=True,
            device=device,
            attributes=after,
            changed_attributes=sorted(patch),
            # The callback reads `result['diff']` and nothing else. A top-level
            # `before` and `after` look equivalent and render nothing at all.
            diff={"before": before, "after": rendered(patch)},
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
