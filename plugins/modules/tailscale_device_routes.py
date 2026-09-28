#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_device_routes
short_description: Manage the subnet routes enabled for a device
version_added: 0.1.0
description:
  - Reconciles the subnet routes a tailnet admin has enabled for a device, which
    is the list a device needs before it acts as a subnet router or an exit node.
  - Routes are advertised, not received. A device advertises the subnets it is
    willing to serve and no API call can change that, so this module enables
    among the routes a device has advertised. Enabling one the device has not
    advertised is accepted and stored, and takes effect when the device
    advertises it.
  - A device cannot be created, so a task selects one the tailnet already holds,
    with exactly one of O(device_id), O(device_name), O(address) or O(tag). A
    selector matching no device is a failure, and so is one matching several.
    There is no C(state) option, because the routes of a device that has been
    removed are not a thing to reconcile, so remove the device with
    M(abn.tailscale.tailscale_device).
  - An empty list clears the enabled routes, which is how a device is stopped
    acting as a subnet router or an exit node without deleting it. The API
    replaces the list rather than adding to it, so the list given is the whole
    list the device should have.
  - Compared without regard to order, because the API returns the routes in its
    own order.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.check_mode_diff_mode
  - abn.tailscale._attributes.connection_delegation
options:
  enabled_routes:
    description:
      - The subnet routes that should be enabled for the device, which replaces
        the list it has now.
      - An empty list clears them.
      - A route has to be a CIDR range, which is what the API accepts and what it
        stores.
    type: list
    elements: str
    required: true
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
- name: Enable the routes an office gateway advertises
  abn.tailscale.tailscale_device_routes:
    api_token: "{{ tailscale_api_token }}"
    device_name: office-gw
    enabled_routes:
      - 10.20.0.0/16
      - 10.21.0.0/16

- name: Let a device act as an exit node
  abn.tailscale.tailscale_device_routes:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    tailnet: "-1234567890123"
    device_id: n1234CNTRL
    enabled_routes:
      - 0.0.0.0/0
      - "::/0"

- name: Stop a device acting as a subnet router
  abn.tailscale.tailscale_device_routes:
    api_token: "{{ tailscale_api_token }}"
    device_id: n1234CNTRL
    enabled_routes: []

- name: Report what would change without writing it
  abn.tailscale.tailscale_device_routes:
    api_token: "{{ tailscale_api_token }}"
    device_name: office-gw
    enabled_routes:
      - 10.20.0.0/16
  check_mode: true
"""

RETURN = r"""
device:
  description:
    - The device the routes belong to, as the API returned it.
  returned: always
  type: dict
  sample:
    id: "3133440773018733"
    nodeId: n6Ka9CB9UR11CNTRL
    hostname: office-gw
    name: office-gw.tail1234.ts.net
routes:
  description:
    - The routes the device has, as the endpoint returned them after the run, so
      the advertised routes are reported alongside the enabled ones.
      - C(advertised_routes) is what the device asked to serve, which no API call
        changes.
      - C(enabled_routes) is what a tailnet admin enabled, which is what this
        module reconciles.
  returned: always
  type: dict
  contains:
    advertised_routes:
      description: The subnets the device requests to expose.
      returned: always
      type: list
      elements: str
      sample:
        - 10.20.0.0/16
    enabled_routes:
      description: The subnets an admin has enabled for the device.
      returned: always
      type: list
      elements: str
      sample:
        - 10.20.0.0/16
diff:
  description:
    - The enabled routes before and after, rendered by C(--diff). Both sides are
      equal when nothing would change, and C(after) is what a check run would
      have written.
  returned: always
  type: dict
  contains:
    before:
      description: The enabled routes the device holds now.
      returned: always
      type: list
      elements: str
    after:
      description: The enabled routes reconciled to, or what a check run would write.
      returned: always
      type: list
      elements: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import SELECTORS
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import DeviceError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import identity
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import listing
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import resolve
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import routes_wanted
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import (
    connection_arguments,
)

#: The routes have their own endpoint rather than being another property of the
#: device document, and they are the only thing this module reconciles, so it is
#: required. The four selectors are the same four the device module takes, and for
#: the same reason: a task that names a device two ways has two chances to be
#: wrong about which one it means.
ARGUMENT_SPEC = connection_arguments(
    enabled_routes={"type": "list", "elements": "str", "required": True},
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


def reported(routes: dict) -> dict:
    """The routes document, in the module's own spelling.

    The API spells the two lists in camel case, and the RETURN names them in snake
    case because the rest of this module's output is not the API's spelling either.
    Both lists are read with an absent key treated as an empty one, because the
    endpoint omits a list it holds none of rather than sending an empty one.
    """
    return {
        "advertised_routes": [str(route) for route in routes.get("advertisedRoutes") or []],
        "enabled_routes": [str(route) for route in routes.get("enabledRoutes") or []],
    }


def run(module: AnsibleModule) -> None:
    try:
        api = build_client(module.params)
        selection = resolve(listing(api), module.params, many=False)
        device = selection.devices[0]
        where = {"deviceId": identity(device)}

        current = api.call("device_routes_get", "GET", params=where).body
        current = current if isinstance(current, dict) else {}
        held = sorted(str(route) for route in current.get("enabledRoutes") or [])
        wanted = routes_wanted(current, module.params["enabled_routes"])

        if wanted is None or module.check_mode:
            after = current
        else:
            written = api.call(
                "device_routes_set", "POST", params=where, body={"routes": wanted}
            ).body
            after = written if isinstance(written, dict) else {}

        module.exit_json(
            changed=wanted is not None,
            device=device,
            routes=reported(after),
            # The callback reads `result['diff']` and nothing else. A top-level
            # `before` and `after` look equivalent and render nothing at all.
            diff={"before": held, "after": held if wanted is None else wanted},
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
