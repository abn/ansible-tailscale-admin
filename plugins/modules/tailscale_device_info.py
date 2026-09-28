#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_device_info
short_description: List the devices in a tailnet
version_added: 1.0.0
description:
  - Returns every device the tailnet holds. This is a read, not a resource. There
    is nothing to reconcile, nothing to create and nothing to delete, so the
    module always reports C(changed=False) and has no C(state).
  - The devices are the API's own documents, unaltered, because Tailscale adds
    fields to them and projecting a fixed shape would drop information a task
    needs. Each carries both address families in C(addresses), the MagicDNS name
    in C(name), and the machine name in C(hostname).
  - This is the list M(abn.tailscale.tailscale_device) selects one device from, so
    a device that module can manage is a device this returns.
  - A task that manages one device and wants its current state after the run reads
    it from that module's own return value. This module exists for the case that
    module cannot serve, which is naming no device and reading them all.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.connection_delegation
attributes:
  check_mode:
    description: >-
      The module only reads, so a check run reads and returns the same result as a
      real one. There is no write for check mode to hold back.
    support: full
  diff_mode:
    description: >-
      The module returns no diff. Rendering the devices a tailnet holds as a diff
      would describe the tailnet rather than a change this module made.
    support: none
"""

EXAMPLES = r"""
- name: Read every device in the tailnet
  abn.tailscale.tailscale_device_info:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
  register: tailnet_devices

- name: Show the MagicDNS name and IPv4 of each device
  ansible.builtin.debug:
    msg: "{{ item.name }} -> {{ item.addresses | first }}"
  loop: "{{ tailnet_devices.devices }}"

- name: Collect the address of one device by the name a role knows it by
  ansible.builtin.set_fact:
    nibbler_ipv4: >-
      {{
        tailnet_devices.devices
        | selectattr('name', 'search', '^nibbler\.')
        | map(attribute='addresses')
        | first
        | first
      }}
"""

RETURN = r"""
devices:
  description:
    - The devices the tailnet holds, in the order the API returned them. Empty when
      the tailnet holds none.
    - Each is the API's own C(Device) document, unaltered. C(addresses) is the IPv4
      followed by the IPv6, C(name) is the MagicDNS name, C(hostname) is the
      machine name, and C(nodeId) and C(id) are the two identifiers the API accepts
      wherever a device id is taken.
  returned: always
  type: list
  elements: dict
  sample:
    - addresses:
        - 100.87.74.78
        - fd7a:115c:a1e0:ac82:4843:ca90:697d:c36e
      id: "92960230385"
      nodeId: n292kg92CNTRL
      user: amelie@example.com
      name: pangolin.tailfe8c.ts.net
      hostname: pangolin
      os: linux
      authorized: true
      tags:
        - tag:lab
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import DeviceError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import listing
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import (
    connection_arguments,
)

ARGUMENT_SPEC = connection_arguments()


def run(module: AnsibleModule) -> None:
    try:
        api = build_client(module.params)
        devices = listing(api)
    except (CredentialError, DeviceError, TailscaleError) as error:
        module.fail_json(msg=str(error))

    module.exit_json(
        # A read has nothing to change. Reporting anything else would make every
        # run of a facts task look like a mutation of the tailnet.
        changed=False,
        devices=devices,
    )


def main() -> None:
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        required_together=[("oauth_client_id", "oauth_client_secret")],
        mutually_exclusive=[
            ("api_token", "oauth_client_id"),
            ("api_token", "oauth_client_secret"),
        ],
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
