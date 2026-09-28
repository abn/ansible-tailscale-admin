#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_service_info
short_description: List the Services published in a tailnet
version_added: 1.0.0
description:
  - Returns every Service the tailnet holds, as the API's C(vipServices) list. This
    is a read, not a resource. There is nothing to reconcile, so the module always
    reports C(changed=False) and has no C(state).
  - The Services are the API's own documents, unaltered. Each carries the name, the
    C(svc:) prefix included, both assigned addresses in C(addrs), and the ports,
    tags and display name it was created with.
  - This is the list a task reads when it does not yet know which Services exist.
    A task that already names one reads it through
    M(abn.tailscale.tailscale_service) instead.
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
      The module returns no diff. Rendering the Services a tailnet holds as a diff
      would describe the tailnet rather than a change this module made.
    support: none
"""

EXAMPLES = r"""
- name: Read every Service in the tailnet
  abn.tailscale.tailscale_service_info:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
  register: tailnet_services

- name: Show the name and IPv4 of each Service
  ansible.builtin.debug:
    msg: "{{ item.name }} -> {{ item.addrs | first }}"
  loop: "{{ tailnet_services.services }}"
"""

RETURN = r"""
services:
  description:
    - The Services the tailnet holds, in the order the API returned them. Empty
      when the tailnet holds none.
    - Each is the API's own C(VIPServiceInfo) document, unaltered. C(name) carries
      the C(svc:) prefix, C(addrs) is the IPv4 followed by the IPv6,
      C(displayName) and C(comment) are the labels a task set, and C(ports) and
      C(tags) are the access control the Service was created with.
  returned: always
  type: list
  elements: dict
  sample:
    - name: svc:example
      displayName: Example Service
      addrs:
        - 100.93.49.180
        - fd7a:115c:a1e0::3456:3cb4
      comment: Example Service
      ports:
        - tcp:80
        - tcp:443
      tags:
        - tag:web
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import (
    connection_arguments,
)

ARGUMENT_SPEC = connection_arguments()


class ServiceListError(Exception):
    """A response this module refuses to read as a Service list.

    A distinct type from the API's own failures, because it is this collection
    declining rather than Tailscale refusing, and the message says so.
    """


def _services_of(body: object) -> list[dict]:
    """The Services in a response body, refusing one that is not a Service list.

    A tailnet with no Services answers with an empty list rather than an absent
    key, but a body that is not an object at all is a different matter and is
    refused: reporting an empty tailnet from a response that never described it
    would be a claim about the tailnet the response does not support.
    """
    if not isinstance(body, dict) or not isinstance(body.get("vipServices"), list):
        raise ServiceListError(
            "The Service list came back in a form this module could not read, so the "
            "tailnet's Services could not be told from a response that never listed them."
        )
    return [entry for entry in body["vipServices"] if isinstance(entry, dict)]


def run(module: AnsibleModule) -> None:
    try:
        api = build_client(module.params)
        services = _services_of(api.call("service_list", "GET").body)
    except (CredentialError, ServiceListError, TailscaleError) as error:
        module.fail_json(msg=str(error))

    module.exit_json(
        # A read has nothing to change. Reporting anything else would make every
        # run of a facts task look like a mutation of the tailnet.
        changed=False,
        services=services,
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
