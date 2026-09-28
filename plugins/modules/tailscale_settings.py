#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_settings
short_description: Manage the feature settings of a tailnet
version_added: 1.0.0
description:
  - Sets individual tailnet settings, such as whether joining a device needs
    approval and how long an authorisation key lasts.
  - The endpoint merges, so an option this module is not given is left as the
    tailnet already has it. Every option is optional and the module writes only
    when a value it was asked for differs from the one already there.
  - Only the options given are compared. A setting this module does not manage
    cannot make a run report a change, however the server chooses to report it.
  - Option names are snake case, as Ansible requires. The API spells the same
    fields in camel case, and the mapping happens here.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.check_mode_diff_mode
  - abn.tailscale._attributes.connection_delegation
options:
  devices_approval_on:
    description: Whether a new device must be approved before it can join.
    type: bool
    version_added: 1.0.0
  devices_auto_updates_on:
    description: Whether devices update themselves automatically.
    type: bool
    version_added: 1.0.0
  devices_key_duration_days:
    description: How long an authorisation key stays valid, in days.
    type: int
    version_added: 1.0.0
  users_approval_on:
    description: Whether a new user must be approved before joining.
    type: bool
    version_added: 1.0.0
  users_role_allowed_to_join_external_tailnets:
    description:
      - The role a user needs before they may join a tailnet outside this one.
    type: str
    version_added: 1.0.0
  network_flow_logging_on:
    description: Whether the tailnet records network flow logs.
    type: bool
    version_added: 1.0.0
  regional_routing_on:
    description: Whether regional routing is available to the tailnet.
    type: bool
    version_added: 1.0.0
  posture_identity_collection_on:
    description: Whether device posture identity collection is enabled.
    type: bool
    version_added: 1.0.0
  https_enabled:
    description: Whether HTTPS certificates are enabled for the tailnet.
    type: bool
    version_added: 1.0.0
  acls_externally_managed_on:
    description:
      - Whether the access control policy is managed outside Tailscale.
    type: bool
    version_added: 1.0.0
  acls_external_link:
    description:
      - Where the externally managed policy lives.
    type: str
    version_added: 1.0.0
"""

EXAMPLES = r"""
- name: Require approval for devices, and keep authorisation keys for a year
  abn.tailscale.tailscale_settings:
    api_token: "{{ tailscale_api_token }}"
    devices_approval_on: true
    devices_key_duration_days: 365

- name: Leave every other setting alone
  abn.tailscale.tailscale_settings:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    tailnet: "-1234567890123"
    regional_routing_on: false

- name: Report what would change without writing it
  abn.tailscale.tailscale_settings:
    api_token: "{{ tailscale_api_token }}"
    network_flow_logging_on: true
  check_mode: true
"""

RETURN = r"""
changed_settings:
  description:
    - The API field names of the settings this run changed, empty when it changed
      none.
  returned: always
  type: list
  elements: str
  sample:
    - devicesApprovalOn
diff:
  description:
    - The value of each setting this run changed, before and after, rendered by
      C(--diff). It covers only those settings. A value the API omits appears as
      V(none), and a setting this module does not manage is absent rather than
      shown unchanged, because a diff across the whole settings document would
      bury the line that matters.
  returned: always
  type: dict
  contains:
    before:
      description: The value each changed setting holds now.
      returned: always
      type: dict
    after:
      description: The value each changed setting was set to, or would be set to.
      returned: always
      type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import (
    connection_arguments,
)

#: Module option to API field. The API is Go, and Go marshals to camel case.
_FIELDS = {
    "devices_approval_on": "devicesApprovalOn",
    "devices_auto_updates_on": "devicesAutoUpdatesOn",
    "devices_key_duration_days": "devicesKeyDurationDays",
    "users_approval_on": "usersApprovalOn",
    "users_role_allowed_to_join_external_tailnets": "usersRoleAllowedToJoinExternalTailnets",
    "network_flow_logging_on": "networkFlowLoggingOn",
    "regional_routing_on": "regionalRoutingOn",
    "posture_identity_collection_on": "postureIdentityCollectionOn",
    "https_enabled": "httpsEnabled",
    "acls_externally_managed_on": "aclsExternallyManagedOn",
    "acls_external_link": "aclsExternalLink",
}

#: No option carries a default, so one left out arrives as None and is dropped
#: from the request. A default would make "not mentioned" indistinguishable from
#: "set to false", and on a merging endpoint those are different instructions.
ARGUMENT_SPEC = connection_arguments(
    devices_approval_on={"type": "bool"},
    devices_auto_updates_on={"type": "bool"},
    # Matches the secret-name pattern on "key", but it is a number of days.
    devices_key_duration_days={"type": "int", "no_log": False},
    users_approval_on={"type": "bool"},
    users_role_allowed_to_join_external_tailnets={"type": "str"},
    network_flow_logging_on={"type": "bool"},
    regional_routing_on={"type": "bool"},
    posture_identity_collection_on={"type": "bool"},
    https_enabled={"type": "bool"},
    acls_externally_managed_on={"type": "bool"},
    acls_external_link={"type": "str"},
)


def wanted(params: dict) -> dict:
    """The API fields for the options that were given, and only those.

    No option carries a default, so an option left out arrives as None and is
    dropped here. That is what makes the endpoint's merge semantics visible: a
    field absent from the request is a field the server leaves alone.
    """
    patch: dict = {}
    for option, field in _FIELDS.items():
        value = params.get(option)
        if value is None:
            continue
        patch[field] = value
    return patch


def differing(patch: dict, current: dict) -> dict:
    """The subset of `patch` the tailnet does not already hold.

    Only the requested fields are compared. Comparing whole documents would let
    a setting this module does not manage report a change on every run, and the
    operator would have no way to make it stop.
    """
    return {field: value for field, value in patch.items() if current.get(field) != value}


def run(module: AnsibleModule) -> None:
    try:
        api = build_client(module.params)
        current = api.call("tailnet_settings_get", "GET").body
        # Substituting an empty document is safe here and is not safe in the DNS
        # module, which replaces rather than merges. A PATCH naming only the
        # requested fields changes only those fields, so there is nothing to lose.
        current = current if isinstance(current, dict) else {}
        change = differing(wanted(module.params), current)
        # Scoped to the fields being changed rather than to the whole settings
        # document, which carries many this module does not manage. A diff
        # across all of them would bury the one line that matters.
        before = {field: current.get(field) for field in change}
        if not change:
            module.exit_json(
                changed=False,
                changed_settings=[],
                diff={"before": before, "after": before},
            )
        if not module.check_mode:
            api.call("tailnet_settings_update", "PATCH", body=change)
        module.exit_json(
            changed=True,
            changed_settings=sorted(change),
            # The callback reads `result['diff']` and nothing else. A top-level
            # `before` and `after` look equivalent and render nothing at all.
            diff={"before": before, "after": change},
        )
    except CredentialError as error:
        module.fail_json(msg=str(error))
    except TailscaleError as error:
        module.fail_json(msg=str(error))


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
