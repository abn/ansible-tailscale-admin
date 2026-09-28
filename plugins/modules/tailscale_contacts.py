#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_contacts
short_description: Manage the contact addresses of a tailnet
version_added: 0.1.0
description:
  - Reconciles the email address of each contact type a tailnet can hold. A
    tailnet has one account contact, one support contact and one security
    contact, and the API reads them as three keys of one document.
  - The update endpoint takes a single field, C(email), so a write sets the
    address of the type it names and touches no other type. Every option is
    optional and the module writes only when an address it was given differs
    from the one the tailnet already holds.
  - A contact cannot be cleared. The API refuses an empty address with a server
    error rather than a refusal naming the field, so the module declines an
    empty address before it makes the request.
  - Changing an address makes Tailscale send a verification email to it, and the
    contact then reports that it needs verification until somebody follows the
    link. Verification is not part of the reconciled state, so a task that sets
    the address the tailnet already holds writes nothing even while verification
    is pending. The resend endpoint is deliberately not exposed, because it sends
    an email and changes nothing the API reports, so a task driving it could
    never report C(changed=false) on a second run.
  - Option names are snake case, as Ansible requires. The API spells the same
    fields in camel case, and the mapping happens here.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.check_mode_diff_mode
  - abn.tailscale._attributes.connection_delegation
options:
  account:
    description:
      - The email address the tailnet keeps as its account contact.
    type: str
    version_added: 0.1.0
  support:
    description:
      - The email address the tailnet keeps as its support contact.
    type: str
    version_added: 0.1.0
  security:
    description:
      - The email address the tailnet keeps as its security contact.
    type: str
    version_added: 0.1.0
"""

EXAMPLES = r"""
- name: Send security notices to one mailbox and leave the other contacts alone
  abn.tailscale.tailscale_contacts:
    api_token: "{{ tailscale_api_token }}"
    security: security@example.com

- name: Set every contact, against a named tailnet
  abn.tailscale.tailscale_contacts:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    tailnet: "-1234567890123"
    account: owner@example.com
    support: support@example.com
    security: security@example.com

- name: Report what would change without writing it
  abn.tailscale.tailscale_contacts:
    api_token: "{{ tailscale_api_token }}"
    security: security@example.com
  check_mode: true
"""

RETURN = r"""
contacts:
  description:
    - Each contact the tailnet holds after the run, by contact type, in the
      API's own camel case spelling.
    - The email of a type this run changed is the address it was written to; the
      verification fields are those the read returned, because the write makes
      the server require verification and the API reports that only on the next
      read.
  returned: always
  type: dict
  sample:
    account:
      email: owner@example.com
      needsVerification: false
    support:
      email: support@example.com
      needsVerification: true
      fallbackEmail: old@example.com
    security:
      email: security@example.com
      needsVerification: false
changed_contacts:
  description:
    - The contact types this run changed, empty when it changed none.
  returned: always
  type: list
  elements: str
  sample:
    - security
diff:
  description:
    - The contact of each type this run changed, before and after, rendered by
      C(--diff). It covers only those types. A type this module does not manage
      is absent rather than shown unchanged, because a diff across the whole
      contacts document would bury the line that matters.
  returned: always
  type: dict
  contains:
    before:
      description: The contact each changed type held.
      returned: always
      type: dict
    after:
      description: The contact each changed type was set to, or would be set to.
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

#: The contact types the API accepts, and the order they are reported in. The
#: module's options carry the same names, so no separate mapping is needed.
_CONTACT_TYPES = ("account", "support", "security")

#: The fields of a contact this module returns. A whitelist, so a field the API
#: adds to its Contact schema later is not something this module has promised.
_CONTACT_FIELDS = ("email", "fallbackEmail", "needsVerification")

ARGUMENT_SPEC = connection_arguments(
    account={"type": "str"},
    support={"type": "str"},
    security={"type": "str"},
)


def wanted(params: dict) -> dict:
    """The email for the contact types the task gave an option for, and only those.

    No option carries a default, so one left out arrives as None and is dropped
    here. The endpoint takes one type per request, so what is dropped is exactly
    what is left alone.
    """
    return {
        contact_type: params[contact_type]
        for contact_type in _CONTACT_TYPES
        if params.get(contact_type) is not None
    }


def projection(document: dict) -> dict:
    """The contact types a document holds, reduced to the fields this module returns."""
    contacts: dict[str, dict] = {}
    for contact_type in _CONTACT_TYPES:
        contact = document.get(contact_type)
        if not isinstance(contact, dict):
            continue
        contacts[contact_type] = {
            field: contact[field] for field in _CONTACT_FIELDS if field in contact
        }
    return contacts


def differing(wanted_emails: dict, current: dict) -> dict:
    """The subset of the wanted emails the tailnet does not already hold.

    Only the address is compared, because it is the only field the update
    endpoint takes. The verification fields move on their own when the address
    changes, and comparing them would report a change on every run for a contact
    that is merely waiting for somebody to follow the link.
    """
    return {
        contact_type: email
        for contact_type, email in wanted_emails.items()
        if (current.get(contact_type) or {}).get("email") != email
    }


def reconciled(current: dict, change: dict) -> dict:
    """The read contacts with the changes applied, reduced to the returned fields."""
    contacts = projection(current)
    for contact_type, email in change.items():
        contacts.setdefault(contact_type, {})["email"] = email
    return contacts


def changed_only(contacts: dict, change: dict) -> dict:
    """The entries of `contacts` for the types this run changed, in type order."""
    return {contact_type: contacts[contact_type] for contact_type in sorted(change)}


def run(module: AnsibleModule) -> None:
    try:
        api = build_client(module.params)
        current = api.call("contacts_get", "GET").body
        if not isinstance(current, dict):
            # Substituting an empty document would make every address look
            # unset, so a task naming one contact would write it and every other
            # type's held address would go unreported rather than compared.
            # Reachable from a proxy error page answering 200, so it fails here.
            module.fail_json(
                msg="The contacts read back were not a JSON object, so the tailnet's "
                "current contacts could not be read. Nothing was written."
            )
        change = differing(wanted(module.params), current)
        for contact_type in sorted(change):
            if change[contact_type] == "":
                # The API answers an empty address with a 500 rather than a
                # refusal naming the field, so the server's own reason is no use
                # to the operator. There is also no endpoint that clears a
                # contact, so an empty address can only be a mistake.
                module.fail_json(
                    msg=f"The {contact_type} contact cannot be set to an empty address. "
                    "The API refuses one with a server error, and has no endpoint that "
                    "clears a contact. Give the address a real value, or drop the option "
                    "to leave the contact alone."
                )
        after = reconciled(current, change)
        before = changed_only(projection(current), change)
        if not change:
            module.exit_json(
                changed=False,
                contacts=after,
                changed_contacts=[],
                diff={"before": before, "after": before},
            )
        if not module.check_mode:
            for contact_type in sorted(change):
                api.call(
                    "contact_update",
                    "PATCH",
                    params={"contactType": contact_type},
                    body={"email": change[contact_type]},
                )
        module.exit_json(
            changed=True,
            contacts=after,
            changed_contacts=sorted(change),
            # The callback reads `result['diff']` and nothing else. A top-level
            # `before` and `after` look equivalent and render nothing at all.
            diff={"before": before, "after": changed_only(after, change)},
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
