#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_dns
short_description: Manage the DNS configuration of a tailnet
version_added: 1.0.0
description:
  - Reconciles the DNS resolvers, split DNS mappings, search paths and
    preferences of a Tailscale tailnet.
  - The API replaces the whole configuration document, so an option this module
    is not given is left as the tailnet already has it rather than being reset.
    Every option is therefore optional, and the module writes only when the
    merged result differs from what is already there.
  - Option names are snake case, as Ansible requires. The API spells the same
    fields in camel case, and the mapping happens here.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.check_mode_diff_mode
  - abn.tailscale._attributes.connection_delegation
options:
  nameservers:
    description:
      - Global resolvers, used instead of the host's own when
        O(override_local_dns=true) and as fallbacks otherwise.
      - The order is the preference order and is preserved.
      - Each entry is either the resolver address as a string, or a mapping with
        C(address) and an optional C(use_with_exit_node). A string is the same as
        a mapping that gives only C(address), so the simple case needs no nesting.
      - An entry that does not give C(use_with_exit_node) keeps whatever the
        tailnet holds for that address, which is the rule the rest of this module
        follows for an option that was not given. The field is only ever sent as
        on, because the server stores a false as an absent key, so the module sends
        it for a resolver reachable through an exit node and omits it otherwise. A
        resolver that had it and no longer should is turned off by an explicit
        C(use_with_exit_node=false).
    type: list
    elements: raw
    version_added: 1.0.0
  split_dns:
    description:
      - A map from a domain suffix to the resolvers that serve it.
      - Each value is a list of resolvers in the same shape as O(nameservers),
        including the string form and the carry-forward of C(use_with_exit_node).
    type: dict
    version_added: 1.0.0
  search_paths:
    description:
      - Additional DNS search paths, which are searched after the tailnet's own.
    type: list
    elements: str
    version_added: 1.0.0
  magic_dns:
    description:
      - Whether MagicDNS resolves names of devices in the tailnet.
      - Left as the tailnet already has it when not given.
    type: bool
    version_added: 1.0.0
  override_local_dns:
    description:
      - Whether O(nameservers) replaces the host's own resolvers, rather than
        acting as fallbacks behind them.
      - Left as the tailnet already has it when not given.
    type: bool
    version_added: 1.0.0
"""

EXAMPLES = r"""
- name: Send every device to two resolvers, and take over from the host's own
  abn.tailscale.tailscale_dns:
    api_token: "{{ tailscale_api_token }}"
    nameservers:
      - 1.1.1.1
      - 2a07:a8c0::6e:1191
    override_local_dns: true

- name: Flag a resolver as reachable through an exit node
  abn.tailscale.tailscale_dns:
    api_token: "{{ tailscale_api_token }}"
    nameservers:
      - address: 1.1.1.1
        use_with_exit_node: true

- name: Route one domain to an internal resolver, leaving the rest alone
  abn.tailscale.tailscale_dns:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    tailnet: "-1234567890123"
    split_dns:
      internal.example.com:
        - address: 10.0.0.53

- name: Report what would change without writing it
  abn.tailscale.tailscale_dns:
    api_token: "{{ tailscale_api_token }}"
    magic_dns: true
  check_mode: true
"""

RETURN = r"""
dns_configuration:
  description:
    - The configuration the tailnet holds after the run, in the API's own camel
      case spelling.
  returned: always
  type: dict
  sample:
    nameservers:
      - address: 1.1.1.1
        useWithExitNode: true
    preferences:
      magicDNS: true
      overrideLocalDNS: true
diff:
  description:
    - The configuration as read and the configuration it was reconciled to,
      rendered by C(--diff). Both sides are equal when nothing would change, and
      C(after) is what a check run would have written.
  returned: always
  type: dict
  contains:
    before:
      description: The configuration as the tailnet held it.
      returned: always
      type: dict
    after:
      description: The configuration reconciled to.
      returned: always
      type: dict
"""

from collections.abc import Mapping
from typing import Any

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import (
    connection_arguments,
)

ARGUMENT_SPEC = connection_arguments(
    # `elements: raw` rather than `dict`, because an entry is either an address or
    # a mapping. The shape is checked in `address_of`, which can say what was wrong
    # with an entry where argument validation would only say that one was.
    nameservers={"type": "list", "elements": "raw"},
    split_dns={"type": "dict"},
    search_paths={"type": "list", "elements": "str"},
    magic_dns={"type": "bool"},
    override_local_dns={"type": "bool"},
)


#: Module option to API field, for the options that are a value rather than a set
#: of resolvers. `nameservers` and `split_dns` are built by `resolvers`, because a
#: resolver carries a field that has to be carried forward.
_FIELDS = {
    "search_paths": "searchPaths",
}

_PREFERENCES = {
    "magic_dns": "magicDNS",
    "override_local_dns": "overrideLocalDNS",
}


class ResolverError(Exception):
    """A resolver entry this module cannot read as one.

    A distinct type because it is this collection declining rather than Tailscale
    refusing, and the message says so.
    """


def address_of(entry: Any) -> str:
    """The address a resolver entry names, whether it is a string or a mapping."""
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict) and isinstance(entry.get("address"), str):
        return entry["address"]
    raise ResolverError(
        "A resolver entry is either an address or a mapping with an 'address', and "
        f"{entry!r} is neither. Give a string, or a mapping whose 'address' is a string."
    )


def resolver(entry: Any, held: Mapping[str, bool]) -> dict:
    """One resolver, in the shape the API expects.

    ``useWithExitNode`` is sent only when it is on. The server stores a ``false`` as
    an absent key, so sending one leaves a document that differs from the tailnet on
    every run. The key being absent is what the server reads as off, so a resolver
    that had the flag and no longer should is turned off by sending no key for it,
    which an explicit ``use_with_exit_node: false`` asks for.

    An entry that does not give the field takes the value the tailnet holds for that
    address, because an option a task did not give is left as the tailnet has it
    everywhere else in this module.
    """
    address = address_of(entry)
    given = entry.get("use_with_exit_node") if isinstance(entry, dict) else None
    flagged = bool(held.get(address)) if given is None else bool(given)

    shaped = {"address": address}
    if flagged:
        shaped["useWithExitNode"] = True
    return shaped


def resolvers(entries: list, held: Any) -> list:
    """The resolvers a task declared, with the tailnet's own values carried forward.

    ``held`` is the list the tailnet has for the same place, which is what an entry
    that omits ``use_with_exit_node`` is matched against, by address.
    """
    known = {
        str(entry.get("address")): bool(entry.get("useWithExitNode"))
        for entry in (held or [])
        if isinstance(entry, dict) and entry.get("address")
    }
    return [resolver(entry, known) for entry in entries or []]


def desired_configuration(params: dict, current: dict) -> dict:
    """The current configuration with the options that were given applied over it.

    The endpoint replaces the whole document, so anything this module is not told
    about has to come from what the tailnet already has. Sending a default
    instead would silently reset a field the operator never mentioned, which on a
    replace endpoint is indistinguishable from asking for it.

    A value the server will not store is not sent. Measured against the real
    endpoint: a ``false`` and an empty collection are each accepted and each stored
    as an absent key, so ``{"splitDNS": {}}`` comes back with no ``splitDNS`` at all
    and ``{"preferences": {"magicDNS": false}}`` comes back as
    ``{"preferences": {}}``. Sending either would leave a document that differs from
    the tailnet on every run, and a task saying ``magic_dns: false`` would report a
    change for ever. So a value that is off is removed from what is sent rather than
    sent as ``false``, and an empty list or map clears its key rather than emptying
    it.
    """
    merged = dict(current)

    if params.get("nameservers") is not None:
        wanted = resolvers(params["nameservers"], current.get("nameservers"))
        if wanted:
            merged["nameservers"] = wanted
        else:
            # An empty list is how the resolvers are cleared, and the server stores
            # that as an absent key.
            merged.pop("nameservers", None)

    for option, field in _FIELDS.items():
        if params.get(option) is None:
            continue
        if params[option]:
            merged[field] = params[option]
        else:
            merged.pop(field, None)

    if params.get("split_dns") is not None:
        held = current.get("splitDNS")
        held = held if isinstance(held, dict) else {}
        wanted = {
            domain: resolvers(entries, held.get(domain))
            for domain, entries in params["split_dns"].items()
        }
        if wanted:
            merged["splitDNS"] = wanted
        else:
            # An empty map is how a domain is cleared, and the server drops an empty
            # map rather than storing it, so the key is removed here instead of being
            # sent. Sending it would leave the tailnet without the key and the task
            # still asking for one, so every run reported a change.
            merged.pop("splitDNS", None)

    # The block is left in place whatever it holds, because the server keeps an
    # empty one: a tailnet whose only preference is off reads back
    # `{"preferences": {}}`, and removing the key here would make every later run
    # differ from it over a block the task never mentioned.
    preferences = dict(merged.get("preferences") or {})
    for option, field in _PREFERENCES.items():
        if params.get(option) is None:
            continue
        if params[option]:
            preferences[field] = True
        else:
            # Dropped rather than sent as `false`, because the server drops it and a
            # key it will not store is a difference on every run.
            preferences.pop(field, None)
    if preferences or "preferences" in merged:
        merged["preferences"] = preferences

    return merged


def run(module: AnsibleModule) -> None:
    try:
        api = build_client(module.params)
        current = api.call("dns_configuration_get", "GET").body
        if not isinstance(current, dict):
            # This endpoint replaces the whole document, so merging into an empty
            # one would send back only the fields the task named and silently
            # discard every resolver the tailnet has. Reachable from a proxy
            # error page or a captive portal answering 200, so it fails instead.
            module.fail_json(
                msg="The DNS configuration read back was not a JSON object, so the "
                "tailnet's current resolvers could not be read and merging into "
                "them would discard them. Nothing was written."
            )
        merged = desired_configuration(module.params, current)
        if merged == current:
            module.exit_json(
                changed=False,
                dns_configuration=current,
                diff={"before": current, "after": current},
            )
        if not module.check_mode:
            api.call("dns_configuration_set", "POST", body=merged)
        module.exit_json(
            changed=True,
            dns_configuration=merged,
            # The callback reads `result['diff']` and nothing else. A top-level
            # `before` and `after` look equivalent and render nothing at all.
            diff={"before": current, "after": merged},
        )
    except (CredentialError, ResolverError, TailscaleError) as error:
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
