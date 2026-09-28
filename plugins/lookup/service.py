# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
name: service
short_description: Look up one Service in a tailnet
version_added: 1.0.0
description:
  - Resolves one Service by name and returns one of its properties, for a template
    that needs a value rather than a list.
  - The term is the Service name, with the C(svc:) prefix. A name the tailnet does
    not hold is an error rather than an empty answer, so a template cannot treat a
    typo as a Service that is simply not there.
  - A task that does not know which Services exist reads them all with
    M(abn.tailscale.tailscale_service_info) instead.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._lookup_auth
options:
  _terms:
    description: The Service names to resolve, one property each.
    required: true
  want:
    description:
      - Which property to return for each term.
      - C(ipv4) and C(ipv6) pick the address of that family. The API returns both
        in C(addrs) with the IPv4 first.
    type: str
    default: ipv4
    choices:
      - name
      - display_name
      - comment
      - ipv4
      - ipv6
      - ports
      - tags
"""

EXAMPLES = r"""
- name: Point an ingress at a Service by name
  ansible.builtin.debug:
    msg: "{{ lookup('abn.tailscale.service', 'svc:web', want='ipv4') }}"

- name: List the ports a Service exposes
  ansible.builtin.debug:
    msg: "{{ query('abn.tailscale.service', 'svc:web', want='ports') }}"
"""

RETURN = r"""
_raw:
  description:
    - One value per term, in the order the terms were given, holding the property
      O(want) named.
    - C(ports) and C(tags) are lists, a Service holding neither answers with an
      empty list, and every other choice is a string.
  type: list
  elements: raw
"""

from typing import Any

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleNotFound,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client

#: The connection options, in the order the fragment documents them.
_CONNECTION = (
    "tailnet",
    "api_token",
    "oauth_client_id",
    "oauth_client_secret",
    "base_url",
    "validate_certs",
    "ca_path",
    "timeout",
)


def client(plugin: Any) -> Any:
    """Build a client from a controller-side plugin's own resolved options."""
    return build_client({name: plugin.get_option(name) for name in _CONNECTION})


def _addresses(entry: dict) -> list[str]:
    addresses = entry.get("addrs")
    return [str(value) for value in addresses] if isinstance(addresses, list) else []


def _strings(entry: dict, key: str) -> list[str]:
    values = entry.get(key)
    return [str(value) for value in values] if isinstance(values, list) else []


def _wanted(entry: dict, want: str, term: str) -> Any:
    if want == "name":
        return str(entry.get("name") or "")
    if want == "display_name":
        return str(entry.get("displayName") or "")
    if want == "comment":
        return str(entry.get("comment") or "")
    if want == "ports":
        return _strings(entry, "ports")
    if want == "tags":
        return _strings(entry, "tags")
    family = "." if want == "ipv4" else ":"
    found = [address for address in _addresses(entry) if family in address]
    if not found:
        raise AnsibleError(
            f"The Service {term!r} holds no {want} address, so nothing could be returned. The "
            "API assigns both when a Service is created."
        )
    return found[0]


def _resolve(api: Any, term: str) -> dict:
    try:
        body = api.call("service_get", "GET", params={"serviceName": term}).body
    except TailscaleNotFound as error:
        raise AnsibleError(
            f"The tailnet holds no Service named {term!r}. A name starts with 'svc:'; a task "
            "that does not know which Services exist reads them all with "
            "abn.tailscale.tailscale_service_info."
        ) from error
    if not isinstance(body, dict):
        raise AnsibleError(
            f"The Service {term!r} was read back as something other than a Service document, so "
            "nothing could be returned."
        )
    return body


class LookupModule(LookupBase):
    def run(self, terms: Any, variables: Any = None, **kwargs: Any) -> list[Any]:
        self.set_options(var_options=variables, direct=kwargs)
        want = self.get_option("want")

        try:
            api = client(self)
            return [_wanted(_resolve(api, str(term)), want, str(term)) for term in terms]
        except (CredentialError, TailscaleError) as error:
            raise AnsibleError(str(error)) from error
