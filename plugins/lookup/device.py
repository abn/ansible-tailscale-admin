# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
name: device
short_description: Look up one device in a tailnet
version_added: 1.0.0
description:
  - Resolves one device in the tailnet and returns one of its properties, for a
    template that needs a value rather than a list.
  - The term names the device the way M(abn.tailscale.tailscale_device) names one,
    which is the label part of its MagicDNS name, the whole MagicDNS name, an
    address it holds, or the id the API lists. A term matching no device, or more
    than one, is an error rather than a guess, so a template cannot silently read
    the wrong device.
  - The device list is read once per call, so a template resolving several devices
    makes one request each. A task that needs them all uses
    M(abn.tailscale.tailscale_device_info) instead.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._lookup_auth
options:
  _terms:
    description: The devices to resolve, one property each.
    required: true
  want:
    description:
      - Which property to return for each term.
      - C(ipv4) and C(ipv6) pick the address of that family. The API returns both
        in one list with the IPv4 first.
    type: str
    default: ipv4
    choices:
      - name
      - hostname
      - ipv4
      - ipv6
      - node_id
      - id
      - tags
"""

EXAMPLES = r"""
- name: Point a firewall rule at a host by the name its role already knows
  ansible.builtin.debug:
    msg: "{{ lookup('abn.tailscale.device', 'nibbler', want='ipv4') }}"

- name: Resolve several hosts at once
  ansible.builtin.debug:
    msg: "{{ item }}"
  loop: "{{ query('abn.tailscale.device', 'nibbler', 'canvas', want='name') }}"
"""

RETURN = r"""
_raw:
  description:
    - One value per term, in the order the terms were given, holding the property
      O(want) named.
    - C(tags) is a list, a device carrying none answers with an empty list, and
      every other choice is a string.
  type: list
  elements: raw
"""

from typing import Any

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import DeviceError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import listing
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import select
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
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

#: The selectors a term is tried against, in order. A label and a whole MagicDNS
#: name are one selector, so a term that is neither is next tried as an address and
#: then as an id.
_SELECTORS = ("device_name", "address", "device_id")


def client(plugin: Any) -> Any:
    """Build a client from a controller-side plugin's own resolved options."""
    return build_client({name: plugin.get_option(name) for name in _CONNECTION})


def _addresses(entry: dict) -> list[str]:
    addresses = entry.get("addresses")
    return [str(value) for value in addresses] if isinstance(addresses, list) else []


def _wanted(entry: dict, want: str, term: str) -> Any:
    if want == "name":
        return str(entry.get("name") or "")
    if want == "hostname":
        return str(entry.get("hostname") or "")
    if want == "node_id":
        return str(entry.get("nodeId") or "")
    if want == "id":
        return str(entry.get("id") or "")
    if want == "tags":
        tags = entry.get("tags")
        return [str(value) for value in tags] if isinstance(tags, list) else []
    family = "." if want == "ipv4" else ":"
    found = [address for address in _addresses(entry) if family in address]
    if not found:
        raise AnsibleError(
            f"The device {term!r} holds no {want} address, so nothing could be returned. A "
            "device that joined this tailnet holds both; one shared in from another may not."
        )
    return found[0]


def _resolve(devices: list[dict], term: str) -> dict:
    matches: list[dict] = []
    for selector in _SELECTORS:
        matches = select(devices, {selector: term}).devices
        if matches:
            break
    if not matches:
        raise AnsibleError(
            f"No device in the tailnet matches {term!r}, so nothing was returned. A device "
            "that has just been removed is the ordinary cause; a mistyped value is the other."
        )
    if len(matches) > 1:
        raise AnsibleError(
            f"{len(matches)} devices match {term!r}, so this lookup does not say which one it "
            "means. Name it by an address it holds, or by the id the API lists."
        )
    return matches[0]


class LookupModule(LookupBase):
    def run(self, terms: Any, variables: Any = None, **kwargs: Any) -> list[Any]:
        self.set_options(var_options=variables, direct=kwargs)
        want = self.get_option("want")

        try:
            devices = listing(client(self))
            return [_wanted(_resolve(devices, str(term)), want, str(term)) for term in terms]
        except (CredentialError, DeviceError, TailscaleError) as error:
            raise AnsibleError(str(error)) from error
