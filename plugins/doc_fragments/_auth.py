# SPDX-License-Identifier: GPL-3.0-or-later
"""Internal documentation fragment holding the connection options that every
module in this collection shares, so that no module retypes them and the action
group in meta/runtime.yml can supply them once.

The leading underscore on the file name is the declaration: this fragment is
private to the collection and may change in any release without a major version
bump. A module depends on it only by including it by FQCN.
"""

from __future__ import annotations


class ModuleDocFragment:
    # Every type and default below is cross-checked against the argument spec
    # of the including module, so the shared connection helper that builds those
    # specs has to declare the same values. Descriptions therefore never restate
    # a default: the cross-check reads the default key, not the prose.
    DOCUMENTATION = r"""
options:
  tailnet:
    description: >-
      The tailnet to manage, given as the tailnet ID or as a dash selecting the
      default tailnet of the credential in use. A dash is the right choice
      unless one playbook manages more than one tailnet.
    type: str
    default: '-'
    version_added: 0.1.0
  api_token:
    description: >-
      A Tailscale API access token, which is recognisable by its
      C(tskey-api-) prefix, expires within 90 days and carries the permissions
      of the user who created it. Mutually exclusive with C(oauth_client_id)
      and C(oauth_client_secret).
    type: str
    version_added: 0.1.0
  oauth_client_id:
    description: >-
      The client ID of a Tailscale OAuth client, which exchanges its secret for
      a short-lived access token and therefore does not expire. Must be set
      together with C(oauth_client_secret). Mutually exclusive with
      C(api_token).
    type: str
    version_added: 0.1.0
  oauth_client_secret:
    description: >-
      The client secret of the Tailscale OAuth client, which is recognisable by
      its C(tskey-client-) prefix. Must be set together with
      C(oauth_client_id). Mutually exclusive with C(api_token).
    type: str
    version_added: 0.1.0
  base_url:
    description: >-
      The base URL of the Tailscale Admin API, which points the modules at a
      test double standing in for the API.
    type: str
    default: https://api.tailscale.com/api/v2
    version_added: 0.1.0
  validate_certs:
    description: Whether the TLS certificate of the API endpoint is verified.
    type: bool
    default: true
    version_added: 0.1.0
  ca_path:
    description: >-
      Path to a PEM file of certificate authorities to trust in place of the
      system trust store, which is how a private certificate authority is
      trusted.
    type: path
    version_added: 0.1.0
  timeout:
    description: >-
      Seconds to wait for one API request before failing, which bounds a
      stalled connection rather than the time the module spends in total.
    type: int
    default: 30
    version_added: 0.1.0
"""
