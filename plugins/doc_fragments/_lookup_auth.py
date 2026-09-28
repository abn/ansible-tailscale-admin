# SPDX-License-Identifier: GPL-3.0-or-later
"""Internal documentation fragment holding the connection options the lookup
plugins share.

Separate from ``_auth`` because a lookup resolves these from the variables a play
already holds. The action group in ``meta/runtime.yml`` carries the connection
options to a module and ``module_defaults`` applies to modules, but neither
reaches a lookup, so a variable is how a play sets one credential once for a
template.

The variable names are the ones the collection's own examples use for the value
they feed a module's option, so a play that already sets
``tailscale_api_token`` feeds a lookup without a second spelling.
"""

from __future__ import annotations


class ModuleDocFragment:
    DOCUMENTATION = r"""
options:
  tailnet:
    description: >-
      The tailnet to read, given as the tailnet ID or as a dash for the default
      tailnet of the credential in use.
    type: str
    default: '-'
    vars:
      - name: tailscale_tailnet
  api_token:
    description: >-
      A Tailscale API access token, recognisable by its C(tskey-api-) prefix.
      Mutually exclusive with O(oauth_client_id) and O(oauth_client_secret).
    type: str
    vars:
      - name: tailscale_api_token
  oauth_client_id:
    description: >-
      The client ID of a Tailscale OAuth client, which exchanges its secret for a
      short-lived access token. Must be set together with O(oauth_client_secret).
    type: str
    vars:
      - name: tailscale_oauth_client_id
  oauth_client_secret:
    description: >-
      The client secret of the Tailscale OAuth client, recognisable by its
      C(tskey-client-) prefix. Must be set together with O(oauth_client_id).
    type: str
    vars:
      - name: tailscale_oauth_client_secret
  base_url:
    description: >-
      The base URL of the Tailscale Admin API, which points a lookup at a test
      double standing in for the API.
    type: str
    default: https://api.tailscale.com/api/v2
  validate_certs:
    description: Whether the TLS certificate of the API endpoint is verified.
    type: bool
    default: true
  ca_path:
    description: >-
      Path to a PEM file of certificate authorities to trust in place of the
      system trust store.
    type: path
  timeout:
    description: >-
      Seconds to wait for one API request before failing.
    type: int
    default: 30
"""
