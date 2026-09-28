# SPDX-License-Identifier: BSD-2-Clause
"""The connection options every module in this collection declares, once.

Internal to this collection. See ``.agents/rules/ansible.md`` for why the
``_tailscale`` package is private.

Why this file exists
--------------------
A module that talks to the Tailscale Admin API has the same eight connection
options, the same credential resolution and the same client construction as
every other one. Written out per module, the copies drift, and they drift
quietly: two of the three carried an unannotated ``post`` closure, so the type
of the transport was checked in one module and unchecked in the others.

The option *specifications* still have to appear in each module's
``ARGUMENT_SPEC``, because ``validate-modules`` reads each module's effective
dict and cross-checks it against the documentation fragment. It follows the
reference, so it does not need them copied in. ``ANSIBLE_TEST_CONTENT_ROOT``
staging copies this file, so the reference resolves on the target host.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import ApiOptions
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import post_form
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import Authoriser
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import from_options

__all__ = [
    "CONNECTION_ARGUMENTS",
    "build_client",
    "connection_arguments",
]


#: The eight options, in the order the documentation fragment documents them.
#: Kept as literals rather than derived from the fragment because a module's
#: argument spec has to be readable on its own and the fragment is prose.
CONNECTION_ARGUMENTS: dict[str, dict[str, Any]] = {
    "tailnet": {"type": "str", "default": "-"},
    "api_token": {"type": "str", "no_log": True},
    "oauth_client_id": {"type": "str"},
    "oauth_client_secret": {"type": "str", "no_log": True},
    "base_url": {"type": "str", "default": "https://api.tailscale.com/api/v2"},
    "validate_certs": {"type": "bool", "default": True},
    "ca_path": {"type": "path"},
    "timeout": {"type": "int", "default": 30},
}


def connection_arguments(**own: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """A module's own options, plus the connection options every module has.

    ``deepcopy`` guards a sharing hazard rather than a demonstrated one. As of
    ansible-core 2.21 the only in-place write to ``argument_spec`` is behind
    ``add_file_common_args``, which none of these modules passes, and default
    resolution mutates the parameters rather than the spec, so a shared constant
    would work today. It is copied anyway because the failure mode if that changes
    is a module whose spec has another module's defaults already resolved in it,
    which is silent, and the cost is one dict copy per module at import.
    """
    return {**deepcopy(CONNECTION_ARGUMENTS), **own}


def build_client(params: Mapping[str, Any]) -> Api:
    """Wire a module's resolved connection options into a client.

    Takes the mapping rather than the module, so nothing here imports
    ``AnsibleModule``. That class is available on the target host but is the
    heaviest thing in the tree to import, and ``module_utils`` is loaded before
    a module decides whether it needs it at all.

    The credential is resolved before anything is opened, so a task with no
    credential fails on the spot rather than after a request it had no business
    making.
    """
    options = ApiOptions(
        base_url=params["base_url"],
        tailnet=params["tailnet"],
        validate_certs=params["validate_certs"],
        ca_path=params["ca_path"] or "",
        timeout=params["timeout"],
    )
    credentials = from_options(
        api_token=params["api_token"],
        oauth_client_id=params["oauth_client_id"],
        oauth_client_secret=params["oauth_client_secret"],
    )

    def post(path: str, form: dict[str, str]) -> tuple[int, str]:
        return post_form(
            options.base_url,
            path,
            form,
            validate_certs=options.validate_certs,
            ca_path=options.ca_path,
            timeout=options.timeout,
        )

    return Api(options, Authoriser(credentials, post))
