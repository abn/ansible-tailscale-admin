# SPDX-License-Identifier: BSD-2-Clause
"""Operation table for the Tailscale Admin API v2, and the scopes each one needs.

This module is internal to ``abn.tailscale``. The underscore on the package path
is the declaration: the kernel may be refactored in any release without a major
version bump.

The table is hand-written Python literals rather than something derived from the
vendored OpenAPI description, because a module executes on the target host with
only the standard library and no YAML parser, so the description cannot be read
at runtime. ``test__spec.py`` asserts every entry against the vendored copy at
``tests/fixtures/openapi/tailscale.yaml``, which is what turns upstream drift into
a test failure rather than a 404 in production.

Three path shapes exist upstream, and mixing them up yields a plausible-looking
404 rather than a 400:

* tailnet-scoped, ``/tailnet/{tailnet}/...``, where ``{tailnet}`` accepts ``-``
  for the credential's own default tailnet;
* device-scoped, ``/device/{deviceId}/...``, which is *not* under a tailnet
  prefix at all;
* top-level, ``/users/{userId}/...``, ``/webhooks/{endpointId}/...``,
  ``/user-invites/{userInviteId}/...``, ``/posture/integrations/{id}/...``, none
  of which carry a tailnet prefix.
"""

from __future__ import annotations

import re
from typing import NamedTuple

# The API accepts a dash for the tailnet the credential itself belongs to, which
# is the right default because it survives the credential being moved. Held here
# so no call site re-derives the string.
TAILNET_DEFAULT = "-"

# The vendored description declares the API root in `servers` and its `paths`
# below it, so the table holds the path with no prefix while a request line
# carries one. Dropping it is what lets a real request resolve to a table entry.
API_PREFIX = "/api/v2"

_PATH_PARAMETER_RE = re.compile(r"\{([a-zA-Z]+)\}")

# The deprecated scope set. Only credentials created before 2024-11-14 hold
# these, and Tailscale documents a one-to-one replacement for each. This is the
# single statement of what must never appear in OPERATIONS, so the check is not
# made against a second, drifting copy of the list.
LEGACY_SCOPES = frozenset({"acl", "devices", "routes", "logs", "network-logs"})

# Authorisation is not always a single scope. Reading or writing the policy file
# also requires read access to devices, because a policy can name a device by its
# attributes and Tailscale grants those separately. That is the most common
# reason a credential which looks correctly scoped is still refused with a 403.
SCOPE_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "policy_file": ("devices:posture_attributes:read", "devices:core:read"),
    "policy_file:read": ("devices:posture_attributes:read", "devices:core:read"),
}


class Operation(NamedTuple):
    """One upstream operation, identified by a name a call site can hold.

    ``scopes`` lists every scope that can gate the call, most identifying first.
    The first entry is the one that names the operation and the one a failure
    message should quote; the rest gate a subset of what the operation touches,
    as ``tailnet_settings_get`` does.
    """

    name: str
    method: str
    path: str
    scopes: tuple[str, ...]


_TAIL = (
    # PolicyFile
    Operation("policy_get", "GET", "/tailnet/{tailnet}/acl", ("policy_file:read",)),
    Operation("policy_set", "POST", "/tailnet/{tailnet}/acl", ("policy_file",)),
    Operation("policy_validate", "POST", "/tailnet/{tailnet}/acl/validate", ("policy_file:read",)),
    # DNS. Neither operation carries an OAuth Scope annotation in the vendored
    # description. `dns` and `dns:read` come from Tailscale's trust-credential
    # documentation, which lists them among the current scopes and records that
    # the legacy split did not change for them. A test pins the absence of the
    # annotation so a future upstream addition gets reconciled rather than
    # silently ignored.
    Operation(
        "dns_configuration_get", "GET", "/tailnet/{tailnet}/dns/configuration", ("dns:read",)
    ),
    Operation("dns_configuration_set", "POST", "/tailnet/{tailnet}/dns/configuration", ("dns",)),
    # Devices
    Operation("device_list", "GET", "/tailnet/{tailnet}/devices", ("devices:core:read",)),
    Operation("device_get", "GET", "/device/{deviceId}", ("devices:core:read",)),
    Operation("device_delete", "DELETE", "/device/{deviceId}", ("devices:core",)),
    Operation("device_rename", "POST", "/device/{deviceId}/name", ("devices:core",)),
    Operation("device_set_tags", "POST", "/device/{deviceId}/tags", ("devices:core",)),
    Operation("device_authorize", "POST", "/device/{deviceId}/authorized", ("devices:core",)),
    Operation("device_set_key_expiry", "POST", "/device/{deviceId}/key", ("devices:core",)),
    Operation("device_set_ip", "POST", "/device/{deviceId}/ip", ("devices:core",)),
    Operation("device_expire_key", "POST", "/device/{deviceId}/expire", ("devices:core",)),
    # Device routes. Advertised routes are set by the node and cannot be written
    # through the API; these two only read what is advertised and enable a subset.
    Operation("device_routes_get", "GET", "/device/{deviceId}/routes", ("devices:routes:read",)),
    Operation("device_routes_set", "POST", "/device/{deviceId}/routes", ("devices:routes",)),
    # TailnetSettings. The API authorises these per field rather than per
    # operation, so every entry here is a real gate on a different subset of the
    # same document.
    Operation(
        "tailnet_settings_get",
        "GET",
        "/tailnet/{tailnet}/settings",
        (
            "feature_settings:read",
            "logs:network:read",
            "networking_settings:read",
            "policy_file:read",
        ),
    ),
    Operation(
        "tailnet_settings_update",
        "PATCH",
        "/tailnet/{tailnet}/settings",
        ("feature_settings", "logs:network", "networking_settings", "policy_file"),
    ),
    # Logging. The two log reads are separate operations because the API
    # authorises each on its own scope: a credential that may read the
    # configuration audit log is not thereby allowed to read the flow logs.
    # Measured on a free plan: the flow-log read answers 403 with "feature not
    # available on current billing plan", which is a billing refusal wearing a
    # permissions status, so `_unauthorised` has to recognise that wording.
    Operation(
        "logging_configuration_get",
        "GET",
        "/tailnet/{tailnet}/logging/configuration",
        ("logs:configuration:read",),
    ),
    Operation(
        "logging_network_get",
        "GET",
        "/tailnet/{tailnet}/logging/network",
        ("logs:network:read",),
    ),
    # Log streaming. `{logType}` is a path parameter rather than a field of the
    # configuration, because the description marks `logType` read-only: the
    # destination is chosen by the URL a PUT is sent to.
    Operation(
        "logging_stream_get",
        "GET",
        "/tailnet/{tailnet}/logging/{logType}/stream",
        ("log_streaming:read",),
    ),
    Operation(
        "logging_stream_set",
        "PUT",
        "/tailnet/{tailnet}/logging/{logType}/stream",
        ("log_streaming",),
    ),
    Operation(
        "logging_stream_delete",
        "DELETE",
        "/tailnet/{tailnet}/logging/{logType}/stream",
        ("log_streaming",),
    ),
    Operation(
        "logging_stream_status_get",
        "GET",
        "/tailnet/{tailnet}/logging/{logType}/stream/status",
        ("log_streaming:read",),
    ),
    # Keys. Tailscale authorises the four kinds of credential separately, so an
    # operation spanning more than one kind carries all of them.
    Operation(
        "keys_list",
        "GET",
        "/tailnet/{tailnet}/keys",
        ("api_access_tokens:read", "auth_keys:read", "oauth_keys:read", "federated_keys:read"),
    ),
    Operation(
        "keys_create",
        "POST",
        "/tailnet/{tailnet}/keys",
        ("auth_keys", "oauth_keys", "federated_keys"),
    ),
    Operation(
        "keys_get",
        "GET",
        "/tailnet/{tailnet}/keys/{keyId}",
        ("api_access_tokens:read", "auth_keys:read", "oauth_keys:read", "federated_keys:read"),
    ),
    Operation(
        "keys_set", "PUT", "/tailnet/{tailnet}/keys/{keyId}", ("oauth_keys", "federated_keys")
    ),
    Operation(
        "keys_delete",
        "DELETE",
        "/tailnet/{tailnet}/keys/{keyId}",
        ("api_access_tokens", "auth_keys", "oauth_keys", "federated_keys"),
    ),
    # Users. The list is tailnet-scoped; every per-user mutation is top-level.
    Operation("users_list", "GET", "/tailnet/{tailnet}/users", ("users:read",)),
    Operation("user_set_role", "POST", "/users/{userId}/role", ("users",)),
    Operation("user_approve", "POST", "/users/{userId}/approve", ("users",)),
    Operation("user_suspend", "POST", "/users/{userId}/suspend", ("users",)),
    Operation("user_restore", "POST", "/users/{userId}/restore", ("users",)),
    Operation("user_delete", "POST", "/users/{userId}/delete", ("users",)),
    # Services. A Service is created by a PUT to a name that does not exist yet,
    # so there is no create operation to record separately. The list and the single
    # read are `services:read`; the two reads under the Service record the write
    # scope upstream names rather than a read scope, because a host is a device and
    # approving one is a device action: the description annotates them `services`,
    # `devices:core` and a test asserts every recorded scope is named there.
    Operation("service_list", "GET", "/tailnet/{tailnet}/services", ("services:read",)),
    Operation(
        "service_get", "GET", "/tailnet/{tailnet}/services/{serviceName}", ("services:read",)
    ),
    Operation("service_set", "PUT", "/tailnet/{tailnet}/services/{serviceName}", ("services",)),
    Operation(
        "service_delete", "DELETE", "/tailnet/{tailnet}/services/{serviceName}", ("services",)
    ),
    Operation(
        "service_hosts_list",
        "GET",
        "/tailnet/{tailnet}/services/{serviceName}/devices",
        ("services", "devices:core"),
    ),
    Operation(
        "service_approval_get",
        "GET",
        "/tailnet/{tailnet}/services/{serviceName}/device/{deviceId}/approved",
        ("services", "devices:core"),
    ),
    Operation(
        "service_approval_set",
        "POST",
        "/tailnet/{tailnet}/services/{serviceName}/device/{deviceId}/approved",
        ("services", "devices:core"),
    ),
    # Contacts. One document per contact type, plus an action that resends a
    # verification email and changes no state this collection reconciles.
    Operation("contacts_get", "GET", "/tailnet/{tailnet}/contacts", ("account_settings:read",)),
    Operation(
        "contact_update",
        "PATCH",
        "/tailnet/{tailnet}/contacts/{contactType}",
        ("account_settings",),
    ),
    # Webhooks. The list is tailnet-scoped and every per-endpoint operation is
    # top-level, which is why an endpoint is addressed with no tailnet prefix once
    # its id is known. `test` and `rotate` are deliberately absent: one sends a real
    # event and one issues a secret, and neither changes a state a later read can
    # observe, so a task driving either could never reach `changed: 0`.
    Operation("webhook_list", "GET", "/tailnet/{tailnet}/webhooks", ("webhooks:read",)),
    Operation("webhook_create", "POST", "/tailnet/{tailnet}/webhooks", ("webhooks",)),
    Operation("webhook_get", "GET", "/webhooks/{endpointId}", ("webhooks:read",)),
    Operation("webhook_update", "PATCH", "/webhooks/{endpointId}", ("webhooks",)),
    Operation("webhook_delete", "DELETE", "/webhooks/{endpointId}", ("webhooks",)),
    # Device posture attributes. The tailnet-level operation is a batch write over
    # the whole set, and the per-device pair is one key at a time.
    Operation(
        "device_attributes_batch_set",
        "PATCH",
        "/tailnet/{tailnet}/device-attributes",
        ("devices:posture_attributes",),
    ),
    Operation(
        "device_attributes_get",
        "GET",
        "/device/{deviceId}/attributes",
        ("devices:posture_attributes:read",),
    ),
    Operation(
        "device_attribute_set",
        "POST",
        "/device/{deviceId}/attributes/{attributeKey}",
        ("devices:posture_attributes",),
    ),
    Operation(
        "device_attribute_delete",
        "DELETE",
        "/device/{deviceId}/attributes/{attributeKey}",
        ("devices:posture_attributes",),
    ),
    # AWS external id. The first creates one if the tailnet has none and returns it
    # otherwise, so it is a read as much as a write. The second is a validator.
    Operation(
        "aws_external_id_get", "POST", "/tailnet/{tailnet}/aws-external-id", ("log_streaming",)
    ),
    Operation(
        "aws_external_id_validate",
        "POST",
        "/tailnet/{tailnet}/aws-external-id/{id}/validate-aws-trust-policy",
        ("log_streaming",),
    ),
)

OPERATIONS: dict[str, Operation] = {operation.name: operation for operation in _TAIL}


def normalise_path(path: str) -> str:
    """Reduce a request path to the bare, queryless form used for comparison.

    Three shapes have to reduce to the same string, or resolution silently
    answers ``None`` for a request the table does hold: the absolute URL a
    transport layer hands over, the prefixed form of it, and the table's own
    template. A template carries no origin, no prefix, no query and no
    fragment, so it survives this unchanged.

    The query string is dropped because a device filter can carry a user's
    address while nothing downstream needs it, and a trailing slash is dropped
    because the API documents none.
    """
    remainder = path.partition("://")[2] if "://" in path else path
    _host, slash, tail = remainder.partition("/")
    remainder = "/" + tail if slash else "/"
    remainder = remainder.partition("?")[0].partition("#")[0]
    if remainder == API_PREFIX:
        remainder = ""
    elif remainder.startswith(API_PREFIX + "/"):
        remainder = remainder[len(API_PREFIX) :]
    if len(remainder) > 1 and remainder.endswith("/"):
        remainder = remainder[:-1]
    return remainder or "/"


def _path_parameters(path: str) -> tuple[str, ...]:
    return tuple(_PATH_PARAMETER_RE.findall(path))


def build_path(name: str, **params: str) -> str:
    """Render an operation's path, substituting its path parameters.

    An omitted ``tailnet`` renders as the ``-`` shorthand, so a caller that only
    ever wants the credential's own tailnet never spells it. An explicit
    ``tailnet`` is used verbatim, which is what makes the shorthand and an
    explicit tailnet id interchangeable at the call site.
    """
    if name not in OPERATIONS:
        raise ValueError(f"unknown operation: {name}")

    path = OPERATIONS[name].path
    expected = _path_parameters(path)
    supplied = dict(params)
    if "tailnet" in expected and "tailnet" not in supplied:
        supplied["tailnet"] = TAILNET_DEFAULT

    unexpected = sorted(set(supplied) - set(expected))
    if unexpected:
        names = ", ".join(repr(parameter) for parameter in unexpected)
        raise ValueError(f"operation {name} takes no {names}")
    missing = [parameter for parameter in expected if parameter not in supplied]
    if missing:
        names = ", ".join(repr(parameter) for parameter in missing)
        raise ValueError(f"operation {name} needs {names}")

    def substitute(match: re.Match) -> str:
        return str(supplied[match.group(1)])

    return _PATH_PARAMETER_RE.sub(substitute, path)


def is_tailnet_scoped(operation: Operation) -> bool:
    """Whether the operation is addressed through ``/tailnet/{tailnet}/``."""
    return normalise_path(operation.path).startswith("/tailnet/{tailnet}/")


def _segments(path: str) -> tuple[str, ...]:
    return tuple(normalise_path(path).split("/"))


def _matches(operation: Operation, segments: tuple[str, ...]) -> bool:
    template = _segments(operation.path)
    if len(template) != len(segments):
        return False
    return all(
        expected.startswith("{") or expected == actual
        for expected, actual in zip(template, segments, strict=False)
    )


def resolve(method: str, path: str) -> Operation | None:
    """Find the operation a concrete request line refers to, or ``None``.

    Matching a concrete path against a template means treating every template
    parameter as matching any single segment. Where two table entries could both
    match, the answer is ``None`` rather than a guess, for the same reason a
    device selector matching two nodes is an error rather than a pick.
    """
    verb = method.upper()
    segments = _segments(path)
    matches = [
        operation
        for operation in OPERATIONS.values()
        if operation.method == verb and _matches(operation, segments)
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def scope_dependencies(scope: str) -> tuple[str, ...]:
    """Scopes that must be granted alongside ``scope``, or an empty tuple."""
    return SCOPE_DEPENDENCIES.get(scope, ())
