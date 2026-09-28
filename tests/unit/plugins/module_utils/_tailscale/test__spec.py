# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the hand-written operation table in ``_spec.py``."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import LEGACY_SCOPES
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import OPERATIONS
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import TAILNET_DEFAULT
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import build_path
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import (
    is_tailnet_scoped,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import normalise_path
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import resolve
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import (
    scope_dependencies,
)

# parents[0] is _tailscale, [1] module_utils, [2] plugins, [3] unit, [4] tests.
SPEC_PATH = Path(__file__).resolve().parents[4] / "fixtures" / "openapi" / "tailscale.yaml"

_PATH_PARAMETER_RE = re.compile(r"\{([a-zA-Z]+)\}")

# The path shapes upstream uses. A path outside all of them is a typo, and a typo
# here is a 404 that looks entirely plausible in a failure message.
_PATH_PREFIXES = (
    "/tailnet/{tailnet}/",
    "/device/{deviceId}/",
    "/device/{deviceId}",
    "/users/{userId}/",
    "/webhooks/{endpointId}",
)

# Concrete values for each path parameter, so a template can be rendered and
# matched back against the table.
_PARAMETER_VALUES = {
    "tailnet": TAILNET_DEFAULT,
    "attributeKey": "custom:example",
    "contactType": "account",
    "deviceId": "nABCD123456CNTRL",
    "endpointId": "123456",
    "id": "iABCD123456CNTRL",
    "keyId": "kABCD123456CNTRL",
    "logType": "configuration",
    "serviceName": "svc:example",
    "userId": "uABCD123456CNTRL",
}


def _render(name: str) -> str:
    """A concrete request path for a table entry, with every parameter filled in."""
    return build_path(
        name,
        **{
            key: _PARAMETER_VALUES[key] for key in _PATH_PARAMETER_RE.findall(OPERATIONS[name].path)
        },
    )


def _operation_prose(item: dict, method: str) -> str:
    """Every scrap of prose attached to one operation, flattened to a string.

    The OAuth Scope annotation lives in the operation description for most
    endpoints and in a parameter description for a few, so both are searched.
    """
    operation = item.get(method)
    assert operation is not None, f"{method} is not an operation on this path"
    parts = [operation.get("description") or "", item.get("description") or ""]
    for parameter in list(operation.get("parameters", [])) + list(item.get("parameters", [])):
        parts.append(parameter.get("description") or "")
    return "\n".join(parts)


@pytest.fixture(scope="module")
def vendored_paths() -> dict:
    with SPEC_PATH.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)["paths"]


@pytest.fixture(scope="module")
def operations() -> list:
    return list(OPERATIONS.values())


def test_every_operation_path_exists_in_the_vendored_spec(operations, vendored_paths) -> None:
    missing = sorted({op.path for op in operations if op.path not in vendored_paths})

    assert missing == []


def test_every_operation_method_exists_on_that_path(operations, vendored_paths) -> None:
    # A path can survive while the verb this collection uses is renamed or
    # withdrawn, which is a different failure from the path disappearing.
    missing = sorted(
        f"{op.method} {op.path}"
        for op in operations
        if op.method.lower() not in vendored_paths.get(op.path, {})
    )

    assert missing == []


def test_every_recorded_scope_is_named_upstream(operations, vendored_paths) -> None:
    # A scope can be renamed without the endpoint moving, and a credential then
    # asked for the old name fails with a 403 that names nothing useful.
    renamed = []
    for op in operations:
        prose = _operation_prose(vendored_paths[op.path], op.method.lower())
        if "OAuth Scope" not in prose:
            continue
        renamed.extend(f"{op.name}: {scope}" for scope in op.scopes if scope not in prose)

    assert renamed == []


def test_the_only_operations_upstream_leaves_unscoped_are_the_dns_ones(
    operations, vendored_paths
) -> None:
    # `dns` and `dns:read` come from Tailscale's trust-credential documentation
    # rather than from the description. Pinning the absence means an upstream
    # annotation arriving is a failure to reconcile, not a comment that quietly
    # becomes wrong.
    unscoped = sorted(
        op.name
        for op in operations
        if "OAuth Scope" not in _operation_prose(vendored_paths[op.path], op.method.lower())
    )

    assert unscoped == ["dns_configuration_get", "dns_configuration_set"]


def test_no_operation_records_a_deprecated_scope(operations) -> None:
    recorded = {scope for op in operations for scope in op.scopes}

    assert recorded & LEGACY_SCOPES == set()


def test_every_operation_name_is_unique_and_indexed_by_its_own_name(operations) -> None:
    names = [op.name for op in operations]

    assert len(names) == len(set(names))
    assert set(OPERATIONS) == set(names)


def test_every_operation_path_uses_one_of_the_three_upstream_shapes(operations) -> None:
    misprefixed = sorted(
        f"{op.method} {op.path}" for op in operations if not op.path.startswith(_PATH_PREFIXES)
    )

    assert misprefixed == []


def test_a_rendered_path_resolves_back_to_its_own_operation(operations) -> None:
    # Resolution matches a concrete path against a template, so two entries
    # differing only in a literal segment would make one of them unresolvable.
    # The round trip is what proves the table holds no such collision.
    unresolved = sorted(op.name for op in operations if resolve(op.method, _render(op.name)) != op)

    assert unresolved == []


def test_a_path_this_collection_does_not_use_resolves_to_nothing() -> None:
    assert resolve("GET", "/tailnet/-/user-invites") is None
    assert resolve("GET", "/tailnet/-/device-invites") is None
    assert resolve("DELETE", "/tailnet/-/acl") is None
    assert resolve("POST", "/tailnet/-/dns/nameservers") is None


def test_a_device_operation_is_not_reachable_through_a_tailnet_prefix() -> None:
    # /tailnet/{tailnet}/device/{id}/name does not exist upstream, and a wrong
    # path shape answers 404 rather than 400, so it is the failure this table
    # exists to prevent.
    assert resolve("POST", "/tailnet/-/device/n1/name") is None
    assert resolve("POST", _render("device_rename")) == OPERATIONS["device_rename"]
    assert is_tailnet_scoped(OPERATIONS["device_list"])
    assert not is_tailnet_scoped(OPERATIONS["device_rename"])


def test_a_user_mutation_is_top_level_and_a_user_list_is_tailnet_scoped() -> None:
    assert resolve("POST", "/tailnet/-/users/u1/role") is None
    assert resolve("POST", _render("user_set_role")) == OPERATIONS["user_set_role"]
    assert is_tailnet_scoped(OPERATIONS["users_list"])
    assert not is_tailnet_scoped(OPERATIONS["user_set_role"])


def test_an_omitted_tailnet_renders_as_the_default_shorthand() -> None:
    assert build_path("policy_get") == "/tailnet/-/acl"
    assert build_path("policy_get", tailnet=TAILNET_DEFAULT) == "/tailnet/-/acl"


def test_an_explicit_tailnet_is_used_verbatim() -> None:
    assert build_path("policy_get", tailnet="example.com") == "/tailnet/example.com/acl"


def test_a_device_operation_takes_no_tailnet_at_all() -> None:
    assert build_path("device_rename", deviceId="n1") == "/device/n1/name"


def test_the_policy_file_scopes_require_the_device_scopes_too() -> None:
    assert scope_dependencies("policy_file") == (
        "devices:posture_attributes:read",
        "devices:core:read",
    )
    assert scope_dependencies("policy_file:read") == (
        "devices:posture_attributes:read",
        "devices:core:read",
    )
    assert scope_dependencies("devices:core") == ()


def test_a_read_operation_records_a_read_scope_and_a_write_one_does_not() -> None:
    # The `:read` suffix is what separates them, and a collection that asks for
    # a write scope it does not need is a collection that over-grants.
    for name in ("policy_get", "device_list", "users_list", "tailnet_settings_get"):
        assert OPERATIONS[name].scopes[0].endswith(":read"), name

    for name in ("policy_set", "device_rename", "user_approve", "tailnet_settings_update"):
        assert not OPERATIONS[name].scopes[0].endswith(":read"), name


def test_build_path_rejects_an_operation_the_table_does_not_hold() -> None:
    with pytest.raises(ValueError, match="unknown operation: contact_list"):
        build_path("contact_list")


def test_build_path_rejects_a_parameter_the_path_does_not_take() -> None:
    with pytest.raises(ValueError, match="takes no 'keyId'"):
        build_path("policy_get", keyId="k1")


def test_build_path_rejects_a_parameter_it_cannot_substitute() -> None:
    with pytest.raises(ValueError, match="needs 'deviceId'"):
        build_path("device_get")


def test_normalise_path_drops_the_origin_the_query_string_and_a_trailing_slash() -> None:
    url = "https://api.tailscale.com/api/v2/tailnet/-/devices?fields=all&tags=tag:admin@example.com"

    assert normalise_path(url) == "/tailnet/-/devices"
    assert normalise_path("/tailnet/-/acl/") == "/tailnet/-/acl"
    assert normalise_path("/tailnet/-/acl#frag") == "/tailnet/-/acl"
    assert normalise_path("https://api.tailscale.com") == "/"


def test_normalise_path_leaves_a_template_untouched() -> None:
    assert normalise_path("/tailnet/{tailnet}/acl") == "/tailnet/{tailnet}/acl"
