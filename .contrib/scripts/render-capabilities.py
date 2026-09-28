#!/usr/bin/env python
# SPDX-License-Identifier: GPL-3.0-or-later
"""Render docs/capabilities.md from the spec table and the coverage classification.

Run through the make target so the collection is importable:

    make docs/capabilities

The page is generated rather than written because a hand-kept list of what is
covered is wrong the first time a module is added and nothing catches it. `make
check` regenerates this file and fails on a difference, so it cannot drift from the
two structures it is derived from.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
from collections import defaultdict
from types import ModuleType

# The repository root, found by walking up to the directory holding galaxy.yml,
# so the script does not depend on how deep under the root it sits.
ROOT = next(
    parent
    for parent in pathlib.Path(__file__).resolve().parents
    if (parent / "galaxy.yml").is_file()
)
TARGET = ROOT / "docs" / "capabilities.md"


def _load(name: str) -> ModuleType:
    """Load a kernel file by path.

    By path rather than by the collection package, so this script needs no staged
    farm and `make check` cannot restage the tree a live run is reading from. The
    two files it loads import nothing but the standard library, which is what makes
    that possible.
    """
    path = ROOT / "plugins" / "module_utils" / "_tailscale" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_coverage = _load("_coverage")
_spec = _load("_spec")

CATEGORIES = _coverage.CATEGORIES
EXCLUDED = _coverage.EXCLUDED
OPERATIONS = _spec.OPERATIONS
Exclusion = _coverage.Exclusion
Operation = _spec.Operation

#: The order families appear in, so the page reads the way the API is laid out
#: rather than alphabetically. A family not named here lands at the end.
FAMILY_ORDER = (
    "policy",
    "dns",
    "settings",
    "devices",
    "device attributes",
    "services",
    "keys",
    "users",
    "logs",
    "contacts",
    "aws external id",
    "webhooks",
    "oauth applications",
    "posture integrations",
    "invites",
    "organizations",
    "tailnet",
)


def family_of(path: str) -> str:
    """The API area a path belongs to, as a reader would name it.

    The mapping is explicit because the API's own layout does not group itself: a
    policy lives at `acl`, the logs live under `logging`, and an invite for a device
    sits under the device while an invite for a user sits at the top level.
    """
    if path.startswith("/posture"):
        return "posture integrations"
    if path.startswith("/webhooks"):
        return "webhooks"
    if path.startswith("/organizations"):
        return "organizations"
    if path.startswith("/device-invites") or path.startswith("/user-invites"):
        return "invites"
    if path.startswith("/device/{deviceId}/device-invites"):
        return "invites"
    if path.startswith("/device/{deviceId}/attributes"):
        return "device attributes"
    if path.startswith("/device/{deviceId}"):
        return "devices"
    if path.startswith("/users"):
        return "users"
    if path.startswith("/tailnet/"):
        rest = [part for part in path.strip("/").split("/") if not part.startswith("{")]
        head = rest[1] if len(rest) > 1 else "tailnet"
        return {
            "acl": "policy",
            "logging": "logs",
            "device-attributes": "device attributes",
            "oauth-apps": "oauth applications",
            "posture": "posture integrations",
            "device-invites": "invites",
            "user-invites": "invites",
            "aws-external-id": "aws external id",
        }.get(head, head)
    parts = [part for part in path.strip("/").split("/") if not part.startswith("{")]
    return parts[0] if parts else path


def _sort_key(family: str) -> tuple[int, str]:
    return (FAMILY_ORDER.index(family) if family in FAMILY_ORDER else len(FAMILY_ORDER), family)


def render() -> str:
    covered: dict[str, list[Operation]] = defaultdict(list)
    for operation in OPERATIONS.values():
        covered[family_of(operation.path)].append(operation)

    excluded: dict[str, list[tuple[tuple[str, str], Exclusion]]] = defaultdict(list)
    for endpoint, exclusion in EXCLUDED.items():
        excluded[family_of(endpoint[1])].append((endpoint, exclusion))

    families = sorted(set(covered) | set(excluded), key=_sort_key)
    total = len(OPERATIONS) + len(EXCLUDED)
    lines = [
        "---",
        "type: Reference",
        "title: What the collection manages",
        "description: Every Tailscale API endpoint, whether a module calls it, and",
        "  the reason for each one that none does.",
        "status: stable",
        "tags:",
        "  - tailscale",
        "  - api",
        "  - coverage",
        "---",
        "",
        "# What the collection manages",
        "",
        f"{len(OPERATIONS)} of the {total} endpoints in the API description are used by the",
        f"collection. The other {len(EXCLUDED)} are listed here with the reason each is left.",
        "",
        "Generated from the operation table and the coverage classification by",
        "`.contrib/scripts/render-capabilities.py`. `make check` regenerates it and fails if this",
        "page and the code disagree.",
        "",
        "## By area",
        "",
        "| Area | Called | Not called |",
        "|---|---|---|",
    ]
    for family in families:
        lines.append(
            f"| {family} | {len(covered.get(family, []))} | {len(excluded.get(family, []))} |"
        )
    lines += ["", "## What is called", ""]
    for family in families:
        operations = covered.get(family)
        if not operations:
            continue
        lines += [f"### {family}", "", "| Operation | Endpoint |", "|---|---|"]
        for operation in sorted(operations, key=lambda o: (o.path, o.method)):
            lines.append(f"| `{operation.name}` | `{operation.method} {operation.path}` |")
        lines.append("")
    lines += ["## What is not called", ""]
    for category, explanation in CATEGORIES.items():
        lines += [f"### {category}", "", explanation, ""]
    for family in families:
        entries = excluded.get(family)
        if not entries:
            continue
        lines += [f"**{family}**", "", "| Endpoint | Why |", "|---|---|"]
        for (method, path), exclusion in sorted(entries):
            lines.append(f"| `{method} {path}` | {exclusion.note} (`{exclusion.category}`) |")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    rendered = render()
    if "--check" in sys.argv:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != rendered:
            print(
                f"{TARGET.relative_to(ROOT)} is out of step with the code. "
                "Run `make docs/capabilities`.",
                file=sys.stderr,
            )
            return 1
        return 0
    TARGET.write_text(rendered, encoding="utf-8")
    print(f"wrote {TARGET.relative_to(ROOT)} ({len(rendered.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
