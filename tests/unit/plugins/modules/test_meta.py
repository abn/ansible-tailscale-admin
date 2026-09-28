# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the collection manifest in ``meta/runtime.yml``."""

from __future__ import annotations

import pathlib

import yaml

COLLECTION_ROOT = pathlib.Path(__file__).resolve().parents[4]
MODULES = COLLECTION_ROOT / "plugins" / "modules"
RUNTIME = COLLECTION_ROOT / "meta" / "runtime.yml"

#: The group a playbook names to declare connection options once for every module.
GROUP = "tailscale"


def _shipped_modules() -> set[str]:
    """Every module in the collection, by fully qualified name."""
    return {
        f"abn.tailscale.{path.stem}" for path in MODULES.glob("*.py") if path.stem != "__init__"
    }


def _group_members() -> list[str]:
    document = yaml.safe_load(RUNTIME.read_text(encoding="utf-8"))
    return list(document["action_groups"][GROUP])


def test_every_module_is_in_the_action_group() -> None:
    """A module outside the group cannot be given the group's defaults.

    The group is how a playbook declares a credential and a tailnet once instead of
    per task, and the docs present it as covering every module. A module missing
    from the list is not a cosmetic gap: a task naming only the group fails before
    it makes a request, with a message about a missing credential that has nothing
    to do with the task.
    """
    missing = sorted(_shipped_modules() - set(_group_members()))

    assert missing == [], (
        "these modules are not in the action group, so a task using the group's "
        f"defaults alone cannot reach them: {missing}"
    )


def test_the_action_group_names_no_module_that_is_gone() -> None:
    """A stale entry is a rename that was not followed through.

    The group is matched by name, so an entry for a module that no longer exists
    fails at the point a playbook names the group rather than at the task that
    needed the module.
    """
    stale = sorted(set(_group_members()) - _shipped_modules())

    assert stale == [], f"the action group names modules that do not exist: {stale}"
