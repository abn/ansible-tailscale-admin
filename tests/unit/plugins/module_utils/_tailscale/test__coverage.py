# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the endpoint coverage classification in ``_coverage.py``."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
import yaml
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._coverage import CATEGORIES
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._coverage import EXCLUDED
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._spec import OPERATIONS

# parents[0] is _tailscale, [1] module_utils, [2] plugins, [3] unit, [4] tests.
SPEC_PATH = Path(__file__).resolve().parents[4] / "fixtures" / "openapi" / "tailscale.yaml"

_VERBS = ("get", "post", "put", "patch", "delete")


@pytest.fixture(scope="module")
def described() -> set[tuple[str, str]]:
    """Every endpoint the vendored description declares, by verb and path."""
    with SPEC_PATH.open(encoding="utf-8") as handle:
        paths = yaml.safe_load(handle)["paths"]
    return {
        (method.upper(), path)
        for path, item in paths.items()
        for method in item
        if method in _VERBS
    }


def _covered() -> set[tuple[str, str]]:
    return {(operation.method.upper(), operation.path) for operation in OPERATIONS.values()}


def test_every_operation_is_named_outside_the_table() -> None:
    """A row nothing calls would be a capability the page wrongly claims is called.

    The page says the collection calls the operations in the table. A row no module,
    helper or test names is a claim that is not true, and three such rows existed: a
    policy preview, a Service list the module does not need, and a resend whose
    result nothing can observe. They were found by hand and are excluded now.
    """
    root = SPEC_PATH.parents[3]
    sources = [
        path
        for path in list((root / "plugins").rglob("*.py")) + list((root / "tests").rglob("*.py"))
        if path.name != "_spec.py"
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in sources)

    unreferenced = sorted(name for name in OPERATIONS if f'"{name}"' not in text)

    assert unreferenced == [], (
        "these operations are in the table and nothing names them, so the coverage "
        f"page claims a capability that is not called: {unreferenced}"
    )


def test_every_described_endpoint_is_classified(described: set[tuple[str, str]]) -> None:
    """Nothing in the description is left unaccounted for.

    This is the whole point of the file. A capability that is neither in the table
    nor in the exclusions is one nobody decided about, and it will not appear on the
    page a reader consults to find out whether it exists.
    """
    unaccounted = sorted(described - _covered() - set(EXCLUDED))

    assert unaccounted == [], (
        "these endpoints are neither called nor excluded, so nothing says whether "
        f"the collection manages them: {unaccounted}"
    )


def test_no_exclusion_names_an_endpoint_the_description_lacks(
    described: set[tuple[str, str]],
) -> None:
    """An exclusion for an endpoint that is gone is a claim that stopped being true.

    An endpoint removed or renamed upstream would otherwise sit here excluded for a
    reason nobody can check, and the page would describe an API that does not exist.
    """
    stale = sorted(set(EXCLUDED) - described)

    assert stale == [], f"these exclusions name endpoints the description does not have: {stale}"


def test_nothing_is_both_called_and_excluded() -> None:
    """The two halves are disjoint, so a row cannot mean two things."""
    overlap = sorted(set(EXCLUDED) & _covered())

    assert overlap == [], f"these are in the table and excluded at once: {overlap}"


def test_every_category_used_is_defined_and_every_category_is_used() -> None:
    """A category with no definition has no line on the page; an unused one is dead.

    The first is the failure that matters, because the page would render a blank
    reason. The second is a category that outlived the endpoints it described.
    """
    used = {exclusion.category for exclusion in EXCLUDED.values()}

    assert used - set(CATEGORIES) == set(), "a category is used but has no definition"
    assert set(CATEGORIES) - used == set(), "a category is defined but nothing uses it"


def test_every_exclusion_says_what_the_endpoint_does() -> None:
    """Each note names the endpoint, so the page reads as a list rather than a table.

    A note that is empty or a placeholder tells a reader nothing they could not get
    from the path, and the point of the page is the reason.
    """
    thin = sorted(key for key, exclusion in EXCLUDED.items() if len(exclusion.note) < 15)

    assert thin == [], f"these exclusions carry a note too thin to be a reason: {thin}"


def test_the_counts_add_up(described: set[tuple[str, str]]) -> None:
    """Every described endpoint is in exactly one of the two, which is the summary.

    Asserted as arithmetic rather than as literals, so the page's headline figure is
    derived from the same two structures the modules and the classification use.
    """
    counted = Counter("covered" if endpoint in _covered() else "excluded" for endpoint in described)

    assert counted["covered"] + counted["excluded"] == len(described)
    assert counted["covered"] == len(_covered())
