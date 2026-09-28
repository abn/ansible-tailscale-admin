# SPDX-License-Identifier: GPL-3.0-or-later
"""Pytest fixtures every module unit test in this directory builds on.

A test imports the module it exercises and calls its ``main()``. Nothing here
imports a module, so adding one needs no change to this file. The fixtures drive
the real ``AnsibleModule`` with a synthesised argument payload and let the real
``exit_json`` and ``fail_json`` finish the run, so argument validation, check
mode, diff mode and ``no_log`` scrubbing behave as they do under
``ansible-playbook``.

The harness itself lives in ``tests/live/harness.py`` and is shared with the live
stress suite, which drives modules the same way against a real API. One
implementation, because a test that proves something about a second copy of the
harness proves something about the copy.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from ansible_collections.abn.tailscale.tests.live.harness import _Harness
from ansible_collections.abn.tailscale.tests.live.harness import args_setter
from ansible_collections.abn.tailscale.tests.live.harness import harness_for
from ansible_collections.abn.tailscale.tests.live.harness import result_capture


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> _Harness:
    """Patch AnsibleModule for one test. Prefer ``module_args`` and ``module_result``."""
    return harness_for(monkeypatch)


@pytest.fixture
def module_args(harness: _Harness) -> Callable[..., None]:
    """Set the arguments the next module run reads.

    ``module_args({"tailnet": "-"}, check_mode=True)``
    """
    return args_setter(harness)


@pytest.fixture
def module_result(harness: _Harness) -> _Harness:
    """Capture how the module under test finished.

    ``with module_result.success() as result:`` for a run that should succeed,
    ``with module_result.failure() as result:`` for one that should fail.
    """
    return result_capture(harness)
