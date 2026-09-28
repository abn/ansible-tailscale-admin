# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the module test harness in ``conftest.py``.

Every module test in this collection is written against those fixtures without
being able to change them, so the fixtures are tested here rather than trusted.
The stand-in modules below exist only to make the harness's behaviour
observable; none of them is a module the collection ships.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from ansible.module_utils import basic
from ansible.module_utils.basic import AnsibleModule

_SECRET = "tskey-api-supersecretvalue"

_ARGUMENT_SPEC: dict[str, dict[str, Any]] = {
    "tailnet": {"type": "str", "default": "-"},
    "count": {"type": "int", "default": 1},
    "api_token": {"type": "str", "no_log": True},
    "required_option": {"type": "str", "required": True},
}


class _Probe(AnsibleModule):
    """Constructs an AnsibleModule and does nothing else."""

    def __init__(self, *, supports_check_mode: bool = True, **kwargs: Any) -> None:
        super().__init__(
            argument_spec=_ARGUMENT_SPEC,
            supports_check_mode=supports_check_mode,
            **kwargs,
        )


class _Echo(_Probe):
    """Succeeds, echoing the parameters and the two run flags."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.exit_json(
            changed=False,
            params=dict(self.params),
            check_mode=self.check_mode,
            diff=self._diff,
        )


class _Failing(_Probe):
    """Fails with a fixed message."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.fail_json(msg="the tailnet refused")


class _Skipped(_Probe):
    """Succeeds having skipped, for a reason other than check mode."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.exit_json(changed=False, skipped=True, msg="nothing to do here")


class _Silent(_Probe):
    """Returns without finishing, the way a module missing a return path does."""


class _NoCheckMode(_Probe):
    """Forgot supports_check_mode, which is the trap the harness has to catch."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(supports_check_mode=False, **kwargs)
        self.exit_json(changed=False, check_mode=self.check_mode)


class _Exploding(_Probe):
    """Raises instead of finishing."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        raise RuntimeError("the transport gave up")


def test_reads_the_arguments_it_was_given(module_args, module_result):
    module_args({"tailnet": "example.com", "count": 7, "required_option": "x"})

    with module_result.success() as result:
        _Echo()

    assert result["params"]["tailnet"] == "example.com"
    assert result["params"]["count"] == 7


def test_applies_the_argument_spec_defaults(module_args, module_result):
    module_args({"required_option": "x"})

    with module_result.success() as result:
        _Echo()

    assert result["params"]["tailnet"] == "-"
    assert result["params"]["count"] == 1


def test_captures_exit_json(module_args, module_result):
    module_args({"required_option": "x"})

    with module_result.success() as result:
        _Echo()

    assert result["changed"] is False
    assert "failed" not in result


def test_captures_fail_json(module_args, module_result):
    module_args({"required_option": "x"})

    with module_result.failure() as result:
        _Failing()

    assert result["failed"] is True
    assert result["msg"] == "the tailnet refused"


def test_fails_when_a_required_argument_is_missing(module_args, module_result):
    module_args({})

    with module_result.failure() as result:
        _Echo()

    assert "required_option" in result["msg"]


def test_a_test_that_sets_no_arguments_still_gets_a_payload(module_result):
    with module_result.failure() as result:
        _Echo()

    assert "required_option" in result["msg"]


def test_scrubs_no_log_values_from_the_result(module_args, module_result):
    module_args({"required_option": "x", "api_token": _SECRET})

    with module_result.success() as result:
        _Echo()

    assert _SECRET not in str(result)


def test_check_mode_reaches_the_module(module_args, module_result):
    module_args({"required_option": "x"}, check_mode=True)

    with module_result.success() as result:
        _Echo()

    assert result["check_mode"] is True


def test_check_mode_is_off_by_default(module_args, module_result):
    module_args({"required_option": "x"})

    with module_result.success() as result:
        _Echo()

    assert result["check_mode"] is False


def test_diff_mode_reaches_the_module(module_args, module_result):
    module_args({"required_option": "x"}, diff=True)

    with module_result.success() as result:
        _Echo()

    assert result["diff"] is True


def test_the_run_flags_are_absent_from_the_parameters(module_args, module_result):
    module_args({"required_option": "x"}, check_mode=True, diff=True)

    with module_result.success() as result:
        _Echo()

    assert "_ansible_check_mode" not in result["params"]
    assert "_ansible_diff" not in result["params"]


def test_a_second_run_reports_its_own_result(module_args, module_result):
    module_args({"required_option": "first"})
    with module_result.success() as first:
        _Echo()

    module_args({"required_option": "second"})
    with module_result.success() as second:
        _Echo()

    assert first["params"]["required_option"] == "first"
    assert second["params"]["required_option"] == "second"


def test_a_run_that_never_finishes_reuses_no_earlier_result(module_args, module_result):
    module_args({"required_option": "x"})
    with module_result.success() as first:
        _Echo()

    assert first["changed"] is False

    with (
        pytest.raises(AssertionError, match="without calling exit_json"),
        module_result.success() as second,
    ):
        _Silent()

    assert second == {}


def test_a_module_that_skips_check_mode_fails_the_run(module_args, module_result):
    module_args({"required_option": "x"}, check_mode=True)

    with (
        pytest.raises(AssertionError, match="supports_check_mode"),
        module_result.success() as result,
    ):
        _NoCheckMode()

    assert result == {}


def test_a_skip_for_another_reason_is_accepted(module_args, module_result):
    module_args({"required_option": "x"})

    with module_result.success() as result:
        _Skipped()

    assert result["skipped"] is True


def test_a_failing_run_rejects_a_success(module_args, module_result):
    module_args({"required_option": "x"})

    with (
        # The message names what the harness wanted and what happened, in that
        # order, and the test pins both because a swap here is silent.
        pytest.raises(
            AssertionError,
            match=re.escape("expected the module to fail, but it succeeded:"),
        ),
        module_result.failure() as result,
    ):
        _Echo()

    assert result == {}


def test_a_successful_run_rejects_a_failure(module_args, module_result):
    module_args({"required_option": "x"})

    with (
        pytest.raises(
            AssertionError,
            match="expected the module to succeed, but it failed: 'the tailnet refused'",
        ),
        module_result.success() as result,
    ):
        _Failing()

    assert result == {}


def test_an_unexpected_module_error_propagates(module_args, module_result):
    module_args({"required_option": "x"})

    with (
        pytest.raises(RuntimeError, match="the transport gave up"),
        module_result.success() as result,
    ):
        _Exploding()

    assert result == {}


def test_the_argument_globals_are_restored_with_the_fixture(harness, monkeypatch):
    harness.set_args({"required_option": "x"})

    assert basic._ANSIBLE_ARGS is not None

    monkeypatch.undo()

    assert basic._ANSIBLE_ARGS is None
    assert basic._ANSIBLE_PROFILE is None
