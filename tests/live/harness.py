"""The module harness, for tests that drive a module rather than the kernel.

Split out of ``tests/unit/plugins/modules/conftest.py`` so the live stress suite
runs the same way, against a real API instead of a double. The unit suite
imports it from there; importing one copy is the point, because a harness with
two implementations is one where a test proves something about the wrong one.

The behaviour is unchanged: the real ``AnsibleModule`` runs, the real ``exit_json``
and ``fail_json`` produce the result, and check mode and diff mode behave as they
do under ``ansible-playbook``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from types import TracebackType
from typing import Any
from typing import NoReturn

from ansible.module_utils import _internal
from ansible.module_utils import basic
from ansible.module_utils.basic import AnsibleModule

# Captured before the fixture replaces them. The replacements call these rather
# than reimplementing them, so the real result path still runs and reports the
# no_log values the way the installed ansible-core reports them.
_REAL_EXIT_JSON = AnsibleModule.exit_json
_REAL_FAIL_JSON = AnsibleModule.fail_json
_REPORTED_SECRETS_ATTR = "_harness_reported_secrets"

# AnsibleModule decodes the payload with the codec this profile names. It is a
# module global separate from _ANSIBLE_ARGS, and _load_params refuses to parse a
# payload that arrives without one, so the two are installed together.
_SERIALIZATION_PROFILE = "legacy"

# The key AnsibleModule reads its arguments from inside the payload.
_ARGS_KEY = "ANSIBLE_MODULE_ARGS"

# AnsibleModule's own names for the two run flags, read out of the payload and
# then deleted from the parameters the module sees.
_CHECK_MODE_KEY = "_ansible_check_mode"
_DIFF_KEY = "_ansible_diff"

# Attribute the recorded result is stashed under, on the module instance that
# produced it. Keying by instance is what keeps one run's result out of the next.
_RECORDED_ATTR = "_unit_test_result"

# What AnsibleModule puts in the result when a task asks for check mode against a
# module that did not pass supports_check_mode=True. Left unnoticed, a check mode
# test asserts nothing at all.
_UNSUPPORTED_CHECK_MODE = "does not support check mode"

#: A key ansible-core 2.22 and later puts in the result carrying the raw values a
#: module marked no_log, for the controller to redact. The controller pops it and
#: masks the values wherever the result is rendered. A test reads the dict itself,
#: so the harness pops it and redacts the values in place, or an assertion that a
#: credential is absent fails on a version where it is legitimately present on the
#: way out.
_CONTROLLER_POPPED = "_ansible_new_secrets"

#: What ansible-core substitutes for a no_log value before a result reaches a user.
_REDACTED = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"


class ModuleExitedError(Exception):
    """The module under test called ``exit_json``."""

    def __init__(self, result: dict[str, Any]) -> None:
        super().__init__(result.get("msg", ""))
        self.result = result


class ModuleFailedError(Exception):
    """The module under test called ``fail_json``."""

    def __init__(self, result: dict[str, Any]) -> None:
        super().__init__(result.get("msg", ""))
        self.result = result


def _redact(value: Any, secrets: list[str]) -> Any:
    """Return ``value`` with every occurrence of a secret replaced.

    Walks the shapes a result is built from, because a credential reaches one as
    a value of its own or embedded in a longer string.
    """
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, _REDACTED)
        return value
    if isinstance(value, dict):
        return {_redact(key, secrets): _redact(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, secrets) for item in value]
    return value


def _record_result(module: AnsibleModule, result: dict[str, Any]) -> None:
    """Stand in for the hook the real result path ends on.

    Pops what the controller pops, keeps the values it named, and redacts them from
    the result so it reads the way it reaches a user. ansible-core up to 2.21
    scrubbed the result inside ``_return_formatted``; 2.22 names the values on the
    way out and leaves the redaction to the controller, which a unit test does not
    have.
    """
    secrets = result.pop(_CONTROLLER_POPPED, None)
    if secrets is not None:
        values = [str(value) for value in secrets]
        setattr(module, _REPORTED_SECRETS_ATTR, values)
        result = _redact(result, values)
    setattr(module, _RECORDED_ATTR, result)


def _exit_json(module: AnsibleModule, **kwargs: Any) -> NoReturn:
    """Let the real exit_json produce the result, then raise instead of exiting."""
    try:
        _REAL_EXIT_JSON(module, **kwargs)
    except SystemExit as reason:
        raise ModuleExitedError(getattr(module, _RECORDED_ATTR, {})) from reason


def _fail_json(module: AnsibleModule, *args: Any, **kwargs: Any) -> NoReturn:
    """Let the real fail_json produce the result, then raise instead of exiting.

    ``msg`` is positional in the real signature, so both call shapes are accepted.
    """
    try:
        _REAL_FAIL_JSON(module, *args, **kwargs)
    except SystemExit as reason:
        raise ModuleFailedError(getattr(module, _RECORDED_ATTR, {})) from reason


class _Harness:
    """Holds the argument payload and the run flags for the duration of one test.

    Both named fixtures are this one object: ``module_args`` is :meth:`set_args`
    and ``module_result`` is the object itself.
    """

    def __init__(self, monkeypatch: Any) -> None:
        self._monkeypatch = monkeypatch
        self.check_mode = False
        self.reported_secrets: list[str] = []

        # The three replacements below take the module as their first argument, so
        # the real methods still run against the real instance. That is also what
        # makes them work for a module that bound AnsibleModule into its own
        # namespace at import time: attribute lookup happens on the class at call
        # time, so nothing has to be re-imported after the patch is in place.
        monkeypatch.setattr(AnsibleModule, "exit_json", _exit_json)
        monkeypatch.setattr(AnsibleModule, "fail_json", _fail_json)
        monkeypatch.setattr(AnsibleModule, "_record_module_result", _record_result)

        # A module process is not the controller, and ansible-core decides that at
        # import: importing `ansible` into this test process flips the flag, which
        # makes `warn` display the warning instead of recording it, so a test
        # asserting on `result['warnings']` sees nothing. The harness runs the
        # module the way a module process does, so the flag is put back.
        monkeypatch.setattr(_internal, "is_controller", False)

        # A module that takes no arguments is a legitimate test, and leaving the
        # payload unset would make AnsibleModule read pytest's own argv.
        self.set_args()

    def set_args(
        self,
        options: dict[str, Any] | None = None,
        *,
        check_mode: bool = False,
        diff: bool = False,
    ) -> None:
        """Set the arguments, check mode and diff mode of the next module run.

        Takes a dict rather than keyword arguments so that no module option can
        be shadowed by one of the two run flags.
        """
        params: dict[str, Any] = dict(options or {})
        if check_mode:
            params[_CHECK_MODE_KEY] = True
        if diff:
            params[_DIFF_KEY] = True

        self.check_mode = check_mode
        # monkeypatch restores both globals when the test ends, so a payload set
        # here cannot reach a test that never asked for this harness.
        self._monkeypatch.setattr(basic, "_ANSIBLE_ARGS", json.dumps({_ARGS_KEY: params}).encode())
        self._monkeypatch.setattr(basic, "_ANSIBLE_PROFILE", _SERIALIZATION_PROFILE)

    def success(self) -> _Run:
        """Context manager for a module run that is expected to succeed."""
        return _Run(self, expect_failed=False)

    def failure(self) -> _Run:
        """Context manager for a module run that is expected to fail."""
        return _Run(self, expect_failed=True)


class _Run:
    """Runs the body of a test and asserts how the module finished.

    The body receives the result dict as it stands after no_log scrubbing, which
    is the dict the controller would receive.
    """

    def __init__(self, harness: _Harness, *, expect_failed: bool) -> None:
        self._harness = harness
        self._expect_failed = expect_failed
        self.result: dict[str, Any] = {}

    def __enter__(self) -> dict[str, Any]:
        return self.result

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if exc is None:
            raise AssertionError("the module returned without calling exit_json or fail_json")

        if not isinstance(exc, (ModuleExitedError, ModuleFailedError)):
            return False

        failed = isinstance(exc, ModuleFailedError)
        if failed != self._expect_failed:
            # Both words are named from what the harness wanted, not from what
            # happened. Reading them off `failed` instead swaps the two, so a
            # failure reads "expected it to fail, but it failed".
            raise AssertionError(
                f"expected the module to {'fail' if self._expect_failed else 'succeed'},"
                f" but it {'failed' if failed else 'succeeded'}:"
                f" {exc.result.get('msg', exc.result)!r}"
            )

        # A recorded result is never empty, so an empty one means the run stopped
        # short of the record hook. Asserting on it would silently prove nothing.
        if not exc.result:
            raise AssertionError("the module finished without recording a result")

        if not self._expect_failed and self._skipped_for_check_mode(exc.result):
            raise AssertionError(
                "the module exited without acting because it does not pass"
                " supports_check_mode=True, so the check mode assertion is vacuous"
            )

        # Filled in rather than rebound: the body of the with statement holds this
        # very dict, and the result is only known once the body has finished.
        self.result.update(exc.result)
        return True

    def _skipped_for_check_mode(self, result: dict[str, Any]) -> bool:
        return (
            self._harness.check_mode
            and bool(result.get("skipped"))
            and _UNSUPPORTED_CHECK_MODE in str(result.get("msg", ""))
        )


def harness_for(monkeypatch: Any) -> _Harness:
    """Build a harness on a pytest monkeypatch. The entry point both suites use."""
    return _Harness(monkeypatch)


def args_setter(harness: _Harness) -> Callable[..., None]:
    return harness.set_args


def result_capture(harness: _Harness) -> _Harness:
    return harness
