# SPDX-License-Identifier: BSD-2-Clause
"""The logging modules against a real tailnet, through the modules.

Two families with opposite shapes are under test here, and the tailnet decides
how much of the second one can be exercised.

The configuration audit log is readable on any plan, so the read module is covered
in full: a change this session made appears in the window that was asked for, each
filter narrows it, a quiet window is empty rather than a failure, and a window the
API refuses reaches the operator with the server's own reason.

Log streaming is a paid feature, and this throwaway tailnet does not have it.
Measured against it: every endpoint of the family, and the network flow log read,
answers 403 with "feature not available on current billing plan". A plan limit is
not a module defect, so each streaming test asks the plan what it will do first
and then asserts the branch that applies. Where the plan refuses, the assertion
is that the refusal arrives as a billing answer naming no scope, and that it came
from the read rather than from a write, so nothing was applied.

Every assertion drives a module's ``main()``. The ``preserved`` fixture puts a
streaming destination back in a ``finally``, so a failed assertion cannot leave
the tailnet streaming somewhere. This suite writes nothing else to the tailnet: the
audit entries it reads are caused by a credential it creates and removes, rather
than by a settings or policy change another live suite is making at the same time.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleNotFound,
)
from ansible_collections.abn.tailscale.plugins.modules import tailscale_log_streaming
from ansible_collections.abn.tailscale.plugins.modules import tailscale_logs
from ansible_collections.abn.tailscale.tests.live.conftest import PREFIX

pytestmark = pytest.mark.live_smoke

#: A destination pointed at a name that cannot resolve, under a reserved TLD. The
#: plan is what decides whether a stream is ever attempted, and if one is then
#: every publish fails, which is the point: this suite configures a destination
#: and never sends the tailnet's logs anywhere real.
DESTINATION = {
    "destination_type": "elastic",
    "url": "https://logs.invalid:8080/config-log-datastream",
    "user": "ansible",
    "compression_format": "zstd",
    "upload_period_minutes": 5,
}

#: The event and target type a credential's creation is recorded as, measured
#: against the real API. Naming both is what lets a filtered read be checked
#: against the entries it selected rather than against a count.
CREDENTIAL_CREATED_EVENT = "API_KEY.CREATE"
CREDENTIAL_TARGET_TYPE = "API_KEY"

#: The audit log is written by a rate limiter that may defer an entry, so a test
#: that made a change waits for it rather than reading once and concluding it is
#: missing.
AUDIT_TIMEOUT = 90.0
AUDIT_INTERVAL = 2.0


@dataclass(frozen=True)
class Plan:
    """What this tailnet's plan will do with a request, discovered once."""

    offered: bool
    reason: str


@pytest.fixture(scope="session")
def log_streaming(api: Api) -> Plan:
    """Whether the plan offers log streaming, and the server's words if it does not.

    Asked of the read rather than the write, so that discovering the answer cannot
    change anything. A not-found means the plan offers it and the tailnet has no
    destination yet, which is a state rather than a refusal.
    """
    try:
        api.call("logging_stream_get", "GET", params={"logType": "configuration"})
    except TailscaleNotFound:
        return Plan(offered=True, reason="the tailnet has no destination yet")
    except TailscaleError as error:
        return Plan(offered=False, reason=error.message)
    return Plan(offered=True, reason="a destination is already configured")


@pytest.fixture(scope="session")
def network_flow_logs(api: Api) -> Plan:
    """Whether the plan records network flow logs, asked the same way."""
    try:
        api.call(
            "logging_network_get",
            "GET",
            query={"start": _stamp(_ago(60)), "end": _stamp(_ago(0))},
        )
    except TailscaleError as error:
        return Plan(offered=False, reason=error.message)
    return Plan(offered=True, reason="")


@dataclass(frozen=True)
class AuditEntry:
    """One audit entry this session caused, and a window certain to hold it."""

    window: dict[str, str]
    event_time: str
    actor: str


@pytest.fixture(scope="session")
def audit_entry(api: Api, teardown: Any) -> AuditEntry:
    """A credential created for this session, and the audit entry that records it.

    A client rather than a settings change or a tagged auth key, for two measured
    reasons. The settings document is shared with the other live suites, so an
    entry manufactured by flipping a setting is an entry another suite may be
    flipping at the same moment. And the API refuses a tailnet-owned auth key that
    carries no tag, which would make this depend on the policy the harness writes,
    which is the other shared document.

    One for the session rather than one per test, because a credential that
    outlives its test is the thing this suite is most able to leak. Registered with
    the session teardown before it exists, and the harness deletes any credential
    whose description carries its own prefix before it mints its own, so even a
    session killed outright leaves nothing behind.
    """
    body = api.call(
        "keys_create",
        "POST",
        body={
            "keyType": "client",
            # The narrowest scope that mints a client, because a credential this
            # suite cannot use for anything else is a credential worth less if it
            # outlives the run.
            "scopes": ["devices:core:read"],
            "description": f"{PREFIX} logging read",
        },
    ).body
    client_id = body.get("id") if isinstance(body, dict) else None
    if not client_id:
        raise AssertionError(f"no OAuth client was minted: {body!r}")

    def remove() -> None:
        try:
            api.call("keys_delete", "DELETE", params={"keyId": client_id})
        except TailscaleError:
            # Already gone, which the harness's own sweep does at the start of every
            # session. A cleanup that failed here would report a leak that is the
            # opposite of one.
            return

    teardown.register(f"OAuth client {str(client_id)[:8]} for the audit log", remove)

    window = _window()

    def is_this_client(entry: dict[str, Any]) -> bool:
        target = entry.get("target")
        return (
            isinstance(target, dict)
            and target.get("id") == client_id
            and entry.get("action") == "CREATE"
        )

    entry = _await_audit(api, window, is_this_client)[0]
    return AuditEntry(
        window=window,
        event_time=str(entry["eventTime"]),
        actor=str(entry["actor"]["id"]),
    )


def _ago(seconds: int) -> datetime:
    return datetime.now(UTC) - timedelta(seconds=seconds)


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _window(seconds_back: int = 600, seconds_forward: int = 300) -> dict[str, str]:
    """A window around now, in the only form the API accepts for a UTC instant."""
    return {"start": _stamp(_ago(seconds_back)), "end": _stamp(_ago(-seconds_forward))}


def _logs(
    module_args: Any, module_result: Any, credentials: dict[str, str], **options: Any
) -> dict[str, Any]:
    module_args({**credentials, **options})
    with module_result.success() as result:
        tailscale_logs.main()
    return dict(result)


def _stream(
    module_args: Any, module_result: Any, credentials: dict[str, str], **options: Any
) -> dict[str, Any]:
    module_args({**credentials, **options})
    with module_result.success() as result:
        tailscale_log_streaming.main()
    return dict(result)


def _refusal(
    module_args: Any, module_result: Any, credentials: dict[str, str], main: Any, **options: Any
) -> str:
    """Run a module expecting a failure and hand back the message it produced."""
    module_args({**credentials, **options})
    with module_result.failure() as result:
        main()
    return str(result["msg"])


def _audit(api: Api, window: dict[str, str]) -> list[dict[str, Any]]:
    body = api.call("logging_configuration_get", "GET", query=dict(window)).body
    if not isinstance(body, dict):
        return []
    entries = body.get("logs")
    return entries if isinstance(entries, list) else []


def _await_audit(
    api: Api, window: dict[str, str], wanted: Callable[[dict[str, Any]], bool]
) -> list[dict[str, Any]]:
    """The entries matching `wanted`, once the audit log has caught up.

    Polling rather than sleeping, because the audit log is written through a rate
    limiter that may defer an entry, and a fixed sleep is either too short, which
    fails a test that would have passed, or too long, which slows every run.
    """
    deadline = time.monotonic() + AUDIT_TIMEOUT
    while time.monotonic() < deadline:
        found = [entry for entry in _audit(api, window) if wanted(entry)]
        if found:
            return found
        time.sleep(AUDIT_INTERVAL)
    raise AssertionError(f"no matching audit entry within {AUDIT_TIMEOUT}s of {window}")


def _is_credential_created(entry: dict[str, Any]) -> bool:
    """Whether the entry records a credential being created.

    Matched on the kind of thing acted on rather than on a name, so it holds for
    every credential in the window and not only for the one this session made.
    """
    target = entry.get("target")
    return (
        isinstance(target, dict)
        and target.get("type") == CREDENTIAL_TARGET_TYPE
        and entry.get("action") == "CREATE"
    )


# The configuration audit log


def test_a_change_appears_in_the_window_that_asked_for_it(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    audit_entry: AuditEntry,
) -> None:
    """The property the whole read module exists for: the entries are the evidence."""
    result = _logs(
        module_args, module_result, credentials, log_type="configuration", **audit_entry.window
    )

    assert result["changed"] is False, "a read has nothing to change"
    assert result["window"] == audit_entry.window, "and it reports the window it asked for"
    assert result["log_count"] == len(result["logs"])
    assert result["log_version"], "the audit log names the format version it answered in"

    made = [entry for entry in result["logs"] if entry.get("eventTime") == audit_entry.event_time]
    assert len(made) == 1, "the change this session caused is in the window that was asked for"
    entry = made[0]
    assert entry["type"] == "CONFIG"
    assert entry["origin"] and entry["action"] == "CREATE"
    assert entry["actor"]["id"] and entry["target"]["id"]
    assert entry["new"], "and it names what was created"


def test_the_event_filter_returns_only_that_events_entries(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    audit_entry: AuditEntry,
) -> None:
    """Measured against the real API: the filter selects an event, and it narrows."""
    everything = _logs(
        module_args, module_result, credentials, log_type="configuration", **audit_entry.window
    )
    filtered = _logs(
        module_args,
        module_result,
        credentials,
        log_type="configuration",
        event=[CREDENTIAL_CREATED_EVENT],
        **audit_entry.window,
    )

    assert filtered["logs"], "the event the session caused is in the window"
    assert all(_is_credential_created(entry) for entry in filtered["logs"]), (
        "every entry the filter returned is about the event it named"
    )
    assert len(filtered["logs"]) < len(everything["logs"]), "and the filter narrowed it"


def test_the_target_filter_narrows_to_one_kind_of_thing(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    audit_entry: AuditEntry,
) -> None:
    """Measured: the target filter matches the kind of thing acted on."""
    result = _logs(
        module_args,
        module_result,
        credentials,
        log_type="configuration",
        target=[CREDENTIAL_TARGET_TYPE],
        **audit_entry.window,
    )

    assert result["logs"], "the credential the session made is in the window"
    assert all(entry["target"].get("type") == CREDENTIAL_TARGET_TYPE for entry in result["logs"])


def test_the_actor_filter_narrows_to_one_actor(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    audit_entry: AuditEntry,
) -> None:
    """An actor ID is an exact match, and the entry names who made the change."""
    result = _logs(
        module_args,
        module_result,
        credentials,
        log_type="configuration",
        actor=[audit_entry.actor],
        **audit_entry.window,
    )

    assert result["logs"], "the suite's own client is the actor of every entry it caused"
    assert {entry["actor"]["id"] for entry in result["logs"]} == {audit_entry.actor}


def test_several_events_are_each_asked_for(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    audit_entry: AuditEntry,
) -> None:
    """The API reads each occurrence of a name as one element, so both must arrive."""
    result = _logs(
        module_args,
        module_result,
        credentials,
        log_type="configuration",
        event=[CREDENTIAL_CREATED_EVENT, "FAILED_REQUEST.UPDATE"],
        **audit_entry.window,
    )

    assert result["logs"], "one of the two events is in the window"
    assert all(
        _is_credential_created(entry) or entry["target"].get("type") == "FAILED_REQUEST"
        for entry in result["logs"]
    ), "and no entry belongs to a third event"


def test_a_window_holding_nothing_is_an_empty_list_rather_than_a_failure(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """The API answers a null list for an empty window, measured, and the module says empty."""
    result = _logs(
        module_args,
        module_result,
        credentials,
        log_type="configuration",
        start="2001-01-01T00:00:00Z",
        end="2001-01-01T00:01:00Z",
    )

    assert result["logs"] == []
    assert result["log_count"] == 0
    assert result["log_version"]


def test_a_window_the_api_refuses_reaches_the_operator_with_its_reason(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """A timestamp with no offset is the API's to refuse, and its wording is the useful part."""
    message = _refusal(
        module_args,
        module_result,
        credentials,
        tailscale_logs.main,
        log_type="configuration",
        start="2026-09-27T10:45:46",
        end="2026-09-27T10:45:48Z",
    )

    assert 'invalid "start" time' in message
    assert "Traceback" not in message
    for secret in credentials.values():
        assert secret not in message


def test_a_filter_the_api_does_not_recognise_reaches_the_operator(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """A withdrawn event must fail the task rather than quietly return nothing."""
    message = _refusal(
        module_args,
        module_result,
        credentials,
        tailscale_logs.main,
        log_type="configuration",
        event=["NOT.AN.EVENT.THAT.EXISTS"],
        **_window(),
    )

    assert "NOT.AN.EVENT.THAT.EXISTS" in message


def test_a_filter_on_a_flow_log_is_refused_without_a_request(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """The flow log endpoint declares no filter, and would ignore one silently."""
    message = _refusal(
        module_args,
        module_result,
        credentials,
        tailscale_logs.main,
        log_type="network",
        event=["API_KEY.CREATE"],
        **_window(),
    )

    assert "event" in message
    assert "Traceback" not in message


def test_a_read_never_reports_a_change(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """Two runs over a moving window differ, and that is not drift."""
    options = {"log_type": "configuration", **_window()}

    first = _logs(module_args, module_result, credentials, **options)
    second = _logs(module_args, module_result, credentials, **options)

    assert first["changed"] is False
    assert second["changed"] is False


def test_no_credential_reaches_the_result(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    audit_entry: AuditEntry,
) -> None:
    """The client secret must not come back. The client id does, and is not a secret.

    Measured: the audit entry for a credential's creation names the client or the
    user it belongs to as the actor, so a result read over a window in which this
    collection acted carries the client id. Ansible does not redact the id either,
    and `api_token` and `oauth_client_secret` are the options marked `no_log`.
    """
    result = _logs(
        module_args, module_result, credentials, log_type="configuration", **audit_entry.window
    )

    assert result["logs"]
    assert credentials["oauth_client_secret"] not in str(result)


def test_the_network_flow_log_read_reports_the_plans_answer(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    network_flow_logs: Plan,
) -> None:
    """Either the plan records flow logs, or its refusal arrives intact.

    The OAuth client this suite mints is granted `all`, which includes
    `logs:network:read`, so a refusal here is the plan rather than a permission. A
    message that named a scope would send the operator to widen a credential that
    already carries it.
    """
    if network_flow_logs.offered:
        result = _logs(module_args, module_result, credentials, log_type="network", **_window())
        assert result["changed"] is False
        assert result["log_version"] == "", "the flow log response carries no version field"
        assert isinstance(result["logs"], list)
        return

    message = _refusal(
        module_args,
        module_result,
        credentials,
        tailscale_logs.main,
        log_type="network",
        **_window(),
    )
    assert "feature not available on current billing plan" in message
    assert "scope" not in message, "the credential holds logs:network:read already"
    for secret in credentials.values():
        assert secret not in message
    assert "Traceback" not in message


# Log streaming


def test_a_destination_is_written_then_deleted(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    log_streaming: Plan,
    preserved: Any,
) -> None:
    """The whole lifecycle, or the plan's refusal of it, asserted either way."""
    if not log_streaming.offered:
        # Outside `preserved`, because its reader is the very request the plan
        # refuses: there is no state to put back, and nothing was changed to put it
        # back for.
        message = _refusal(
            module_args,
            module_result,
            credentials,
            tailscale_log_streaming.main,
            log_type="configuration",
            **DESTINATION,
        )
        assert "feature not available on current billing plan" in message
        assert "request: GET " in message, "the failure was the read, so no write was attempted"
        assert "scope" not in message
        return

    with preserved("log_stream:configuration"):
        first = _stream(
            module_args, module_result, credentials, log_type="configuration", **DESTINATION
        )
        assert first["changed"] is True
        assert first["unverified_options"] == [], "no password was given, so none is unverified"
        assert first["stream_configuration"]["destinationType"] == "elastic"
        assert first["stream_configuration"]["user"] == "ansible"
        assert first["stream_configuration"]["uploadPeriodMinutes"] == 5
        assert first["stream_configuration"]["logType"] == "configuration", (
            "the field the API sets for itself is reported even though it is never sent"
        )
        assert first["streaming_status"], "a configured destination has a status to report"

        second = _stream(
            module_args, module_result, credentials, log_type="configuration", **DESTINATION
        )
        assert second["changed"] is False, (
            f"the tailnet holds {second['stream_configuration']!r} and a second run over "
            "the same task must find nothing to change"
        )

        moved = _stream(
            module_args,
            module_result,
            credentials,
            log_type="configuration",
            upload_period_minutes=15,
        )
        assert moved["changed"] is True, "and changing one field is a change"
        assert moved["stream_configuration"]["user"] == "ansible", (
            "the field the task did not mention was carried over rather than reset"
        )

        removed = _stream(
            module_args,
            module_result,
            credentials,
            log_type="configuration",
            state="absent",
        )
        assert removed["changed"] is True
        assert removed["stream_configuration"] == {}

        again = _stream(
            module_args,
            module_result,
            credentials,
            log_type="configuration",
            state="absent",
        )
        assert again["changed"] is False, "and removing what is not there is quiet"


def test_a_run_over_an_unchanged_destination_writes_nothing(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    log_streaming: Plan,
    preserved: Any,
) -> None:
    """The invariant of this module, and the one a replace endpoint breaks."""
    if not log_streaming.offered:
        pytest.skip(f"this tailnet's plan refuses log streaming: {log_streaming.reason}")

    with preserved("log_stream:configuration"):
        options = {"log_type": "configuration", **DESTINATION}
        _stream(module_args, module_result, credentials, **options)

        second = _stream(module_args, module_result, credentials, **options, check_mode=True)

        assert second["changed"] is False
        assert second["diff"]["before"] == second["diff"]["after"]


def test_check_mode_writes_nothing(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    log_streaming: Plan,
    preserved: Any,
) -> None:
    if not log_streaming.offered:
        pytest.skip(f"this tailnet's plan refuses log streaming: {log_streaming.reason}")

    with preserved("log_stream:configuration"):
        result = _stream(
            module_args,
            module_result,
            credentials,
            log_type="configuration",
            **DESTINATION,
            check_mode=True,
        )

        assert result["changed"] is True
        assert result["stream_configuration"]["destinationType"] == "elastic"
        assert result["diff"]["after"]["url"] == DESTINATION["url"]
        after = _stream(
            module_args,
            module_result,
            credentials,
            log_type="configuration",
            state="absent",
            check_mode=True,
        )
        assert after["changed"] is False, "and it created no destination to remove"


def test_a_password_never_reaches_the_result(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    log_streaming: Plan,
    preserved: Any,
) -> None:
    if not log_streaming.offered:
        pytest.skip(f"this tailnet's plan refuses log streaming: {log_streaming.reason}")

    secret = "not-a-real-destination-token"
    with preserved("log_stream:configuration"):
        result = _stream(
            module_args,
            module_result,
            credentials,
            log_type="configuration",
            token=secret,
            **DESTINATION,
        )

        assert result["changed"] is True
        assert result["unverified_options"] == ["token"], "and it says it could not check it"
        assert secret not in str(result), "a destination credential must not come back out"
        assert result["diff"]["after"]["token"] == "(write-only)"


def test_a_missing_credential_fails_before_any_request(
    module_args: Any,
    module_result: Any,
) -> None:
    module_args({"log_type": "configuration", "state": "absent"})

    with module_result.failure() as result:
        tailscale_log_streaming.main()

    assert "api_token" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_refused_credential_reaches_the_operator_without_echoing_it(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    module_args(
        {
            **credentials,
            "oauth_client_secret": "not-the-secret",
            "log_type": "configuration",
            "state": "absent",
        }
    )
    with module_result.failure() as result:
        tailscale_log_streaming.main()

    message = result["msg"]
    assert "401" in message
    assert "Traceback" not in message
    assert "not-the-secret" not in message
    assert credentials["oauth_client_id"] not in message
