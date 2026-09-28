# SPDX-License-Identifier: BSD-2-Clause
"""`tailscale_settings` against a real tailnet, through the module.

The settings endpoint is a PATCH, so it merges: a field the request does not name
is a field the server leaves alone. That is the opposite of the DNS module's
replace endpoint, and it is what most of these tests are about: proving the module
only ever names the fields it was asked about, because on a tailnet someone else
is administering, silently writing a field nobody asked for is the failure.

Every assertion drives the module's ``main()``. The ``preserved`` fixture restores
the whole document in a ``finally``, so a failed assertion cannot leave the
tailnet with a different approval policy than it had.
"""

from __future__ import annotations

from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.modules import tailscale_settings

pytestmark = pytest.mark.live_smoke

#: The maximum the API accepts for an authorisation key's lifetime, so the value
#: is inside the enforced range on any plan.
MAX_KEY_DAYS = 180

#: Fields this tailnet's plan will accept, discovered by asking the API rather than
#: written down, because a field a plan refuses is a property of the plan and not of
#: the collection.
#:
#: Two of the eleven are refused on a free plan, both with a 400, and the module
#: carries no remedy, which is right: a plan limit is not something a module can fix.
#: It owes only that the server's reason reaches the operator intact.
PLAN_GATED = {
    "networkFlowLoggingOn": "feature not available on current billing plan",
    "postureIdentityCollectionOn": "current plan does not allow enabling",
}


@pytest.fixture
def accepted_fields(api: Api, preserved: Any) -> dict[str, Any]:
    """The settings this plan will accept a *change* to, discovered one at a time.

    Probed by flipping each boolean to its opposite and putting it straight back.
    Flipping is the only probe that means anything: `regionalRoutingOn` is accepted
    while it holds its existing value and refused the moment it is asked to change,
    so a probe that writes back what it just read concludes the field is settable
    and every test using it then fails for a plan reason. Discovered the first way,
    three fields on this tailnet looked settable and were not.

    Every probe is undone, and the ``preserved`` fixture restores the whole
    document afterwards regardless, so the tailnet is as it was either way.
    """
    with preserved("settings"):
        current = _current(api)
        usable: dict[str, Any] = {}
        for field, value in sorted(current.items()):
            if not isinstance(value, bool):
                usable[field] = value
                continue
            try:
                api.call("tailnet_settings_update", "PATCH", body={field: not value})
            except Exception:
                continue
            usable[field] = not value
            api.call("tailnet_settings_update", "PATCH", body={field: value})
    return usable


def _opposite(api_fields: dict[str, Any]) -> dict[str, Any]:
    """Each requested field set away from what the tailnet holds, so a run has work to do.

    A second run over the same request has to find nothing to change, which is only
    a real assertion if the first run had something to change.
    """
    return api_fields


#: The fields asserted to survive a round trip, and the values they are given.
#: The set of fields is the plan's, not a hand-written one; the values are, because
#: a value per field is the thing under test.
FIELD_VALUES: dict[str, Any] = {
    "devicesApprovalOn": True,
    "devicesAutoUpdatesOn": True,
    "devicesKeyDurationDays": MAX_KEY_DAYS,
    "usersApprovalOn": False,
    "usersRoleAllowedToJoinExternalTailnets": "admin",
    "regionalRoutingOn": False,
    "postureIdentityCollectionOn": True,
    "httpsEnabled": True,
    "aclsExternallyManagedOn": False,
    "aclsExternalLink": "https://example.invalid/acl",
}


def _run(
    module_args: Any, module_result: Any, options: dict[str, Any], **flags: Any
) -> dict[str, Any]:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_settings.main()
    return dict(result)


def _current(api: Api) -> dict[str, Any]:
    body = api.call("tailnet_settings_get", "GET").body
    return body if isinstance(body, dict) else {}


def test_a_full_configuration_then_read_converges(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    accepted_fields: dict[str, Any],
) -> None:
    """Set every option this plan accepts, then set them again and expect no change."""
    wanted = {field: FIELD_VALUES[field] for field in accepted_fields if field in FIELD_VALUES}
    with preserved("settings"):
        options = {**credentials, **_options_for(wanted)}

        first = _run(module_args, module_result, options, diff=True)
        assert first["changed"] is True, "the values were chosen so the first run has work to do"
        assert first["changed_settings"], "it must say which fields it wrote"
        assert first["diff"]["after"], "and the diff must carry them"

        second = _run(module_args, module_result, options)
        assert second["changed"] is False, "the tailnet already holds all of this"
        assert second["changed_settings"] == []


def test_every_field_survives_the_round_trip_in_the_api_spelling(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    accepted_fields: dict[str, Any],
) -> None:
    """The module's snake_case options have to arrive as the API's camel case.

    Read back through the API, because a field sent under the wrong name is
    silently ignored rather than refused, so only the stored document shows it.
    """
    wanted = {field: FIELD_VALUES[field] for field in accepted_fields if field in FIELD_VALUES}
    with preserved("settings"):
        _run(module_args, module_result, {**credentials, **_options_for(wanted)})

        stored = _current(api)
        for field, value in wanted.items():
            assert stored.get(field) == value, f"{field} did not survive the write"


def _options_for(api_fields: dict[str, Any]) -> dict[str, Any]:
    """Module options for a set of API fields, by way of the module's own table.

    Read from the module rather than restated, so this test fails if the table and
    the documentation disagree, which is what `validate-modules` cannot see.
    """
    reverse = {field: option for option, field in tailscale_settings._FIELDS.items()}
    return {reverse[field]: value for field, value in api_fields.items() if field in reverse}


def test_only_the_requested_fields_are_written(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    accepted_fields: dict[str, Any],
) -> None:
    """A PATCH must name only what it was asked to change.

    This is the module's central claim about a merging endpoint, and it is the one
    that would be invisible in a unit test: the request body is asserted here, not
    the result, because the failure mode is a field written that nothing asked for.
    """
    with preserved("settings"):
        before = _current(api)
        field = "devicesApprovalOn"
        option = {value: option for option, value in tailscale_settings._FIELDS.items()}[field]
        wanted = not before[field]

        result = _run(module_args, module_result, {**credentials, option: wanted})

        assert result["changed"] is True
        assert result["changed_settings"] == [field], "and it says so"

        after = _current(api)
        untouched = {k: v for k, v in before.items() if k != field}
        assert {k: v for k, v in after.items() if k != field} == untouched, (
            "nothing else moved, so a second run over an unrelated task is quiet"
        )


def test_a_boolean_set_to_false_is_sent_not_dropped(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """The trap of an option that arrives as None, and False is not None.

    A module that filters on truthiness sends nothing for `false`, so turning a
    setting off silently does nothing and reports no change.

    Driven from whichever value the tailnet currently holds, so the test does not
    assume a starting state that another test may have left behind.
    """
    with preserved("settings"):
        start = _current(api)["devicesApprovalOn"]

        result = _run(module_args, module_result, {**credentials, "devices_approval_on": start})
        assert result["changed"] is False, f"already {start}"

        result = _run(module_args, module_result, {**credentials, "devices_approval_on": not start})
        assert result["changed"] is True, "turning it over is a change"
        assert result["changed_settings"] == ["devicesApprovalOn"]
        assert _current(api)["devicesApprovalOn"] is not start


def test_an_option_left_out_is_not_sent_at_all(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    accepted_fields: dict[str, Any],
) -> None:
    """An omitted option arrives as None and must not become a PATCH field.

    Sending it as `null` would either clear the field on a merging endpoint or be
    ignored, and the first is a silent change nobody asked for.
    """
    with preserved("settings"):
        before = _current(api)
        one = next(
            (f, v) for f, v in accepted_fields.items() if isinstance(v, bool) and f in before
        )

        result = _run(module_args, module_result, {**credentials, **_options_for({one[0]: one[1]})})

        assert result["changed_settings"] == [one[0]]
        after = _current(api)
        for field, value in before.items():
            if field != one[0]:
                assert after.get(field) == value, f"{field} was not asked about and must not move"


def test_check_mode_reports_the_change_without_writing(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    accepted_fields: dict[str, Any],
) -> None:
    """The same, for check mode."""
    with preserved("settings"):
        before = _current(api)
        one = next(
            (f, v) for f, v in accepted_fields.items() if isinstance(v, bool) and f in before
        )

        result = _run(
            module_args,
            module_result,
            {**credentials, **_options_for({one[0]: one[1]})},
            check_mode=True,
        )

        assert result["changed"] is True
        assert result["changed_settings"] == [one[0]], "and which fields"
        assert _current(api) == before, "and it wrote nothing"


def test_check_mode_over_settings_already_in_place_reports_no_change(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    accepted_fields: dict[str, Any],
) -> None:
    """The first thing an operator does."""
    pair = {
        field: value
        for field, value in accepted_fields.items()
        if isinstance(value, bool) and field in ("devicesApprovalOn", "usersApprovalOn")
    }
    if len(pair) < 2:
        pytest.skip("this plan will not accept a change to two settings at once")

    with preserved("settings"):
        options = {**credentials, **_options_for(pair)}
        _run(module_args, module_result, options)

        result = _run(module_args, module_result, options, check_mode=True)

        assert result["changed"] is False
        assert result["changed_settings"] == []


def test_the_diff_covers_only_the_fields_this_run_changed(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    accepted_fields: dict[str, Any],
) -> None:
    """A diff across the whole settings document would bury the one line that matters."""
    # Two booleans this plan will accept a change to, taken from the probe rather
    # than named, because a plan-gated field would fail the run before the diff was
    # ever rendered and the test would be reporting the plan instead of the diff.
    pair = {
        field: value
        for field, value in accepted_fields.items()
        if isinstance(value, bool) and field in ("regionalRoutingOn", "httpsEnabled")
    }
    if len(pair) < 2:
        pytest.skip("this plan will not accept a change to two settings at once")

    with preserved("settings"):
        result = _run(module_args, module_result, {**credentials, **_options_for(pair)}, diff=True)

        assert set(result["diff"]["after"]) == set(pair)
        assert set(result["diff"]["before"]) == set(pair)
        assert set(_current(api)) - set(result["diff"]["before"]), (
            "the tailnet does have other settings, and none of them is in the diff"
        )


@pytest.mark.parametrize("gated", list(PLAN_GATED.items()), ids=list(PLAN_GATED))
def test_a_field_the_plan_does_not_offer_is_the_servers_refusal_to_pass_on(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
    gated: tuple[str, str],
) -> None:
    """A 400 the module has no remedy for must still reach the operator intact.

    Each of :data:`PLAN_GATED` is refused on a free plan. The module cannot invent
    a remedy, which is correct: a plan limit is not something a module can fix. What
    it owes is that the server's own reason arrives scrubbed and length-capped like
    every other upstream message, with nothing of the credential beside it.

    Parametrised over the plan-gated fields rather than one of them, so a tailnet
    that refuses a different set is still covered.
    """
    field, reason = gated
    option = {value: key for key, value in tailscale_settings._FIELDS.items()}[field]
    with preserved("settings"):
        before = _current(api)

        module_args({**credentials, option: True})
        with module_result.failure() as result:
            tailscale_settings.main()

        message = result["msg"]
        assert reason in message, (
            "the server's reason reaches the operator, so the answer is a plan change "
            "rather than a guess"
        )
        assert "Traceback" not in message
        for secret in credentials.values():
            assert secret not in message
        assert _current(api) == before, "and nothing was written"


def test_a_key_duration_outside_the_enforced_range_is_refused(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """The API accepts 1 to 180 and rejects the rest, so the module must too.

    A value above the ceiling was the shipped example until this was measured, so
    the example a user copies is the thing being asserted here.
    """
    with preserved("settings"):
        module_args({**credentials, "devices_key_duration_days": 365})
        with module_result.failure() as result:
            tailscale_settings.main()

        assert "180" in result["msg"] or "365" in result["msg"]
        assert "Traceback" not in result["msg"]


def test_a_key_duration_inside_the_range_is_accepted(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """The other half: a value the API accepts must not be refused locally."""
    with preserved("settings"):
        result = _run(
            module_args,
            module_result,
            {**credentials, "devices_key_duration_days": MAX_KEY_DAYS},
        )

        assert result["changed_settings"] == ["devicesKeyDurationDays"]
        assert _current(api)["devicesKeyDurationDays"] == MAX_KEY_DAYS


def test_a_stringified_number_does_not_look_changed_for_ever(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """A number that comes back as a string must still compare equal.

    The failure this guards is a module that reports a change on every run, which
    is the collection's first invariant broken by a two-character difference no
    playbook can express. Whether the API does it is not established, so the test
    asserts the property rather than the API's behaviour: if the value comes back a
    string, the second run must still be quiet.
    """
    with preserved("settings"):
        options = {**credentials, "devices_key_duration_days": 30}
        _run(module_args, module_result, options)

        second = _run(module_args, module_result, options)

        assert second["changed"] is False, (
            f"the stored value is {_current(api)['devicesKeyDurationDays']!r}, "
            "and a second run over it must report no change whatever its type"
        )


def test_no_credential_option_at_all_fails_before_any_request(
    module_args: Any,
    module_result: Any,
    api: Api,
) -> None:
    """A task with no credential fails on the spot."""
    module_args({"devices_approval_on": True})
    with module_result.failure() as result:
        tailscale_settings.main()

    assert "api_token" in result["msg"] or "oauth_client_id" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_refused_credential_reaches_the_operator_without_echoing_it(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """A bad secret against the real API, which answers 401 for several causes."""
    module_args(
        {
            **credentials,
            "oauth_client_secret": "not-the-secret",
            "devices_approval_on": True,
        }
    )
    with module_result.failure() as result:
        tailscale_settings.main()

    message = result["msg"]
    assert "401" in message
    assert "Traceback" not in message
    assert "not-the-secret" not in message
    assert credentials["oauth_client_id"] not in message
