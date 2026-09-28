# SPDX-License-Identifier: BSD-2-Clause
"""`tailscale_contacts` against a real tailnet, through the module.

The contacts document is read as a whole and written one type at a time. What
these tests establish is that a run names only the type it was asked about, that
the address read back is the one written, and that a second run over the same
address is quiet even though the write makes Tailscale require verification.

Two measured facts shape the suite. A contact that has never been set reads back
with an empty address, and the update endpoint answers an empty address with a
server error and cannot clear one, so a write to such a contact could not be
undone. The suite therefore writes only to a contact that already holds an
address, which the ``writable`` fixture finds, and restores it in a ``finally``.
The other is that the resend endpoint changes nothing the API reports, so the
module does not expose it and there is nothing to assert about it here.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.modules import tailscale_contacts

pytestmark = pytest.mark.live_smoke

#: An address chosen so a live run never sends mail to a real mailbox. The
#: domain is reserved for documentation and delivers nowhere.
PROBE_ADDRESS = "contacts-live-probe@example.com"


def _contacts(api: Api) -> dict[str, Any]:
    body = api.call("contacts_get", "GET").body
    return body if isinstance(body, dict) else {}


def _emails(api: Api) -> dict[str, Any]:
    return {
        contact_type: (contact.get("email"), contact.get("needsVerification"))
        for contact_type, contact in _contacts(api).items()
        if isinstance(contact, dict)
    }


@pytest.fixture
def writable(api: Api) -> tuple[str, str]:
    """A contact type that already holds an address, and the address it holds.

    A contact cannot be cleared, so one whose address is empty cannot be put back
    after a write. Skipped rather than written and abandoned: a live suite that
    leaves a tailnet with a contact nobody chose is a leak of configuration.
    """
    contacts = _contacts(api)
    for contact_type in ("support", "security", "account"):
        contact = contacts.get(contact_type)
        email = contact.get("email") if isinstance(contact, dict) else None
        if email:
            return contact_type, str(email)
    pytest.skip("no contact holds an address, and a contact cannot be cleared")


@contextlib.contextmanager
def _restored(api: Api, contact_type: str, original: str) -> Iterator[None]:
    """Put the contact back, whatever the test did or left behind.

    A changed address sends a verification email, so the original is written back
    even when the test wrote nothing, because the address it read may have been
    left different by an earlier failure.
    """
    try:
        yield
    finally:
        api.call(
            "contact_update",
            "PATCH",
            params={"contactType": contact_type},
            body={"email": original},
        )


def _run(
    module_args: Any, module_result: Any, options: dict[str, Any], **flags: Any
) -> dict[str, Any]:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_contacts.main()
    return dict(result)


def test_reading_the_contacts_reports_no_change(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    """The first thing an operator does: name nothing and expect a quiet read."""
    result = _run(module_args, module_result, {**credentials})

    assert result["changed"] is False
    assert result["changed_contacts"] == []

    stored = _contacts(api)
    for contact_type, contact in stored.items():
        assert result["contacts"][contact_type]["email"] == contact.get("email")


def test_a_contact_already_holding_the_address_is_quiet(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    writable: tuple[str, str],
) -> None:
    contact_type, original = writable
    result = _run(module_args, module_result, {**credentials, contact_type: original})

    assert result["changed"] is False
    assert result["changed_contacts"] == []


def test_setting_an_address_writes_and_reads_back(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    writable: tuple[str, str],
) -> None:
    contact_type, original = writable
    with _restored(api, contact_type, original):
        result = _run(module_args, module_result, {**credentials, contact_type: PROBE_ADDRESS})

        assert result["changed"] is True
        assert result["changed_contacts"] == [contact_type]
        assert result["contacts"][contact_type]["email"] == PROBE_ADDRESS

        stored = _contacts(api)[contact_type]
        assert stored["email"] == PROBE_ADDRESS, "the module's spelling reaches the API"


def test_a_changed_address_needs_verification(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    writable: tuple[str, str],
) -> None:
    """The one observable consequence of a write, and it is not reconciled.

    Setting an address makes the server require verification for it. The module
    does not manage that flag, so a run over the address it just wrote is quiet;
    this asserts the two facts together, which is the reason the flag is read-only
    here rather than part of the state.
    """
    contact_type, original = writable
    with _restored(api, contact_type, original):
        _run(module_args, module_result, {**credentials, contact_type: PROBE_ADDRESS})

        assert _contacts(api)[contact_type]["needsVerification"] is True

        again = _run(module_args, module_result, {**credentials, contact_type: PROBE_ADDRESS})
        assert again["changed"] is False, "a pending verification is not an address change"


def test_only_the_named_contact_moves(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    writable: tuple[str, str],
) -> None:
    contact_type, original = writable
    before = _emails(api)
    with _restored(api, contact_type, original):
        _run(module_args, module_result, {**credentials, contact_type: PROBE_ADDRESS})

        after = _emails(api)
        for other, value in before.items():
            if other != contact_type:
                assert after[other] == value, f"{other} was not named and must not move"


def test_check_mode_reports_without_writing(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    writable: tuple[str, str],
) -> None:
    contact_type = writable[0]
    before = _emails(api)

    result = _run(
        module_args,
        module_result,
        {**credentials, contact_type: PROBE_ADDRESS},
        check_mode=True,
    )

    assert result["changed"] is True
    assert result["changed_contacts"] == [contact_type]
    assert _emails(api) == before, "and it wrote nothing"


def test_an_empty_address_is_refused_and_nothing_is_written(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    writable: tuple[str, str],
) -> None:
    """The API answers an empty address with a bare 500, so the module declines it."""
    contact_type = writable[0]
    before = _emails(api)

    module_args({**credentials, contact_type: ""})
    with module_result.failure() as result:
        tailscale_contacts.main()

    assert contact_type in result["msg"]
    assert "empty" in result["msg"]
    assert "Traceback" not in result["msg"]
    assert _emails(api) == before, "and nothing was written"


def test_no_credential_option_at_all_fails_before_any_request(
    module_args: Any, module_result: Any, api: Api, writable: tuple[str, str]
) -> None:
    contact_type = writable[0]
    module_args({contact_type: PROBE_ADDRESS})
    with module_result.failure() as result:
        tailscale_contacts.main()

    assert "api_token" in result["msg"] or "oauth_client_id" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_refused_credential_reaches_the_operator_without_echoing_it(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    writable: tuple[str, str],
) -> None:
    """A bad secret against the real API, which answers 401 for several causes."""
    contact_type = writable[0]
    module_args(
        {**credentials, "oauth_client_secret": "not-the-secret", contact_type: PROBE_ADDRESS}
    )
    with module_result.failure() as result:
        tailscale_contacts.main()

    message = result["msg"]
    assert "401" in message
    assert "Traceback" not in message
    assert "not-the-secret" not in message
    assert credentials["oauth_client_id"] not in message
