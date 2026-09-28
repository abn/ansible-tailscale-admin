# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the tailscale_user module, driven through the harness.

Every operation is covered here in full, because the tailnet this collection is
verified against holds one user and that user is the credential the suite
authenticates as, so four of the six operations cannot be exercised live without
ending the run. The live suite covers what is safe and says which it skipped.

The server below is a model of the real one rather than a pair of canned
responses: it holds the user list, applies each operation to it, and answers the
per-user endpoints with no body at all, which is what the real API does. A stub
that answered with a document would let a module that returned the request
instead of the tailnet's state pass, and that is the mistake this file is mostly
about.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import ApiOptions
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import RawResponse
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import ApiToken
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import Authoriser
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import Secret
from ansible_collections.abn.tailscale.plugins.modules import tailscale_user

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
BASE = "https://api.tailscale.com/api/v2"

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"

OWNER_ID = "uOWNER0000000001"
MEMBER_ID = "uMEMBER000000001"
PENDING_ID = "uPENDING00000001"

OWNER = {
    "id": OWNER_ID,
    "displayName": "Owner Person",
    "loginName": "owner@example.com",
    "profilePicUrl": "https://example.com/avatar.png",
    "tailnetId": "-1234567890123",
    "type": "member",
    "role": "owner",
    "status": "active",
    "lastSeen": "2026-01-01T00:00:00Z",
    "deviceCount": 2,
}
MEMBER = {
    "id": MEMBER_ID,
    "displayName": "Member Person",
    "loginName": "member@example.com",
    "profilePicUrl": "https://example.com/avatar.png",
    "type": "member",
    "role": "member",
    "status": "active",
    "deviceCount": 0,
}
#: A user who has been invited and has not authenticated yet, which is the only
#: way a user reaches the `needs-approval` status and the only state approval
#: changes.
PENDING = {
    "id": PENDING_ID,
    "displayName": "Pending Person",
    "loginName": "pending@example.com",
    "type": "member",
    "role": "member",
    "status": "needs-approval",
    "deviceCount": 0,
}

#: Every status the vendored description lists other than `suspended` and
#: `needs-approval`, each of which must read as neither.
OTHER_STATUSES = ("active", "idle", "over-billing-limit")


class Body:
    def __init__(self, text: str) -> None:
        self._text = text

    def decode(self, *args: str) -> str:
        return self._text


def _reply(status: int, text: str) -> Any:
    class Response:
        status: int
        headers: dict

        def __init__(self, status: int) -> None:
            self.status = status
            self.headers = {}

        def read(self) -> Body:
            return Body(text)

    return Response(status)


class Tailnet:
    """The user list, and the five operations the API performs on it."""

    def __init__(self, users: list[dict] | None = None, ignore: tuple[str, ...] = ()) -> None:
        self.users = [dict(user) for user in (users if users is not None else [OWNER, MEMBER])]
        self.requests: list[str] = []
        #: Every mutation, as the path the request line ended in.
        self.writes: list[str] = []
        #: Operations answered with a success status and no effect, which is what
        #: the real API does for a user a credential belongs to.
        self.ignore = ignore

    @property
    def by_id(self) -> dict[str, dict]:
        return {str(user.get("id")): user for user in self.users}

    def _find(self, url: str) -> dict | None:
        return self.by_id.get(url.split("/users/")[1].split("/")[0])

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        path = url[len(BASE) :]
        self.requests.append(f"{method} {path}")
        if method == "GET":
            return _reply(200, json.dumps({"users": self.users}))
        if method != "POST":
            return _reply(404, '{"message": "not found"}')

        user = self._find(url)
        if user is None:
            return _reply(404, '{"message": "404 page not found"}')
        self.writes.append(path)
        for operation, apply in (
            ("/role", self._set_role),
            ("/suspend", self._suspend),
            ("/restore", self._restore),
            ("/approve", self._approve),
            ("/delete", self._delete),
        ):
            if path.endswith(operation):
                if operation not in self.ignore:
                    apply(user, data)
                break
        # The real per-user endpoints answer with no document at all, so a module
        # that returned its request rather than re-reading would look correct here
        # and be wrong against the API.
        return _reply(200, "")

    def _set_role(self, user: dict, data: Any) -> None:
        user["role"] = json.loads(str(data))["role"]

    def _suspend(self, user: dict, data: Any) -> None:
        user["status"] = "suspended"

    def _restore(self, user: dict, data: Any) -> None:
        user["status"] = "active"

    def _approve(self, user: dict, data: Any) -> None:
        user["status"] = "active"

    def _delete(self, user: dict, data: Any) -> None:
        self.users = [entry for entry in self.users if entry is not user]


@pytest.fixture
def server(mocker: Any) -> Any:
    return _stand_in(mocker, [OWNER, MEMBER])


def _stand_in(mocker: Any, users: list[dict], ignore: tuple[str, ...] = ()) -> Tailnet:
    """Put a tailnet holding ``users`` behind the module's transport.

    ``ignore`` names operations to answer with a success status and no effect,
    which is what the real API does for a user the credential belongs to.
    """
    tailnet = Tailnet(users, ignore)
    mocker.patch(_API_URL, tailnet)
    return tailnet


def _run(module_args: Any, module_result: Any, options: dict, **flags: Any) -> dict:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_user.main()
    return dict(result)


# Selection.


def test_a_user_is_selected_by_its_login_name(
    module_args: Any, module_result: Any, server: Any
) -> None:
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "login_name": "member@example.com"}
    )

    assert result["user"]["id"] == MEMBER_ID
    assert server.requests == ["GET /tailnet/-/users"]


def test_a_login_name_is_matched_without_regard_to_case(
    module_args: Any, module_result: Any, server: Any
) -> None:
    result = _run(
        module_args, module_result, {"api_token": TOKEN, "login_name": "  Member@Example.COM "}
    )

    assert result["user"]["id"] == MEMBER_ID


def test_a_user_is_selected_by_its_id(module_args: Any, module_result: Any, server: Any) -> None:
    result = _run(module_args, module_result, {"api_token": TOKEN, "user_id": MEMBER_ID})

    assert result["user"]["loginName"] == "member@example.com"


def test_a_selector_that_matches_nothing_is_an_error(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """A user is not something this collection creates, so it cannot be conjured."""
    module_args({"api_token": TOKEN, "login_name": "nobody@example.invalid"})

    with module_result.failure() as result:
        tailscale_user.main()

    assert "nobody@example.invalid" in result["msg"]
    assert "invite" in result["msg"], "the message says how a user comes to exist"
    assert server.writes == []


def test_an_id_the_tailnet_does_not_hold_is_an_error(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "user_id": "uNOSUCHUSER00001"})

    with module_result.failure() as result:
        tailscale_user.main()

    assert "uNOSUCHUSER00001" in result["msg"]
    assert server.writes == [], "an id the list does not hold is never sent"


def test_a_selector_matching_several_users_is_refused_rather_than_resolved(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """Choosing between them would be a guess, and a guess about access is not safe."""
    twin = {**MEMBER, "id": "uTWIN000000000001"}
    _stand_in(mocker, [OWNER, MEMBER, twin])

    module_args({"api_token": TOKEN, "login_name": "member@example.com"})
    with module_result.failure() as result:
        tailscale_user.main()

    assert "matches 2 users" in result["msg"]
    assert MEMBER_ID in result["msg"], "the message names the candidates"
    assert twin["id"] in result["msg"]
    assert "user_id" in result["msg"], "and says how to disambiguate"


def test_one_selector_is_required(module_args: Any, module_result: Any, server: Any) -> None:
    module_args({"api_token": TOKEN, "role": "admin"})
    with module_result.failure() as result:
        tailscale_user.main()

    assert "login_name" in result["msg"]
    assert server.requests == []


def test_the_two_selectors_are_mutually_exclusive(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "login_name": "member@example.com", "user_id": MEMBER_ID})
    with module_result.failure() as result:
        tailscale_user.main()

    assert "login_name" in result["msg"]
    assert server.requests == []


# Role.


def test_a_differing_role_is_written(module_args: Any, module_result: Any, server: Any) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "role": "admin"},
    )

    assert result["changed"] is True
    assert result["changed_fields"] == ["role"]
    assert server.writes == [f"/users/{MEMBER_ID}/role"]
    assert server.by_id[MEMBER_ID]["role"] == "admin"


def test_a_role_already_held_writes_nothing(
    module_args: Any, module_result: Any, server: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "role": "member"},
    )

    assert result["changed"] is False
    assert result["changed_fields"] == []
    assert server.writes == [], "invariant 1: a second run over the same task is quiet"


def test_the_role_request_carries_the_role_in_the_api_spelling(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """Asserted on the wire, because a field sent under the wrong name is ignored."""
    sent: list[str] = []
    tailnet = Tailnet()
    original = tailnet.__call__

    def record(url: str, *args: Any, **kwargs: Any) -> Any:
        if url.endswith("/role"):
            sent.append(str(kwargs.get("data")))
        return original(url, *args, **kwargs)

    mocker.patch(_API_URL, record)

    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "role": "it-admin"},
    )

    assert result["changed"] is True
    assert json.loads(sent[0]) == {"role": "it-admin"}


def test_a_role_outside_the_documented_set_is_refused_by_its_own_validation(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "login_name": "member@example.com", "role": "wizard"})

    with module_result.failure() as result:
        tailscale_user.main()

    assert "role" in result["msg"]
    assert "Traceback" not in result["msg"]
    assert server.requests == []


def test_promoting_the_only_owner_is_allowed(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """The guard is about losing the last owner, not about touching an owner at all."""
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "role": "owner"},
    )

    assert result["changed"] is True
    assert server.by_id[MEMBER_ID]["role"] == "owner"


def test_demoting_the_only_owner_is_refused_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "login_name": "owner@example.com", "role": "admin"})

    with module_result.failure() as result:
        tailscale_user.main()

    assert "only owner" in result["msg"]
    assert "owner role first" in result["msg"], "the message says how to get out"
    assert server.writes == []


def test_demoting_an_owner_while_another_holds_the_role_is_allowed(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """Two owners make the change safe, so refusing it would be wrong."""
    second_owner = {**MEMBER, "role": "owner"}
    _stand_in(mocker, [OWNER, second_owner])

    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "owner@example.com", "role": "auditor"},
    )

    assert result["changed"] is True


def test_the_owner_guard_holds_in_check_mode_too(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """A check run that reported a change would promise a request that never works."""
    module_args(
        {"api_token": TOKEN, "login_name": "owner@example.com", "role": "member"}, check_mode=True
    )

    with module_result.failure() as result:
        tailscale_user.main()

    assert "only owner" in result["msg"]
    assert server.writes == []


# Suspension.


def test_suspending_an_active_user_suspends_it(
    module_args: Any, module_result: Any, server: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "suspended": True},
    )

    assert result["changed"] is True
    assert result["changed_fields"] == ["suspended"]
    assert server.writes == [f"/users/{MEMBER_ID}/suspend"]
    assert result["user"]["status"] == "suspended", "the returned user is re-read"


def test_suspending_an_already_suspended_user_writes_nothing(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """The second half of the idempotency, in the direction a first run leaves behind."""
    _stand_in(mocker, [OWNER, {**MEMBER, "status": "suspended"}])

    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "suspended": True},
    )

    assert result["changed"] is False
    assert result["changed_fields"] == []


def test_restoring_a_suspended_user_restores_it(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    tailnet = _stand_in(mocker, [OWNER, {**MEMBER, "status": "suspended"}])

    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "suspended": False},
    )

    assert result["changed"] is True
    assert tailnet.writes == [f"/users/{MEMBER_ID}/restore"]
    assert tailnet.by_id[MEMBER_ID]["status"] == "active"


def test_restoring_a_user_who_is_not_suspended_writes_nothing(
    module_args: Any, module_result: Any, server: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "suspended": False},
    )

    assert result["changed"] is False
    assert server.writes == []


@pytest.mark.parametrize("status", OTHER_STATUSES)
def test_a_status_other_than_suspended_reads_as_not_suspended(
    module_args: Any, module_result: Any, mocker: Any, status: str
) -> None:
    """`idle` is the trap: it is not active, and a module testing for active would
    call restore on every run and report a change for ever."""
    _stand_in(mocker, [OWNER, {**MEMBER, "status": status}])

    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "suspended": False},
    )

    assert result["changed"] is False, f"a user with status {status} is not suspended"


# Approval.


def test_approving_a_user_awaiting_approval_approves_it(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    tailnet = _stand_in(mocker, [OWNER, PENDING])

    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "pending@example.com", "approved": True},
    )

    assert result["changed"] is True
    assert result["changed_fields"] == ["approved"]
    assert tailnet.writes == [f"/users/{PENDING_ID}/approve"]
    assert result["user"]["status"] == "active"


def test_approving_a_user_who_is_already_approved_writes_nothing(
    module_args: Any, module_result: Any, server: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "approved": True},
    )

    assert result["changed"] is False
    assert server.writes == []


def test_approving_a_suspended_user_calls_nothing(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """A suspended user is not awaiting approval, and the API's approval operation
    is documented as doing nothing for a user who is not."""
    tailnet = _stand_in(mocker, [OWNER, {**MEMBER, "status": "suspended"}])

    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "approved": True},
    )

    assert result["changed"] is False
    assert tailnet.writes == []


def test_withdrawing_an_approval_is_refused_rather_than_reported(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """The API cannot do it, so reporting a change would report one that cannot happen."""
    tailnet = _stand_in(mocker, [OWNER, PENDING])

    module_args({"api_token": TOKEN, "login_name": "pending@example.com", "approved": False})
    with module_result.failure() as result:
        tailscale_user.main()

    assert "cannot withdraw an approval" in result["msg"]
    assert "state: absent" in result["msg"], "the message names the way to do it"
    assert tailnet.writes == []


@pytest.mark.parametrize("status", OTHER_STATUSES)
def test_asking_for_a_user_that_needs_no_approval_is_satisfied(
    module_args: Any, module_result: Any, mocker: Any, status: str
) -> None:
    _stand_in(mocker, [OWNER, {**MEMBER, "status": status}])

    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "approved": False},
    )

    assert result["changed"] is False, f"a user with status {status} needs no approval"


# Removal.


def test_absent_removes_a_user_that_is_there(
    module_args: Any, module_result: Any, server: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "state": "absent"},
    )

    assert result["changed"] is True
    assert result["changed_fields"] == ["state"]
    assert server.writes == [f"/users/{MEMBER_ID}/delete"]
    assert MEMBER_ID not in server.by_id
    assert result["user"] is None


def test_absent_for_a_user_that_is_not_there_is_quiet(
    module_args: Any, module_result: Any, server: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "nobody@example.invalid", "state": "absent"},
    )

    assert result["changed"] is False, "absence is the state the task asked for"
    assert result["user"] is None
    assert server.writes == []


def test_absent_removing_the_only_owner_is_refused_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "login_name": "owner@example.com", "state": "absent"})

    with module_result.failure() as result:
        tailscale_user.main()

    assert "only owner" in result["msg"]
    assert server.writes == []


def test_absent_removing_one_of_two_owners_is_allowed(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    _stand_in(mocker, [OWNER, {**MEMBER, "role": "owner"}])

    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "owner@example.com", "state": "absent"},
    )

    assert result["changed"] is True


def test_a_property_of_a_user_that_is_being_removed_is_refused(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """`state: absent` and `suspended: true` are two instructions, not one."""
    module_args(
        {
            "api_token": TOKEN,
            "login_name": "member@example.com",
            "state": "absent",
            "suspended": True,
        }
    )

    with module_result.failure() as result:
        tailscale_user.main()

    assert "suspended" in result["msg"]
    assert server.requests == []


# Several properties in one task, and the order they are applied in.


def test_two_properties_are_applied_in_a_fixed_order(
    module_args: Any, module_result: Any, server: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {
            "api_token": TOKEN,
            "login_name": "member@example.com",
            "role": "admin",
            "suspended": True,
        },
    )

    assert result["changed_fields"] == ["role", "suspended"]
    assert server.writes == [f"/users/{MEMBER_ID}/role", f"/users/{MEMBER_ID}/suspend"]
    assert result["user"] == {
        "id": MEMBER_ID,
        "displayName": MEMBER["displayName"],
        "loginName": "member@example.com",
        "type": "member",
        "role": "admin",
        "status": "suspended",
        "deviceCount": 0,
    }, "and the returned user is what the tailnet holds, in the documented shape"


def test_running_twice_over_a_task_that_changes_three_properties_converges(
    module_args: Any, module_result: Any, server: Any
) -> None:
    options = {
        "api_token": TOKEN,
        "login_name": "member@example.com",
        "role": "auditor",
        "suspended": True,
    }

    first = _run(module_args, module_result, options)
    second = _run(module_args, module_result, options)

    assert first["changed"] is True
    assert second["changed"] is False, "invariant 1 over the whole reconcile"
    assert len(server.writes) == 2, "one write per changed property, and no more"


def test_the_diff_covers_only_the_properties_this_run_changed(
    module_args: Any, module_result: Any, server: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "role": "it-admin"},
        diff=True,
    )

    assert result["diff"]["before"] == {"role": "member"}
    assert result["diff"]["after"] == {"role": "it-admin"}


def test_the_diff_names_the_suspension_in_the_task_s_own_words(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """The API has one status field, so rendering `status: suspended` against
    `suspended: true` would show a different name for the same change."""
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "suspended": True},
        diff=True,
    )

    assert result["diff"] == {"before": {"suspended": False}, "after": {"suspended": True}}


def test_an_unchanged_run_reports_an_empty_diff(
    module_args: Any, module_result: Any, server: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com"},
        diff=True,
    )

    assert result["changed"] is False
    assert result["diff"]["before"] == result["diff"]["after"] == {}


# A write the API accepts and does not perform.


def test_a_write_the_api_accepted_without_applying_is_not_reported_as_a_change(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """The property the live API forced into the design.

    Measured against a real tailnet: a role change for the user a credential
    belongs to comes back 200 with no document and leaves the role as it was.
    Reporting that as a change would be reporting one that did not happen, and the
    next run would find nothing to do and say it happened again.
    """
    tailnet = _stand_in(mocker, [OWNER, MEMBER], ignore=("/suspend",))
    module_args({"api_token": TOKEN, "login_name": "member@example.com", "suspended": True})

    with module_result.failure() as result:
        tailscale_user.main()

    assert tailnet.writes == [f"/users/{MEMBER_ID}/suspend"], "the request was made"
    assert "success status" in result["msg"]
    assert "suspended" in result["msg"]
    assert "does not report a change it cannot see" in result["msg"]
    assert result["changed"] is False


def test_a_removal_the_api_accepted_without_applying_is_not_reported(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    tailnet = _stand_in(mocker, [OWNER, MEMBER], ignore=("/delete",))
    module_args({"api_token": TOKEN, "login_name": "member@example.com", "state": "absent"})

    with module_result.failure() as result:
        tailscale_user.main()

    assert MEMBER_ID in tailnet.by_id, "the user is still there"
    assert "still in the tailnet" in result["msg"]


def test_a_change_that_landed_is_reported_even_when_another_did_not(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """Two properties, one applied and one dropped. Saying nothing changed would be
    as wrong as saying both did."""
    _stand_in(mocker, [OWNER, MEMBER], ignore=("/role",))
    module_args(
        {
            "api_token": TOKEN,
            "login_name": "member@example.com",
            "role": "admin",
            "suspended": True,
        }
    )

    with module_result.failure() as result:
        tailscale_user.main()

    assert result["changed"] is True, "the suspension did happen"
    assert "role:" in result["msg"], "and the message names the one that did not"


def test_check_mode_reports_an_unapplied_write_without_asking_whether_it_took(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """Check mode asks nothing, so it cannot learn that a write would be dropped,
    and it says what it would do rather than what would happen."""
    _stand_in(mocker, [OWNER, MEMBER], ignore=("/suspend",))

    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "suspended": True},
        check_mode=True,
    )

    assert result["changed"] is True
    assert result["changed_fields"] == ["suspended"]


# Check mode.


def test_check_mode_reports_the_change_without_writing(
    module_args: Any, module_result: Any, server: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "suspended": True},
        check_mode=True,
    )

    assert result["changed"] is True
    assert result["changed_fields"] == ["suspended"]
    assert server.writes == []
    assert server.by_id[MEMBER_ID]["status"] == "active"
    assert server.requests == ["GET /tailnet/-/users"], "a check run reads and stops"


def test_check_mode_over_a_state_already_in_place_reports_no_change(
    module_args: Any, module_result: Any, server: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "suspended": False},
        check_mode=True,
    )

    assert result["changed"] is False
    assert server.writes == []


def test_check_mode_over_a_removal_returns_the_user_it_did_not_remove(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """The return value is the tailnet's state, so a check run must not claim the
    user is gone."""
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "state": "absent"},
        check_mode=True,
    )

    assert result["changed"] is True
    assert result["user"]["id"] == MEMBER_ID
    assert server.writes == []


# Failures the collection owns rather than the API.


def test_an_unreadable_user_list_fails_rather_than_reporting_the_user_absent(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """A 200 that is not the user list. Reading it as an empty tailnet would make
    `state: absent` delete a user that is there."""
    mocker.patch(_API_URL, lambda *args, **kwargs: _reply(200, "<html>captive portal</html>"))

    module_args({"api_token": TOKEN, "login_name": "member@example.com", "state": "absent"})
    with module_result.failure() as result:
        tailscale_user.main()

    assert "Nothing was written" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_user_list_holding_something_that_is_not_a_user_fails(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    mocker.patch(_API_URL, lambda *args, **kwargs: _reply(200, json.dumps({"users": ["oops"]})))

    module_args({"api_token": TOKEN, "login_name": "member@example.com"})
    with module_result.failure() as result:
        tailscale_user.main()

    assert "Nothing was written" in result["msg"]


def test_a_missing_credential_fails_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"login_name": "member@example.com", "suspended": True})

    with module_result.failure() as result:
        tailscale_user.main()

    assert "api_token" in result["msg"]
    assert server.requests == []


def test_a_refusal_from_the_api_is_reported_with_its_own_message(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """A user-owned token is refused with `not allowed to change own role`, and the
    operator needs to read that rather than a bare 400."""

    def refuse(url: str, *args: Any, **kwargs: Any) -> Any:
        if url.endswith("/role"):
            return _reply(400, json.dumps({"message": "not allowed to change own role"}))
        return _reply(200, json.dumps({"users": [OWNER, MEMBER]}))

    mocker.patch(_API_URL, refuse)
    module_args({"api_token": TOKEN, "login_name": "member@example.com", "role": "admin"})

    with module_result.failure() as result:
        tailscale_user.main()

    assert "not allowed to change own role" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_credential_never_reaches_the_result(
    module_args: Any, module_result: Any, server: Any
) -> None:
    result = _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "suspended": True},
    )

    assert TOKEN not in json.dumps(result, default=str)


def test_a_tailnet_is_addressed_by_name_when_given(
    module_args: Any, module_result: Any, server: Any
) -> None:
    _run(
        module_args,
        module_result,
        {
            "api_token": TOKEN,
            "tailnet": "-1234567890123",
            "login_name": "member@example.com",
        },
    )

    assert server.requests[0] == "GET /tailnet/-1234567890123/users"


def test_a_per_user_operation_is_not_addressed_through_a_tailnet_prefix(
    module_args: Any, module_result: Any, server: Any
) -> None:
    """/tailnet/{tailnet}/users/{id}/role does not exist, and it answers 404 rather
    than 400, so the shape is asserted rather than assumed."""
    _run(
        module_args,
        module_result,
        {"api_token": TOKEN, "login_name": "member@example.com", "suspended": True},
    )

    assert server.writes == [f"/users/{MEMBER_ID}/suspend"]


# The pure helpers, which the module's flow is written out of.


def test_reading_users_rejects_a_body_that_is_not_a_list_of_users() -> None:
    def answering(text: str) -> Any:
        return lambda *args, **kwargs: RawResponse(200, text, {})

    api = Api(
        ApiOptions(base_url=BASE, tailnet="-"),
        Authoriser(ApiToken(Secret(TOKEN))),
        answering(json.dumps({"users": "not a list"})),
    )

    with pytest.raises(tailscale_user.UserReadError):
        tailscale_user.read_users(api)


def test_matching_prefers_the_id_when_one_is_given() -> None:
    found = tailscale_user.matching([OWNER, MEMBER], {"user_id": OWNER_ID, "login_name": "x@y"})

    assert [user["id"] for user in found] == [OWNER_ID]


def test_only_owner_is_false_for_a_user_that_holds_no_role() -> None:
    assert tailscale_user.only_owner([OWNER, MEMBER], MEMBER) is False


def test_only_owner_compares_identifiers_not_login_names() -> None:
    """The same person can appear twice in one list, and only the id tells them
    apart for certain."""
    twice = {**OWNER, "id": "uOTHER0000000001"}

    assert tailscale_user.only_owner([OWNER, twice], twice) is False
