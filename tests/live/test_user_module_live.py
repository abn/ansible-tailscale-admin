# SPDX-License-Identifier: BSD-2-Clause
"""`tailscale_user` against a real tailnet, through the module.

Every assertion drives the module's ``main()``, never the kernel, except the two
that measure the API directly, which exist to justify the skips below.

Why so much of this is skipped
------------------------------
The tailnet under test holds exactly one user, and it is the identity the suite's
credential belongs to. So every operation that changes a user is an operation on
the credential running the suite: suspending it or deleting it would end the
session, and every test after that one would fail for a reason that reads like a
module bug.

That is not a shortcut, it is the API. A user cannot be created: a user invite is
a separate resource that only a user-owned key may create, and an invited user
does not appear in the user list at all until it accepts and authenticates. Both
facts were measured against this tailnet, and
``test_a_second_user_cannot_be_created_through_the_api`` records the first.

So the destructive paths are covered in full by the unit suite, and here they are
skipped with the hazard named. A skip that says why is information; a test that
suspends the credential it is running as and reports the result as a module
failure is not.

Nothing in this file writes, so nothing in it needs restoring: every write path
either refuses before it sends anything or is a request the API itself performs
no effect for. The two requests made directly are an invite, which the API refuses
and which is removed again if it ever accepts, and a role change the plan refuses.
"""

from __future__ import annotations

import json
import os
from typing import Any
from typing import ClassVar
from urllib.error import HTTPError
from urllib.request import Request
from urllib.request import urlopen

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import ApiOptions
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import post_form
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import Authoriser
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import OauthClient
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import Secret
from ansible_collections.abn.tailscale.plugins.modules import tailscale_user

#: The same base URL the harness uses, read from the environment so a run against a
#: stand-in does not silently reach the live API.
BASE_URL = os.environ.get("TS_API_BASE", "https://api.tailscale.com/api/v2")

pytestmark = pytest.mark.live_smoke

#: The one reason four of the six operations cannot be exercised here, named once so
#: every skip says the same thing.
HAZARD = (
    "the tailnet under test holds one user, which is the identity this suite's credential "
    "belongs to, and the API cannot create a second one: an invite is refused to an OAuth "
    "client and an invited user does not appear in the user list until it authenticates. "
    "Suspending or deleting that user would end the run, and every test after it would fail "
    "for a reason that reads like a module bug; changing its role is refused by the API three "
    "different ways and, where it answers success, changes nothing. Covered in full by the "
    "unit suite instead."
)


def _run(module_args: Any, module_result: Any, options: dict, **flags: Any) -> dict:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_user.main()
    return dict(result)


def _users(api: Api) -> list[dict]:
    body = api.call("users_list", "GET").body
    return list(body["users"]) if isinstance(body, dict) else []


def _the_only_user(api: Api) -> dict:
    users = _users(api)
    assert len(users) == 1, (
        f"this suite reasons about a tailnet with a single user, and it holds {len(users)}. "
        "The skips in this file were written for one, and a second user means the destructive "
        "operations can be tested rather than skipped."
    )
    return users[0]


def _unchanged(api: Api, before: dict) -> None:
    """The credential's own user, still exactly as it was.

    Asserted after every run that could have written, because the one way this
    suite can do real damage is the one it is written not to do.
    """
    after = _users(api)
    assert len(after) == 1, "a user was removed"
    for field in ("id", "loginName", "role", "status"):
        assert after[0].get(field) == before.get(field), f"{field} moved: {after[0]}"


def _raw(credentials: dict[str, str], method: str, path: str, body: Any = None) -> tuple[int, str]:
    """One request to a path the collection has no operation for, and its answer.

    Two questions in this file are about the API rather than about the module: can
    a second user be created at all, and what does the API say when a credential
    is asked to change the role of the user it belongs to. Neither has a row in
    the operation table, because the collection makes neither call, so they are
    made here over the same OAuth client the modules run as.

    The status is returned as well as the body, because the body of a refusal is
    the only thing that says which refusal it was.
    """
    options = ApiOptions(base_url=BASE_URL, tailnet="-")
    authoriser = Authoriser(
        OauthClient(credentials["oauth_client_id"], Secret(credentials["oauth_client_secret"])),
        lambda form_path, form: post_form(options.base_url, form_path, form),
    )
    request = Request(
        f"{options.base_url}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {authoriser.bearer().expose()}",
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
        method=method,
    )
    try:
        with urlopen(request, timeout=30) as response:
            return int(response.status), response.read().decode("utf-8", "replace")
    except HTTPError as error:
        return int(error.code), error.read().decode("utf-8", "replace")


# What the tailnet looks like, established before anything is asserted about it.


def test_the_tailnet_holds_the_one_user_this_file_assumes(
    api: Api,
) -> None:
    """The premise of every skip below, asserted rather than assumed.

    If this fails, the skips are wrong: a second user means suspend, restore,
    delete and a role change are all testable against a user that is not the
    credential.
    """
    user = _the_only_user(api)
    assert user["role"] == "owner", "the credential's own user, so the owner guard is reachable"
    assert user["status"] == "active", "not suspended, so the suspend path is the one to skip"


def test_a_second_user_cannot_be_created_through_the_api(
    credentials: dict[str, str], api: Api
) -> None:
    """Why the destructive operations are skipped rather than tested.

    An invite is the only way to put a second user on a tailnet, and the API
    refuses it to anything but a user-owned key. Measured here rather than
    asserted from the documentation, because this is the fact the whole file's
    shape rests on. The wording of the refusal has changed between credentials
    ("operation only permitted for user-owned keys" from one, "calling actor does
    not have enough permissions" from another), so the status is what is asserted
    and not the prose.

    Should the API ever accept it, the invite this creates is removed in the same
    test and the failure says so, because a pending user left on a tailnet is
    somebody else's problem afterwards. No address is given, so no message is
    sent to anyone either way.
    """
    status, body = _raw(credentials, "POST", "/tailnet/-/user-invites", [{"role": "member"}])
    if status == 200:
        invite = json.loads(body)[0]["id"]
        removed, removal = _raw(credentials, "DELETE", f"/user-invites/{invite}")
        assert not removal, "the API answered the removal with a body"
        assert removed == 200, (
            f"the API accepted an invite from an OAuth client (HTTP {status}) and the suite "
            f"could not remove it again (HTTP {removed}). Invite {invite} is on the tailnet."
        )
        pytest.fail(
            "the API accepted a user invite from an OAuth client, so a second user can be "
            f"created and the skips in this file are out of date. Removed again: {invite}."
        )

    assert status == 403, f"HTTP {status}: {body}"
    assert len(_users(api)) == 1, "and no user appeared"


def test_a_role_write_reaches_the_api_and_this_plan_refuses_a_paid_role(
    credentials: dict[str, str], api: Api
) -> None:
    """The role endpoint is reachable, and this tailnet's plan refuses part of it.

    `auditor` is a paid role, so the request is refused on the plan rather than on
    the user, which makes it the one role write that can be measured here without
    touching anything: a 403 changes nothing.

    The roles this plan does allow are not probed, and the reason is in
    :data:`HAZARD`. Measured once against this tailnet, a role change for the user
    the suite's credential belongs to is answered 200 with no document and leaves
    the role exactly as it was, while the same request for the role already held is
    answered 500. If that ever changed, the first probe would demote the only owner
    of the tailnet and the request that would put it back is the one that comes
    back 500.
    """
    user = _the_only_user(api)
    status, body = _raw(credentials, "POST", f"/users/{user['id']}/role", {"role": "auditor"})

    assert status == 403, f"HTTP {status}: {body}"
    assert "plan" in body or "billing" in body, f"HTTP {status}: {body}"
    _unchanged(api, user)


# Reading and selection, which are safe because they write nothing.


def test_a_task_with_nothing_to_change_reports_the_user_it_found(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    owner = _the_only_user(api)

    result = _run(module_args, module_result, {**credentials, "login_name": owner["loginName"]})

    assert result["changed"] is False
    assert result["changed_fields"] == []
    assert result["user"]["id"] == owner["id"]
    assert result["user"]["role"] == owner["role"]
    assert result["user"]["status"] == owner["status"]


def test_a_user_is_found_by_its_id_too(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    owner = _the_only_user(api)

    result = _run(module_args, module_result, {**credentials, "user_id": owner["id"]})

    assert result["user"]["loginName"] == owner["loginName"]


def test_running_twice_over_a_task_that_changes_nothing_is_quiet(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    owner = _the_only_user(api)
    options = {**credentials, "login_name": owner["loginName"], "role": owner["role"]}

    first = _run(module_args, module_result, options)
    second = _run(module_args, module_result, options)

    assert first["changed"] is False
    assert second["changed"] is False, "invariant 1, against a real tailnet"
    _unchanged(api, owner)


def test_a_login_name_the_tailnet_does_not_hold_is_an_error(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    """Not a vague failure: the message says how a user comes to exist."""
    before = _the_only_user(api)

    module_args({**credentials, "login_name": "nobody@stress.invalid"})
    with module_result.failure() as result:
        tailscale_user.main()

    assert "nobody@stress.invalid" in result["msg"]
    assert "invite" in result["msg"]
    assert "Traceback" not in result["msg"]
    _unchanged(api, before)


def test_an_id_the_tailnet_does_not_hold_is_an_error_before_any_request(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    before = _the_only_user(api)

    module_args({**credentials, "user_id": "uNoSuchUserInThisTailnet"})
    with module_result.failure() as result:
        tailscale_user.main()

    assert "uNoSuchUserInThisTailnet" in result["msg"]
    assert "Traceback" not in result["msg"]
    _unchanged(api, before)


def test_absent_for_a_user_that_is_not_there_is_quiet(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    """Absence is the state the task asked for, so there is nothing to do."""
    before = _the_only_user(api)

    result = _run(
        module_args,
        module_result,
        {**credentials, "login_name": "nobody@stress.invalid", "state": "absent"},
    )

    assert result["changed"] is False
    assert result["user"] is None
    _unchanged(api, before)


# The guards, which is where a single-user tailnet is the most useful thing to have.


def test_demoting_the_only_owner_is_refused(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    owner = _the_only_user(api)

    module_args({**credentials, "login_name": owner["loginName"], "role": "member"})
    with module_result.failure() as result:
        tailscale_user.main()

    assert "only owner" in result["msg"]
    assert "owner role first" in result["msg"], "the message names the way out"
    _unchanged(api, owner)


def test_demoting_the_only_owner_is_refused_in_check_mode_too(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    """A check run reporting a change would promise a request that cannot work."""
    owner = _the_only_user(api)

    module_args(
        {**credentials, "login_name": owner["loginName"], "role": "member"}, check_mode=True
    )
    with module_result.failure() as result:
        tailscale_user.main()

    assert "only owner" in result["msg"]
    _unchanged(api, owner)


def test_removing_the_only_owner_is_refused(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    owner = _the_only_user(api)

    module_args({**credentials, "login_name": owner["loginName"], "state": "absent"})
    with module_result.failure() as result:
        tailscale_user.main()

    assert "only owner" in result["msg"]
    _unchanged(api, owner)


def test_a_role_the_user_already_holds_writes_nothing(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    owner = _the_only_user(api)

    result = _run(
        module_args,
        module_result,
        {**credentials, "login_name": owner["loginName"], "role": owner["role"]},
    )

    assert result["changed"] is False
    _unchanged(api, owner)


def test_suspending_a_user_who_is_not_suspended_writes_nothing(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    """The safe half of the suspend reconcile, against a user who is not suspended."""
    owner = _the_only_user(api)
    if owner["status"] == "suspended":
        pytest.skip(f"{HAZARD}. This tailnet's user is suspended, which nothing here will undo.")

    result = _run(
        module_args,
        module_result,
        {**credentials, "login_name": owner["loginName"], "suspended": False},
    )

    assert result["changed"] is False
    _unchanged(api, owner)


def test_approving_a_user_who_needs_no_approval_writes_nothing(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    owner = _the_only_user(api)

    result = _run(
        module_args,
        module_result,
        {**credentials, "login_name": owner["loginName"], "approved": True},
    )

    assert result["changed"] is False
    _unchanged(api, owner)


def test_a_write_the_api_accepts_and_does_not_perform_is_refused(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    """The one write this tailnet can be asked for, and the answer it gives.

    The read is doctored to report the credential's own user as awaiting approval,
    and nothing else is: the request the module then makes is the real one, against
    the real API. The API answers it 200 and does nothing, because the user does
    not in fact need approving, and the module has to notice that rather than
    report a change it cannot see.

    That is the property this design turns on, and it is the one thing about the
    users API a mock cannot produce: a success status with nothing behind it. The
    role endpoint does the same for a user a credential belongs to, which is why
    the role transition is skipped rather than tested.

    Only the read is faked, because a second user is where a real one would have to
    come from and the API cannot produce one. The user is checked afterwards, so a
    probe that turned out to change something fails here rather than quietly.
    """
    before = _the_only_user(api)
    if before["status"] == "suspended":
        pytest.skip(f"{HAZARD}. This tailnet's user is suspended, which nothing here will undo.")

    from ansible_collections.abn.tailscale.plugins.module_utils._tailscale import _api as api_module

    class _Listing:
        """A 200 carrying the real user list with one status replaced."""

        status = 200
        headers: ClassVar[dict] = {}

        def __init__(self, users: list[dict]) -> None:
            self._users = users

        def read(self) -> Any:
            payload = json.dumps({"users": self._users})

            class _Body:
                def decode(self, *args: str) -> str:
                    return payload

            return _Body()

    real_open_url = api_module.open_url

    def doctored(url: str, *args: Any, **kwargs: Any) -> Any:
        if kwargs.get("method") == "GET" and url.endswith("/users"):
            users = [dict(before)]
            users[0]["status"] = "needs-approval"
            return _Listing(users)
        return real_open_url(url, *args, **kwargs)

    api_module.open_url = doctored  # ty: ignore[invalid-assignment]
    try:
        module_args({**credentials, "login_name": before["loginName"], "approved": True})
        with module_result.failure() as result:
            tailscale_user.main()
    finally:
        # Restored before the assertion below reads the tailnet, or the read would
        # be answered by the stand-in and would prove nothing.
        api_module.open_url = real_open_url

    assert "success status" in result["msg"]
    assert "awaiting approval" in result["msg"], "the message says what the tailnet holds"
    assert result["changed"] is False
    _unchanged(api, before)


# Validation, which costs no request and no credential.


def test_removing_a_user_while_also_setting_a_property_is_refused(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    before = _the_only_user(api)

    module_args(
        {
            **credentials,
            "login_name": before["loginName"],
            "state": "absent",
            "suspended": True,
        }
    )
    with module_result.failure() as result:
        tailscale_user.main()

    assert "removes the user" in result["msg"]
    _unchanged(api, before)


def test_a_role_outside_the_documented_set_is_refused(
    credentials: dict[str, str], module_args: Any, module_result: Any, api: Api
) -> None:
    before = _the_only_user(api)

    module_args({**credentials, "login_name": before["loginName"], "role": "wizard"})
    with module_result.failure() as result:
        tailscale_user.main()

    assert "role" in result["msg"]
    assert "Traceback" not in result["msg"]
    _unchanged(api, before)


def test_no_credential_fails_before_any_request(
    module_args: Any, module_result: Any, api: Api
) -> None:
    before = _the_only_user(api)

    module_args({"login_name": before["loginName"], "suspended": True})
    with module_result.failure() as result:
        tailscale_user.main()

    assert "api_token" in result["msg"] or "oauth_client_id" in result["msg"]
    assert "Traceback" not in result["msg"]
    _unchanged(api, before)


# The four paths this tailnet cannot carry, each skipped with the hazard named.


def test_suspending_a_user(module_args: Any, module_result: Any, api: Api) -> None:
    pytest.skip(f"suspending a user: {HAZARD}")


def test_restoring_a_suspended_user(module_args: Any, module_result: Any, api: Api) -> None:
    pytest.skip(f"restoring a suspended user: {HAZARD}")


def test_deleting_a_user(module_args: Any, module_result: Any, api: Api) -> None:
    pytest.skip(f"deleting a user: {HAZARD}")


def test_changing_a_role(module_args: Any, module_result: Any, api: Api) -> None:
    pytest.skip(f"changing a role: {HAZARD}")
