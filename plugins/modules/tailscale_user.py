#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_user
short_description: Manage the role and access of a tailnet's users
version_added: 1.0.0
description:
  - Reconciles the role, suspension and approval of a user that already belongs to
    a tailnet, and removes one with O(state=absent).
  - A user is not created by this collection. One appears when somebody
    authenticates or is invited, so the module finds the user first and then
    manages what the API lets it manage. A task naming a user the tailnet does
    not hold is an error, because the module cannot make the user exist and
    reporting success would be a lie.
  - The user is selected by O(login_name) or by O(user_id), and exactly one of
    the two. A selector matching more than one user is refused rather than
    resolved to one of them.
  - O(suspended) and O(approved) are two readings of the one status field the API
    returns. Every other status, C(idle) and C(over-billing-limit) among them,
    means neither suspended nor awaiting approval, so neither operation is
    called for a user in one of them.
  - A role change is access control, and a tailnet nobody can administer cannot
    be repaired through the API. The module refuses a change that would leave
    the tailnet with no owner before sending it, naming the user and the way out.
  - A credential cannot change the user it belongs to, and the API does not always
    say so. The same request is answered C(not allowed to change own role) by one
    credential, a 500 by another and a success by a third, which leaves the user
    untouched. The module therefore reads the user back after writing it, and
    reports a change only when the tailnet holds it.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.check_mode_diff_mode
  - abn.tailscale._attributes.connection_delegation
options:
  state:
    description:
      - Whether the user should belong to the tailnet.
      - C(absent) removes the user. The devices the user owns are not removed with
        them.
    type: str
    choices:
      - present
      - absent
    default: present
    version_added: 1.0.0
  login_name:
    description:
      - The emailish login name of the user, matched without regard to case.
      - Mutually exclusive with O(user_id), and one of the two is required.
    type: str
    version_added: 1.0.0
  user_id:
    description:
      - The identifier the API gives the user, which is what every per-user
        endpoint takes.
      - Mutually exclusive with O(login_name), and one of the two is required.
    type: str
    version_added: 1.0.0
  role:
    description:
      - The role the user holds in the tailnet, which decides what the user may
        change in the admin console.
      - The API documents these as owner, member, admin, it-admin, network-admin,
        billing-admin and auditor.
      - Left as the user already holds it when not given.
    type: str
    choices:
      - owner
      - member
      - admin
      - it-admin
      - network-admin
      - billing-admin
      - auditor
    version_added: 1.0.0
  suspended:
    description:
      - Whether the user is suspended from the tailnet. A suspended user keeps its
        devices and its role, and cannot reach the tailnet until it is restored.
      - Left as the user already is when not given.
    type: bool
    version_added: 1.0.0
  approved:
    description:
      - Whether the user is cleared to join the tailnet. It matters only where the
        tailnet requires approval for new users, and the API documents the
        approval operation as doing nothing where approval is not required.
      - A user awaiting approval cannot be put back into that state, because the
        API can approve a user but cannot withdraw an approval. A task asking for
        C(false) against such a user is refused rather than reported as a change
        that would not happen.
      - Left as the user already is when not given.
    type: bool
    version_added: 1.0.0
"""

EXAMPLES = r"""
- name: Give one user the ability to manage devices, leaving the rest alone
  abn.tailscale.tailscale_user:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    login_name: contractor@example.com
    role: it-admin

- name: Suspend a user who has left, and take away their role
  abn.tailscale.tailscale_user:
    api_token: "{{ tailscale_api_token }}"
    login_name: leaver@example.com
    role: member
    suspended: true

- name: Restore a suspended user
  abn.tailscale.tailscale_user:
    api_token: "{{ tailscale_api_token }}"
    user_id: u1234567890abcdef
    suspended: false

- name: Remove a user from the tailnet
  abn.tailscale.tailscale_user:
    api_token: "{{ tailscale_api_token }}"
    login_name: leaver@example.com
  state: absent

- name: Report what would change without writing it
  abn.tailscale.tailscale_user:
    api_token: "{{ tailscale_api_token }}"
    login_name: contractor@example.com
    role: admin
  check_mode: true
"""

RETURN = r"""
user:
  description:
    - The user as the tailnet holds it after the run, re-read from the API because
      every per-user operation returns no document of its own.
    - A projection of the fields the API returns, holding what the module reads
      and manages rather than the whole object.
    - Null once the user is gone, and also when the run was in check mode and the
      removal was not carried out.
  returned: always
  type: dict
  sample:
    id: u1234567890abcdef
    displayName: Some User
    loginName: someuser@example.com
    type: member
    role: admin
    status: active
changed_fields:
  description:
    - The names of the properties this run changed, in the order they were
      applied, empty when it changed none.
  returned: always
  type: list
  elements: str
  sample:
    - role
    - suspended
diff:
  description:
    - The value of each property this run changed, before and after, rendered by
      C(--diff).
    - The values are the module's own, so they read as the task wrote them, and
      the properties the run did not change are absent rather than shown
      unchanged.
  returned: always
  type: dict
  contains:
    before:
      description: The value each changed property holds now.
      returned: always
      type: dict
    after:
      description: The value each changed property was set to, or would be set to.
      returned: always
      type: dict
"""

from typing import Any
from typing import NamedTuple

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import (
    connection_arguments,
)

#: The roles the API documents, in the order the vendored description lists them.
#: Literals rather than something read at runtime, because a module executes on the
#: target host with no YAML parser.
ROLES = (
    "owner",
    "member",
    "admin",
    "it-admin",
    "network-admin",
    "billing-admin",
    "auditor",
)

#: The one status that means a user is suspended. Every other status means it is
#: not, which is why a task asking for `suspended: false` against a user whose
#: status is `idle` calls nothing.
SUSPENDED = "suspended"

#: The one status that means a user cannot join until somebody approves it.
NEEDS_APPROVAL = "needs-approval"

ARGUMENT_SPEC = connection_arguments(
    state={"type": "str", "default": "present", "choices": ["present", "absent"]},
    login_name={"type": "str"},
    user_id={"type": "str"},
    role={"type": "str", "choices": list(ROLES)},
    suspended={"type": "bool"},
    approved={"type": "bool"},
)


class UserReadError(Exception):
    """The user list could not be read, so no selection can be made from it."""


class Action(NamedTuple):
    """One request the run will make, and the two values the diff renders.

    The plan is data rather than a sequence of calls, because check mode has to
    render the diff of a run it is not going to make, and because a run that
    applies one property and is refused the next has to report what it applied.
    """

    #: The module option this action serves, which is the name the diff carries.
    field: str
    #: The operation from the table, so no call site names a request line.
    operation: str
    #: The request body, or None where the operation takes one.
    body: dict[str, Any] | None
    before: Any
    after: Any


def read_users(api: Api) -> list[dict]:
    """Every user the tailnet holds, or fail rather than read nothing as none.

    The list is the only place a user exists as far as this module is concerned:
    the per-user endpoints take an identifier and cannot be enumerated, so a
    selection made from anything else would be a guess.
    """
    body = api.call("users_list", "GET").body
    if not isinstance(body, dict) or not isinstance(body.get("users"), list):
        # Reachable from a proxy error page or a captive portal answering 200, and
        # reading that as an empty tailnet would report a user as absent, which is
        # the one answer that leads to a removal.
        raise UserReadError(
            "The tailnet's user list did not come back as a list of users, so the user this "
            "task named could not be found. Nothing was written."
        )
    users = []
    for entry in body["users"]:
        if not isinstance(entry, dict):
            raise UserReadError(
                "The tailnet's user list holds an entry that is not a user, so it cannot be "
                "matched against a selector. Nothing was written."
            )
        users.append(entry)
    return users


def matching(users: list[dict], params: dict) -> list[dict]:
    """The users a task's selector names, which may be none, one or several.

    Several is a failure the caller reports rather than resolves. A login name is
    matched without regard to case, because that is the likeliest reason a task
    written from the admin console would otherwise match nothing.
    """
    if params.get("user_id") is not None:
        wanted = str(params["user_id"]).strip()
        return [user for user in users if str(user.get("id", "")).strip() == wanted]
    wanted = str(params["login_name"]).strip().casefold()
    return [user for user in users if str(user.get("loginName", "")).strip().casefold() == wanted]


#: The fields of a user this module returns. A whitelist rather than the object the
#: API sent, which also carries an avatar URL, the tailnet the user came from and
#: two timestamps, none of which the module reads or manages.
RETURNED_FIELDS = ("id", "displayName", "loginName", "type", "role", "status", "deviceCount")


def project(user: dict | None) -> dict | None:
    """The user as this collection returns it, or None once it is gone."""
    if user is None:
        return None
    return {field: user[field] for field in RETURNED_FIELDS if field in user}


def describe(user: dict) -> str:
    """How a user is named in a failure, which is what an operator can act on."""
    name = user.get("loginName") or "a user with no login name"
    return f"{name} (id {user.get('id')})"


def only_owner(users: list[dict], user: dict) -> bool:
    """Whether removing or demoting this user would leave the tailnet with none.

    Compared by identifier rather than by login name, because only the identifier
    tells two entries of the same list apart for certain.
    """
    holders = [entry for entry in users if entry.get("role") == "owner"]
    return len(holders) == 1 and str(holders[0].get("id", "")) == str(user.get("id", ""))


def refuse_leaving_no_owner(module: AnsibleModule, user: dict, verb: str) -> None:
    module.fail_json(
        msg=" ".join(
            [
                f"{describe(user)} is the only owner of the tailnet, and {verb} would leave the",
                "tailnet with none. A tailnet with no owner cannot be administered through the",
                "API, so this module refuses before sending anything rather than send a request",
                "whose outcome it cannot predict. Give another user the owner role first, in a",
                "task of its own, then re-run.",
            ]
        )
    )


def refuse_unapprovable(module: AnsibleModule, user: dict) -> None:
    module.fail_json(
        msg=" ".join(
            [
                f"{describe(user)} is waiting for approval, and this task asks for a user that is",
                "not. The API can approve a user but cannot withdraw an approval, so no request",
                "would satisfy the task, and reporting a change would be reporting one that does",
                "not happen. Set state: absent to remove the user instead.",
            ]
        )
    )


def refuse_ambiguous(module: AnsibleModule, found: list[dict]) -> None:
    """A selector that matches several users is refused rather than resolved.

    Naming them is what makes the task fixable, because the identifier is the
    only thing that tells two of them apart.
    """
    candidates = ", ".join(describe(user) for user in found)
    module.fail_json(
        msg=" ".join(
            [
                f"The selector matches {len(found)} users of the tailnet: {candidates}.",
                "This module refuses to choose between them, because a task that means one user",
                "and changes the wrong one is not repaired by re-running it. Select the one you",
                "mean by user_id.",
            ]
        )
    )


def refuse_missing(module: AnsibleModule, params: dict) -> None:
    selector = (
        f"user id {params['user_id']}"
        if params.get("user_id") is not None
        else f"login name {params['login_name']}"
    )
    module.fail_json(
        msg=" ".join(
            [
                f"The tailnet holds no {selector}.",
                "A user is not something this collection creates: one appears when somebody",
                "authenticates to the tailnet or is invited to it, and an invite is not a user",
                "until it is accepted. Check the spelling, or set state: absent if the point is",
                "that the user should not be there.",
            ]
        )
    )


def plan_present(
    user: dict, users: list[dict], params: dict, module: AnsibleModule
) -> list[Action]:
    """The requests that bring one existing user to the state the task states.

    Every decision is taken from the one read, so a run changing two properties
    does not change what the second is measured against. None of these operations
    alters another's precondition: the role is independent of the status, and
    approval and suspension are both decided from that status without either
    rewriting it first.
    """
    actions: list[Action] = []
    wanted_role = params.get("role")
    if wanted_role is not None and user.get("role") != wanted_role:
        if wanted_role != "owner" and only_owner(users, user):
            refuse_leaving_no_owner(module, user, f"a role change to {wanted_role}")
        actions.append(
            Action("role", "user_set_role", {"role": wanted_role}, user.get("role"), wanted_role)
        )

    awaiting = user.get("status") == NEEDS_APPROVAL
    wanted_approval = params.get("approved")
    if wanted_approval is not None:
        if wanted_approval and awaiting:
            actions.append(Action("approved", "user_approve", None, False, True))
        elif not wanted_approval and awaiting:
            refuse_unapprovable(module, user)

    suspended = user.get("status") == SUSPENDED
    wanted_suspension = params.get("suspended")
    if wanted_suspension is not None and wanted_suspension != suspended:
        actions.append(
            Action(
                "suspended",
                "user_suspend" if wanted_suspension else "user_restore",
                None,
                suspended,
                wanted_suspension,
            )
        )
    return actions


def plan_absent(user: dict, users: list[dict], module: AnsibleModule) -> list[Action]:
    if only_owner(users, user):
        refuse_leaving_no_owner(module, user, "a removal")
    return [Action("state", "user_delete", None, "present", "absent")]


def diff_of(actions: list[Action]) -> dict[str, dict]:
    """The before and after a diff renders, holding only what this run changed.

    A diff across the whole user document would carry the profile picture URL, the
    timestamps and the device count, and bury the two lines the operator asked
    about.
    """
    return {
        "before": {action.field: action.before for action in actions},
        "after": {action.field: action.after for action in actions},
    }


def reached(action: Action, user: dict | None) -> bool:
    """Whether the tailnet now holds what this action asked for.

    Read back rather than assumed, because a success status is not proof a write
    was carried out. Measured against a real tailnet: a role change for the user a
    credential belongs to is answered 200 with no document and leaves the role
    exactly as it was, and the same request for the role the user already holds is
    answered 500. Reporting either as a change would be reporting one that did not
    happen, which is the failure invariant 1 exists to prevent.
    """
    if action.field == "state":
        return user is None
    if user is None:
        return False
    if action.field == "role":
        return user.get("role") == action.after
    if action.field == "suspended":
        return (user.get("status") == SUSPENDED) is bool(action.after)
    return (user.get("status") == NEEDS_APPROVAL) is not bool(action.after)


def held(action: Action, user: dict | None) -> str:
    """What the tailnet holds for one action, in the words the action uses."""
    if action.field == "state":
        return "the user is still in the tailnet"
    if user is None:
        return "the user is gone"
    if action.field == "role":
        return f"the role is {user.get('role')}"
    if action.field == "suspended":
        return "the user is suspended" if user.get("status") == SUSPENDED else "the user is not"
    return (
        "the user is awaiting approval"
        if user.get("status") == NEEDS_APPROVAL
        else "the user needs no approval"
    )


def refuse_unapplied(module: AnsibleModule, actions: list[Action], user: dict | None) -> None:
    """The API answered a write successfully and the tailnet does not show it.

    Failing rather than reporting the change, because the alternative is a task
    that says it did something it cannot show it did, and a second run over the
    same input would then find nothing to do and say the same thing again.
    """
    outstanding = [action for action in actions if not reached(action, user)]
    landed = [action for action in actions if action not in outstanding]
    detail = "; ".join(
        f"{action.field}: {held(action, user)}, the task asked for {action.after}"
        for action in outstanding
    )
    module.fail_json(
        changed=bool(landed),
        msg=" ".join(
            [
                f"The Tailscale API answered {len(outstanding)} of the {len(actions)} requests for",
                f"{describe(user) if user else 'the user'} with a success status, and the tailnet",
                f"does not hold what they asked for: {detail}.",
                "A success status is not proof that a write was applied, and this module does not",
                "report a change it cannot see. The usual cause is that the credential belongs to",
                "the user being changed, which Tailscale does not permit: manage that user with a",
                "different credential, or re-run to reconcile.",
            ]
        ),
    )


def find_again(api: Api, user_id: Any) -> dict | None:
    """The user after a write, or None once it is gone.

    A removal the API accepted but the list has not caught up with reports the
    document the list still holds, rather than a success the tailnet does not
    show. A second run then finds the user and removes it again, which is the
    convergence the collection is built around.
    """
    for user in read_users(api):
        if str(user.get("id", "")) == str(user_id):
            return user
    return None


def refuse_property_of_a_removal(module: AnsibleModule, params: dict) -> None:
    """A property of a user that exists, asked for while removing them.

    Ansible's own ``required_if`` expresses this, and reports it as three options
    being *missing*, which is the opposite of what happened. The message is the
    whole value of refusing, so it is written here.
    """
    named = [name for name in ("role", "suspended", "approved") if params.get(name) is not None]
    module.fail_json(
        msg=" ".join(
            [
                f"This task removes the user, and also sets {', '.join(named)}, which are",
                "properties of a user that is there. It cannot do both: the removal leaves",
                "nothing for the property to apply to, and reporting the removal as a change",
                "while quietly dropping the property would be a task that says less than it",
                "reads. Split it into two tasks, or keep only the removal.",
            ]
        )
    )


def run(module: AnsibleModule) -> None:
    params = module.params
    if params["state"] == "absent" and any(
        params.get(name) is not None for name in ("role", "suspended", "approved")
    ):
        refuse_property_of_a_removal(module, params)
    try:
        api = build_client(params)
        users = read_users(api)
        found = matching(users, params)
        if len(found) > 1:
            refuse_ambiguous(module, found)

        if params["state"] == "absent":
            if not found:
                module.exit_json(
                    changed=False, user=None, changed_fields=[], diff={"before": {}, "after": {}}
                )
            selected = found[0]
            actions = plan_absent(selected, users, module)
        else:
            if not found:
                refuse_missing(module, params)
            selected = found[0]
            actions = plan_present(selected, users, params, module)
            if not actions:
                module.exit_json(
                    changed=False,
                    user=project(selected),
                    changed_fields=[],
                    diff={"before": {}, "after": {}},
                )

        rendered = diff_of(actions)
        if not module.check_mode:
            user_id = str(selected.get("id", ""))
            for action in actions:
                api.call(
                    action.operation,
                    "POST",
                    params={"userId": user_id},
                    body=action.body,
                )
            # Every per-user operation answers with no document at all, so what a
            # write left behind is known only by asking again. Returning the
            # requested values instead would return a user nobody has.
            selected = find_again(api, selected.get("id"))
            if not all(reached(action, selected) for action in actions):
                refuse_unapplied(module, actions, selected)

        module.exit_json(
            changed=True,
            user=project(selected),
            changed_fields=[action.field for action in actions],
            diff=rendered,
        )
    except UserReadError as error:
        module.fail_json(msg=str(error))
    except CredentialError as error:
        module.fail_json(msg=str(error))
    except TailscaleError as error:
        module.fail_json(msg=str(error))


def main() -> None:
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        required_one_of=[["login_name", "user_id"]],
        mutually_exclusive=[
            ("api_token", "oauth_client_id"),
            ("api_token", "oauth_client_secret"),
            ("login_name", "user_id"),
        ],
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
