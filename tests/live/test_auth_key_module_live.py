# SPDX-License-Identifier: BSD-2-Clause
"""`tailscale_auth_key` against a real tailnet, through the module.

Every assertion drives the module's ``main()``, never the kernel. The properties
worth a real API are the ones a fake cannot establish, because a fake answers
whatever the module expects:

* whether the credential a run mints is the credential the next run finds, which
  is the whole of the first invariant;
* what the API returns once and never again, and where the module can put it;
* whether an update replaces the credential rather than merging into it, which
  the module has to carry the unmentioned fields across for;
* whether a create the module accepts is one the API accepts.

Anything created here is registered with the ``teardown`` fixture from before it
exists, so a failure between the create and the assertion still removes it. The
fixture also removes it at the end of the test, so a test that leaves a
credential behind cannot make the next one ambiguous.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.modules import tailscale_auth_key

pytestmark = pytest.mark.live_smoke

#: A description the tests own, so a leak is identifiable. Alphanumerics, hyphens
#: and spaces only, because the API refuses anything else.
PREFIX = "ac-stress key"

#: The tag the suite's policy grants an owner to, which an auth key minted with an
#: OAuth client must carry. `conftest.PROBE_TAG` is the same tag for the same
#: reason: a tag exists only where the policy file says so.
TAG = "tag:stress"


def _remove(api: Api, key_id: str) -> None:
    """`keys_delete`, which is the only call that removes a credential.

    `device_expire_key` takes a `deviceId` and expires the key a device
    registered with, so it has nothing to act on for a key this suite minted.
    A credential already gone is the state this wanted.
    """
    if not key_id:
        return
    try:
        api.call("keys_delete", "DELETE", params={"keyId": key_id})
    except Exception:
        return


def _keys_described(api: Api, description: str) -> list[dict[str, Any]]:
    body = api.call("keys_list", "GET").body
    keys = body.get("keys", []) if isinstance(body, dict) else []
    return [key for key in keys if key.get("description") == description]


def _key_of(api: Api, key_id: str) -> dict[str, Any]:
    body = api.call("keys_get", "GET", params={"keyId": key_id}).body
    return body if isinstance(body, dict) else {}


@pytest.fixture
def minted(api: Api, teardown: Any, probe_policy: dict[str, Any]) -> Iterator[Any]:
    """Register a credential for removal, from the result of the run that made it.

    The id reaches the teardown ledger before the test's next assertion, so a
    create that succeeds and a run that then fails to record it still leaves
    something that can remove it.

    `probe_policy` is a dependency rather than a detail: an auth key minted with
    an OAuth client must carry a tag, and a tag exists only where the policy file
    grants an owner to it. Without the fixture the create is refused for a reason
    that has nothing to do with the module.
    """
    created: list[str] = []

    def remember(result: dict[str, Any]) -> str:
        key_id = str((result.get("key") or {}).get("id") or "")
        if not key_id:
            return ""
        created.append(key_id)
        teardown.register(f"key {key_id}", lambda k=key_id: _remove(api, k))
        return key_id

    yield remember

    for key_id in created:
        _remove(api, key_id)


def _run(
    module_args: Any, module_result: Any, options: dict[str, Any], **flags: Any
) -> dict[str, Any]:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_auth_key.main()
    return dict(result)


def _auth_key(credentials: dict[str, str], description: str, **overrides: Any) -> dict[str, Any]:
    task: dict[str, Any] = {
        **credentials,
        "key_type": "auth",
        "description": description,
        "expiry_seconds": 3600,
        "capabilities": {
            "devices": {
                "create": {
                    "reusable": False,
                    "ephemeral": True,
                    "preauthorized": True,
                    "tags": [TAG],
                }
            }
        },
    }
    task.update(overrides)
    return task


def test_a_key_minted_here_is_found_by_the_next_run(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    minted: Any,
) -> None:
    task = _auth_key(credentials, f"{PREFIX} converge")

    first = _run(module_args, module_result, task)
    key_id = minted(first)
    second = _run(module_args, module_result, task)

    assert first["changed"] is True
    assert key_id
    assert second["changed"] is False, "the second run over the same task must change nothing"
    assert second["changed_fields"] == []
    assert second["key"]["id"] == key_id
    assert second["diff"]["before"] == second["diff"]["after"]


def test_the_stored_expiry_is_a_duration_and_not_a_countdown(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    minted: Any,
) -> None:
    """The value the API returns does not move, which is what makes it comparable."""
    task = _auth_key(credentials, f"{PREFIX} expiry", expiry_seconds=3600)

    first = _run(module_args, module_result, task)
    minted(first)
    second = _run(module_args, module_result, task)

    assert first["key"]["expirySeconds"] == 3600
    assert first["key"]["expires"], "the API also returns the instant it computes"
    assert second["key"]["expirySeconds"] == 3600
    assert second["changed"] is False


def test_a_flag_the_task_left_out_is_left_as_the_key_has_it(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    minted: Any,
) -> None:
    """Measured: the API stores all three flags, false included, and returns them all."""
    first = _run(module_args, module_result, _auth_key(credentials, f"{PREFIX} flags"))
    key_id = minted(first)

    partial = _auth_key(credentials, f"{PREFIX} flags")
    partial["capabilities"] = {"devices": {"create": {"tags": [TAG]}}}
    second = _run(module_args, module_result, partial)

    block = _key_of(api, key_id)["capabilities"]["devices"]["create"]
    assert block["ephemeral"] is True and block["preauthorized"] is True
    assert second["changed"] is False, "naming one flag must not be a request to turn the rest off"


def test_the_secret_comes_back_once_and_is_never_in_the_document(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    minted: Any,
) -> None:
    task = _auth_key(credentials, f"{PREFIX} secret")

    first = _run(module_args, module_result, task)
    minted(first)

    secret = first["secret"]
    assert secret and secret.startswith("tskey-auth-")
    assert secret not in json.dumps(first["key"]), "the document must not carry the secret"
    assert secret not in json.dumps(first["diff"]), "the diff is rendered into logs"

    second = _run(module_args, module_result, task)
    assert second["secret"] is None, "the API never returns it again, so neither does the module"


def test_check_mode_mints_nothing(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    minted: Any,
) -> None:
    description = f"{PREFIX} checked"
    task = _auth_key(credentials, description)

    checked = _run(module_args, module_result, task, check_mode=True)
    assert checked["changed"] is True
    assert checked["secret"] is None, "a check run mints nothing, so it has no secret"
    assert _keys_described(api, description) == [], "check mode wrote a credential"

    after = _run(module_args, module_result, task)
    minted(after)
    assert after["secret"], "the run that mints it is the only one that can report it"


def test_a_client_is_created_narrowed_and_removed(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    minted: Any,
) -> None:
    description = f"{PREFIX} client"
    task = {
        **credentials,
        "key_type": "client",
        "description": description,
        "scopes": ["devices:core:read", "dns:read"],
    }

    first = _run(module_args, module_result, task)
    key_id = minted(first)
    assert first["secret"].startswith("tskey-client-")

    again = _run(module_args, module_result, task)
    assert again["changed"] is False, "an unmentioned field must not be dropped and restored"

    updated = _run(module_args, module_result, dict(task, scopes=["dns:read"]))
    assert updated["changed"] is True
    assert updated["changed_fields"] == ["scopes"]
    assert updated["key"]["scopes"] == ["dns:read"]
    assert _key_of(api, key_id)["description"] == description, (
        "the update replaces the document, so the module has to carry the description across"
    )

    removed = _run(module_args, module_result, dict(task, state="absent"))
    assert removed["changed"] is True
    assert removed["key"] is None
    assert _keys_described(api, description) == []

    twice = _run(module_args, module_result, dict(task, state="absent"))
    assert twice["changed"] is False, "a removal that already happened is not a change"


def test_scopes_in_another_order_are_not_a_change(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    minted: Any,
) -> None:
    description = f"{PREFIX} order"
    first = _run(
        module_args,
        module_result,
        {
            **credentials,
            "key_type": "client",
            "description": description,
            "scopes": ["dns:read", "devices:core:read"],
        },
    )
    minted(first)

    second = _run(
        module_args,
        module_result,
        {
            **credentials,
            "key_type": "client",
            "description": description,
            "scopes": ["devices:core:read", "dns:read"],
        },
    )

    assert second["changed"] is False


def test_a_federated_identity_keeps_the_audience_the_api_generated(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    minted: Any,
) -> None:
    description = f"{PREFIX} federated"
    task = {
        **credentials,
        "key_type": "federated",
        "description": description,
        "issuer": "https://example.com",
        "subject": "ac-stress-*",
        "scopes": ["devices:core:read"],
    }

    first = _run(module_args, module_result, task)
    key_id = minted(first)
    assert first["key"]["audience"], "the API generates one at creation"
    assert first["secret"] is None, "a federated identity has no key material"

    second = _run(module_args, module_result, task)
    assert second["changed"] is False, "the generated audience must survive the comparison"
    assert _key_of(api, key_id)["audience"] == first["key"]["audience"]


def test_an_expiry_an_auth_key_cannot_take_names_the_way_out(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    minted: Any,
) -> None:
    """The API refuses to update a key of type `auth`, so the module refuses first."""
    description = f"{PREFIX} fixed"
    first = _run(
        module_args, module_result, _auth_key(credentials, description, expiry_seconds=3600)
    )
    minted(first)

    module_args(_auth_key(credentials, description, expiry_seconds=7200))
    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "expirySeconds" in result["msg"]
    assert "state: absent" in result["msg"], "the message has to name what the operator can do"


def test_a_tag_the_tailnet_does_not_own_is_refused_with_the_advice(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    task = _auth_key(credentials, f"{PREFIX} unowned")
    task["capabilities"] = {"devices": {"create": {"tags": ["tag:no-owner-here"]}}}
    module_args(task)

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "tagOwners" in result["msg"]
    assert "tag:no-owner-here" in result["msg"]


def test_an_option_belonging_to_another_kind_is_refused_before_a_request(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
) -> None:
    description = f"{PREFIX} foreign"
    module_args(
        {
            **credentials,
            "key_type": "client",
            "description": description,
            "scopes": ["dns:read"],
            "expiry_seconds": 3600,
        }
    )

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "expiry_seconds" in result["msg"]
    assert "`auth`" in result["msg"]
    assert _keys_described(api, description) == [], "nothing may be written against a refused task"
