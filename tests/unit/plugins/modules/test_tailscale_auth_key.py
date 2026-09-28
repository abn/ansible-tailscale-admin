# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the tailscale_auth_key module, driven through the harness.

The fake endpoint below reproduces the behaviour measured against the real one
rather than a shape invented here, because a test that proves something about a
convenient fake proves nothing about the API. What it reproduces:

* `expirySeconds` is the duration the key was minted with, not a countdown, and
  it is returned unchanged by every later read.
* All three capability flags are stored and returned whether or not they were
  sent, false included.
* An update replaces the whole credential: a field the request omits is dropped.
* An update refuses a key of type `auth`, and refuses a change of key type.
* An update refuses an OAuth client with no scopes.
* A create returns the key material; nothing else ever does.
* A description is not unique, so two credentials can carry the same one.
* A key the API no longer holds answers 404 on a get and is absent from a list.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.modules import tailscale_auth_key

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
CLIENT = {
    "oauth_client_id": "kClientCNTRL",
    "oauth_client_secret": "tskey-client-kClientCNTRL-secret",
}
BASE = "https://api.tailscale.com/api/v2"

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"

#: What the API grants for a lifetime nobody asked for. Measured, not read.
DEFAULT_EXPIRY_SECONDS = 7776000


class Body:
    def __init__(self, text: str) -> None:
        self._text = text

    def decode(self, *args: str) -> str:
        return self._text


def _reply(status: int, text: str) -> Any:
    class Response:
        def __init__(self, status: int) -> None:
            self.status = status
            self.headers: dict = {}

        def read(self) -> Body:
            return Body(text)

    return Response(status)


def _created(auth_key: dict) -> dict:
    """An auth key as the API stores and returns it."""
    block = auth_key["capabilities"]["devices"]["create"]
    return {
        "id": auth_key["id"],
        "keyType": "auth",
        "created": "2026-01-01T00:00:00Z",
        "description": auth_key.get("description", ""),
        "expirySeconds": auth_key.get("expirySeconds", DEFAULT_EXPIRY_SECONDS),
        "expires": "2026-04-01T00:00:00Z",
        "capabilities": {
            "devices": {
                "create": {
                    "reusable": bool(block.get("reusable", False)),
                    "ephemeral": bool(block.get("ephemeral", False)),
                    "preauthorized": bool(block.get("preauthorized", False)),
                    # Absent rather than empty when no tag was sent, which is what
                    # the server does and what the comparison has to expect.
                    **({"tags": list(block["tags"])} if block.get("tags") else {}),
                }
            }
        },
    }


def _document(key: dict) -> dict:
    return {field: value for field, value in key.items() if field != "key"}


class Tailnet:
    """The keys endpoint, behaving as measured."""

    def __init__(self, keys: list[dict] | None = None) -> None:
        self.keys: dict[str, dict] = {key["id"]: dict(key) for key in keys or []}
        self.requests: list[str] = []
        self.bodies: list[dict] = []
        self._counter = 0

    def _new_id(self) -> str:
        self._counter += 1
        return f"kUnit{self._counter:04d}CNTRL"

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        line = url.partition(BASE)[2] or url
        self.requests.append(f"{method} {line}")
        if line == "/oauth/token":
            return _reply(200, json.dumps({"access_token": TOKEN, "expires_in": 3600}))

        rest = line.partition("/tailnet/-/keys")[2]
        key_id = rest.strip("/")

        if method == "GET" and not key_id:
            return _reply(200, json.dumps({"keys": list(self.keys.values())}))
        if method == "POST":
            return self._create(json.loads(str(data)))
        if method == "GET":
            if key_id not in self.keys:
                return _reply(404, json.dumps({"message": "not found"}))
            return _reply(200, json.dumps(self.keys[key_id]))
        if method == "PUT":
            return self._replace(key_id, json.loads(str(data)))
        if method == "DELETE":
            if key_id not in self.keys:
                return _reply(404, json.dumps({"message": "key not found"}))
            del self.keys[key_id]
            return _reply(200, "null")
        return _reply(404, json.dumps({"message": "not found"}))

    def _create(self, body: dict) -> Any:
        self.bodies.append(body)
        kind = body.get("keyType", "auth")
        if kind == "auth":
            stored = _created({"id": self._new_id(), **body})
        else:
            stored = {
                "id": self._new_id(),
                "keyType": kind,
                "created": "2026-01-01T00:00:00Z",
                **{field: value for field, value in body.items() if field != "keyType"},
            }
            if kind == "federated":
                # Measured: the API generates the audience and the claim rules at
                # creation whether the request carried them or not.
                stored.setdefault("audience", f"api.tailscale.com/{stored['id']}")
                stored.setdefault("customClaimRules", {})
        if kind in ("auth", "client"):
            stored["key"] = f"tskey-{kind}-{stored['id']}-secret"
        self.keys[str(stored["id"])] = stored
        return _reply(200, json.dumps(stored))

    def _replace(self, key_id: str, body: dict) -> Any:
        self.bodies.append(body)
        current = self.keys.get(key_id)
        if current is None:
            return _reply(404, json.dumps({"message": "not found"}))
        if body.get("keyType") != current.get("keyType"):
            return _reply(
                400,
                json.dumps(
                    {
                        "message": "cannot modify key type, attempting to change from "
                        f'"{current.get("keyType")}" to "{body.get("keyType")}"'
                    }
                ),
            )
        if current.get("keyType") == "auth":
            return _reply(400, json.dumps({"message": 'keys of type "auth" can not be updated'}))
        if current.get("keyType") == "client" and not body.get("scopes"):
            return _reply(
                400,
                json.dumps(
                    {
                        "message": "scopes cannot be empty, at least one scope is required "
                        "for OAuth clients"
                    }
                ),
            )
        # Replaces rather than merges: everything the request left out is gone, and
        # a collection sent empty is dropped rather than stored as an empty one.
        kept = {
            field: value
            for field, value in current.items()
            if field not in body or body[field] != []
        }
        kept.update({field: value for field, value in body.items() if value != []})
        self.keys[key_id] = kept
        return _reply(200, json.dumps(kept))


def _auth(**overrides: Any) -> dict:
    key = {
        "id": "kHeld00000001CNTRL",
        "keyType": "auth",
        "description": "build runners",
        "expirySeconds": 86400,
        "expires": "2026-01-02T00:00:00Z",
        "capabilities": {
            "devices": {
                "create": {
                    "reusable": False,
                    "ephemeral": True,
                    "preauthorized": True,
                    "tags": ["tag:ci"],
                }
            }
        },
    }
    key.update(overrides)
    return key


def _client(**overrides: Any) -> dict:
    key = {
        "id": "kHeld00000002CNTRL",
        "keyType": "client",
        "description": "reporter",
        "created": "2026-01-01T00:00:00Z",
        "scopes": ["devices:core:read", "dns:read"],
        "tags": ["tag:ci"],
    }
    key.update(overrides)
    return key


def _task(auth_key: dict) -> dict:
    """The module arguments that ask for exactly the auth key the fixture holds."""
    block = auth_key["capabilities"]["devices"]["create"]
    task: dict[str, Any] = {
        "api_token": TOKEN,
        "key_type": "auth",
        "description": auth_key["description"],
        "expiry_seconds": auth_key["expirySeconds"],
        "capabilities": {
            "devices": {
                "create": {
                    "reusable": block["reusable"],
                    "ephemeral": block["ephemeral"],
                    "preauthorized": block["preauthorized"],
                    "tags": list(block.get("tags") or []),
                }
            }
        },
    }
    return task


def _key_requests(server: Any) -> list[str]:
    """Every request the run made about keys, reads included."""
    return [line for line in server.requests if "/keys" in line]


def _writes(server: Any) -> list[str]:
    """The key requests that would have changed the tailnet."""
    return [line for line in _key_requests(server) if line.startswith(("POST", "PUT", "DELETE"))]


@pytest.fixture
def server(mocker: Any) -> Any:
    tailnet = Tailnet()
    mocker.patch(_API_URL, tailnet)
    return tailnet


@pytest.fixture
def held(mocker: Any) -> Any:
    """A server already holding one credential, registered before the test runs."""

    def load(key: dict) -> Tailnet:
        tailnet = Tailnet([key])
        mocker.patch(_API_URL, tailnet)
        return tailnet

    return load


def test_an_absent_key_is_minted(module_args: Any, module_result: Any, server: Any) -> None:
    module_args(
        {
            **CLIENT,
            "key_type": "auth",
            "description": "build runners",
            "expiry_seconds": 86400,
            "capabilities": {"devices": {"create": {"tags": ["tag:ci"]}}},
        }
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is True
    assert result["key"]["keyType"] == "auth"
    assert result["key"]["expirySeconds"] == 86400
    assert server.bodies[0]["keyType"] == "auth"
    assert server.bodies[0]["description"] == "build runners"


def test_the_secret_is_reported_only_by_the_run_that_minted_the_key(
    module_args: Any, module_result: Any, held: Any
) -> None:
    held(_auth())
    module_args(_task(_auth()))

    with module_result.success() as first:
        tailscale_auth_key.main()

    assert first["secret"] is None, "the key was already there, so nothing was minted"
    assert json.dumps(first["key"]).find("tskey-") < 0

    with module_result.failure():
        module_args(_task(_auth(expirySeconds=3600)))
        tailscale_auth_key.main()

    module_args(_task(_auth()), check_mode=True)
    with module_result.success() as checked:
        tailscale_auth_key.main()

    assert checked["secret"] is None, "a check run mints nothing, so it has no secret"


def test_the_secret_reaches_the_result_but_no_diff(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "client",
            "description": "reporter",
            "scopes": ["dns:read"],
        }
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    secret = result["secret"]
    assert secret and secret.startswith("tskey-client-")
    rendered = json.dumps(result["diff"], default=str)
    assert secret not in rendered, "the diff is rendered into logs and must not carry a credential"
    assert secret not in json.dumps(result["key"], default=str)


def test_running_twice_converges(module_args: Any, module_result: Any, held: Any) -> None:
    tailnet = held(_auth())
    module_args(_task(_auth()))

    with module_result.success():
        tailscale_auth_key.main()

    with module_result.success() as second:
        tailscale_auth_key.main()

    assert second["changed"] is False, "a second run over identical input must not change"
    assert second["changed_fields"] == []
    assert not [line for line in tailnet.requests if line.startswith(("POST", "PUT", "DELETE"))]


def test_the_expiry_the_api_computes_is_not_compared(
    module_args: Any, module_result: Any, held: Any
) -> None:
    """`expirySeconds` is the duration the key was minted with, not a countdown.

    The API also returns an absolute `expires`, which moves on every run. A module
    that compared it would report a change for ever, and there is no way to ask
    for it: it is a consequence of the duration, not an option.
    """
    held(_auth(expirySeconds=86400, expires="2026-01-02T00:00:00Z"))
    module_args(_task(_auth()))

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is False
    assert result["key"]["expires"] == "2026-01-02T00:00:00Z"
    assert result["diff"]["before"] == result["diff"]["after"]


def test_a_flag_the_task_left_out_is_left_as_the_key_has_it(
    module_args: Any, module_result: Any, held: Any
) -> None:
    """An option the task did not name is the tailnet's, which is the rule everywhere.

    Reading a missing flag as false instead would make a task naming one flag a
    request to turn the other two off, and an auth key cannot be updated, so such
    a task would fail on every run rather than converge.
    """
    held(_auth())
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "auth",
            "description": "build runners",
            "capabilities": {"devices": {"create": {"tags": ["tag:ci"]}}},
        }
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is False, "ephemeral and preauthorized are true on the tailnet"
    assert result["changed_fields"] == []


def test_a_flag_the_task_turns_off_is_a_change(
    module_args: Any, module_result: Any, held: Any
) -> None:
    tailnet = held(_auth())
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "auth",
            "description": "build runners",
            "capabilities": {"devices": {"create": {"ephemeral": False, "tags": ["tag:ci"]}}},
        }
    )

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "`capabilities`" in result["msg"]
    assert _writes(tailnet) == []


def test_a_differing_auth_key_fails_rather_than_reporting_an_impossible_change(
    module_args: Any, module_result: Any, held: Any
) -> None:
    tailnet = held(_auth(expirySeconds=86400))
    module_args(_task(_auth(expirySeconds=3600)))

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "expirySeconds" in result["msg"]
    assert "`auth`" in result["msg"]
    assert "PUT" not in " ".join(tailnet.requests), "an update would be refused by the API"


def test_a_differing_description_on_a_client_is_updated(
    module_args: Any, module_result: Any, held: Any
) -> None:
    tailnet = held(_client())
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "client",
            "key_id": "kHeld00000002CNTRL",
            "description": "renamed",
            "scopes": ["dns:read"],
        }
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is True
    assert result["key"]["description"] == "renamed"
    assert tailnet.bodies[0]["description"] == "renamed"


def test_an_update_carries_the_fields_the_task_did_not_name(
    module_args: Any, module_result: Any, held: Any
) -> None:
    """Measured: the endpoint replaces the credential, so an omitted field is dropped."""
    tailnet = held(_client())
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "client",
            "description": "reporter",
            "scopes": ["dns:read"],
        }
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert tailnet.bodies[0]["tags"] == ["tag:ci"], "the tags the task did not name must survive"
    assert tailnet.bodies[0]["description"] == "reporter"
    assert result["key"]["tags"] == ["tag:ci"]


def test_scopes_in_another_order_are_not_a_change(
    module_args: Any, module_result: Any, held: Any
) -> None:
    tailnet = held(_client())
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "client",
            "description": "reporter",
            "scopes": ["dns:read", "devices:core:read"],
        }
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is False
    assert tailnet.bodies == []


def test_tags_are_cleared_by_an_empty_list(module_args: Any, module_result: Any, held: Any) -> None:
    """Measured: the server drops an empty list, which is how a tag list is cleared."""
    tailnet = held(_client())
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "client",
            "description": "reporter",
            "scopes": ["dns:read", "devices:core:read"],
            "tags": [],
        }
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is True
    assert tailnet.bodies[0]["tags"] == []
    assert "tags" not in result["key"]

    with module_result.success() as second:
        tailscale_auth_key.main()

    assert second["changed"] is False, "a cleared tag list reads back as absent, not as empty"


def test_a_federated_identity_keeps_the_audience_the_api_generated(
    module_args: Any, module_result: Any, held: Any
) -> None:
    tailnet = held(
        {
            "id": "TUnit0001CNTRL-kUnit0002CNTRL",
            "keyType": "federated",
            "description": "partner",
            "created": "2026-01-01T00:00:00Z",
            "scopes": ["dns:read"],
            "issuer": "https://login.example.com",
            "subject": "team-42-*",
            "audience": "api.tailscale.com/TUnit0001CNTRL-kUnit0002CNTRL",
            "customClaimRules": {},
        }
    )
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "federated",
            "description": "partner",
            "scopes": ["dns:read"],
            "issuer": "https://login.example.com",
            "subject": "team-42-*",
        }
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is False
    assert tailnet.bodies == []


def test_a_federated_identity_keeps_the_claim_rules_the_task_did_not_name(
    module_args: Any, module_result: Any, held: Any
) -> None:
    tailnet = held(
        {
            "id": "TUnit0001CNTRL-kUnit0003CNTRL",
            "keyType": "federated",
            "description": "partner",
            "created": "2026-01-01T00:00:00Z",
            "scopes": ["dns:read"],
            "issuer": "https://login.example.com",
            "subject": "team-42-*",
            "audience": "api.tailscale.com/TUnit0001CNTRL-kUnit0003CNTRL",
            "customClaimRules": {"team": "42"},
        }
    )
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "federated",
            "description": "partner",
            "scopes": ["dns:read"],
            "issuer": "https://login.example.com",
            "subject": "team-42-*",
        }
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is False
    assert tailnet.bodies == []


def test_a_claim_rule_the_task_adds_is_written(
    module_args: Any, module_result: Any, held: Any
) -> None:
    tailnet = held(
        {
            "id": "TUnit0001CNTRL-kUnit0004CNTRL",
            "keyType": "federated",
            "description": "partner",
            "created": "2026-01-01T00:00:00Z",
            "scopes": ["dns:read"],
            "issuer": "https://login.example.com",
            "subject": "team-42-*",
            "audience": "api.tailscale.com/TUnit0001CNTRL-kUnit0004CNTRL",
            "customClaimRules": {},
        }
    )
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "federated",
            "description": "partner",
            "scopes": ["dns:read"],
            "issuer": "https://login.example.com",
            "subject": "team-42-*",
            "custom_claim_rules": {"team": "42"},
        }
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is True
    assert tailnet.bodies[0]["customClaimRules"] == {"team": "42"}
    assert "audience" in tailnet.bodies[0], "the generated audience survives the update"


def test_a_duplicate_description_is_refused(
    module_args: Any, module_result: Any, server: Any
) -> None:
    server.keys = {
        "kOne000000001CNTRL": _client(id="kOne000000001CNTRL"),
        "kTwo000000002CNTRL": _client(id="kTwo000000002CNTRL"),
    }
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "client",
            "description": "reporter",
            "scopes": ["dns:read"],
        }
    )

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "kOne000000001CNTRL" in result["msg"]
    assert "kTwo000000002CNTRL" in result["msg"]
    assert server.bodies == [], "nothing may be written against an ambiguous name"


def test_a_credential_of_another_kind_is_refused(
    module_args: Any, module_result: Any, held: Any
) -> None:
    tailnet = held(_client())
    module_args({"api_token": TOKEN, "key_type": "auth", "description": "reporter"})

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "`client`" in result["msg"]
    assert tailnet.bodies == []


def test_an_option_belonging_to_another_kind_is_refused_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "client",
            "description": "reporter",
            "scopes": ["dns:read"],
            "expiry_seconds": 3600,
        }
    )

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "expiry_seconds" in result["msg"]
    assert "`client`" in result["msg"] and "`auth`" in result["msg"]
    assert _key_requests(server) == []


def test_scopes_on_an_auth_key_are_refused_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "auth",
            "description": "build runners",
            "scopes": ["devices:core"],
        }
    )

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "scopes" in result["msg"]
    assert _writes(server) == [], "the create was refused before anything was sent"


def test_a_tailnet_owned_auth_key_with_no_tag_is_refused_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({**CLIENT, "key_type": "auth", "description": "build runners"})

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "tags" in result["msg"]
    assert _writes(server) == [], "the API would refuse this, and its wording misreads as a scope"


def test_a_user_owned_auth_key_with_no_tag_is_minted(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "key_type": "auth", "description": "build runners"})

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is True
    assert server.bodies[0]["capabilities"] == {
        "devices": {
            "create": {"reusable": False, "ephemeral": False, "preauthorized": False, "tags": []}
        }
    }


def test_a_client_with_no_scopes_is_refused_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "key_type": "client", "description": "reporter"})

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "scopes" in result["msg"]
    assert _writes(server) == []


def test_a_federated_identity_with_no_issuer_is_refused_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "federated",
            "description": "partner",
            "scopes": ["dns:read"],
        }
    )

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "issuer" in result["msg"] and "subject" in result["msg"]
    assert _writes(server) == []


def test_a_key_is_removed(module_args: Any, module_result: Any, held: Any) -> None:
    tailnet = held(_auth())
    module_args(
        {"api_token": TOKEN, "key_type": "auth", "description": "build runners", "state": "absent"}
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is True
    assert result["key"] is None
    assert result["removed_key"]["id"] == "kHeld00000001CNTRL"
    assert tailnet.keys == {}


def test_removing_a_key_twice_reports_nothing_the_second_time(
    module_args: Any, module_result: Any, held: Any
) -> None:
    held(_auth())
    module_args(
        {"api_token": TOKEN, "key_type": "auth", "description": "build runners", "state": "absent"}
    )

    with module_result.success() as first:
        tailscale_auth_key.main()
    with module_result.success() as second:
        tailscale_auth_key.main()

    assert first["changed"] is True
    assert second["changed"] is False
    assert second["removed_key"] is None


def test_removing_a_key_that_is_not_there_reports_nothing(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {"api_token": TOKEN, "key_type": "auth", "description": "build runners", "state": "absent"}
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is False
    assert server.bodies == []


def test_removing_a_key_the_api_never_held_reports_nothing(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "auth",
            "key_id": "kAbsent0000001CNTRL",
            "state": "absent",
        }
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is False
    assert "DELETE" not in " ".join(server.requests)


def test_a_revoked_key_named_by_description_is_replaced_and_removed(
    module_args: Any, module_result: Any, held: Any
) -> None:
    """Measured: the API still describes a revoked key and sets `invalid` on it.

    The dead credential is removed as well as replaced, which is what lets the task
    converge. The replacement carries the description, so the next run finds one
    match, valid, and has nothing to do. Leaving the dead one behind made the second
    run ambiguous, or minted another credential on every run.
    """
    tailnet = held(_client(id="kRevoked00001CNTRL", revoked="2026-01-02T00:00:00Z", invalid=True))
    options = {
        "api_token": TOKEN,
        "key_type": "client",
        "description": "reporter",
        "scopes": ["dns:read"],
    }
    module_args(options)

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is True
    assert result["key"]["id"] != "kRevoked00001CNTRL"
    assert result["removed_key"]["id"] == "kRevoked00001CNTRL"
    assert result["diff"]["before"]["id"] == "kRevoked00001CNTRL"
    assert "kRevoked00001CNTRL" not in tailnet.keys, "the dead credential was removed"
    assert "PUT" not in " ".join(tailnet.requests)

    module_args(options)
    with module_result.success() as second:
        tailscale_auth_key.main()

    assert second["changed"] is False, "the second run finds one credential and is quiet"


def test_a_revoked_key_named_by_id_is_refused(
    module_args: Any, module_result: Any, held: Any
) -> None:
    """An id is assigned at mint time, so a replacement cannot carry it.

    A task naming the dead id would mint another credential on every run, which is
    not a state the task can reach, so the module refuses rather than looping.
    """
    tailnet = held(_client(id="kRevoked00003CNTRL", revoked="2026-01-02T00:00:00Z", invalid=True))
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "client",
            "key_id": "kRevoked00003CNTRL",
            "description": "reporter",
            "scopes": ["dns:read"],
        }
    )

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "description" in result["msg"], "the message names the way that converges"
    assert "POST" not in " ".join(tailnet.requests), "nothing was minted"


def test_a_revoked_key_is_already_absent_for_a_removal(
    module_args: Any, module_result: Any, held: Any
) -> None:
    tailnet = held(_client(id="kRevoked00002CNTRL", revoked="2026-01-02T00:00:00Z", invalid=True))
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "client",
            "key_id": "kRevoked00002CNTRL",
            "state": "absent",
        }
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is False
    assert "DELETE" not in " ".join(tailnet.requests)


def test_check_mode_mints_nothing(module_args: Any, module_result: Any, server: Any) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "client",
            "description": "reporter",
            "scopes": ["dns:read"],
        },
        check_mode=True,
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is True
    assert result["secret"] is None
    assert server.bodies == []
    assert [line for line in server.requests if line.startswith(("POST", "PUT", "DELETE"))] == []


def test_check_mode_writes_no_removal(module_args: Any, module_result: Any, held: Any) -> None:
    tailnet = held(_auth())
    module_args(
        {"api_token": TOKEN, "key_type": "auth", "description": "build runners", "state": "absent"},
        check_mode=True,
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["changed"] is True
    assert tailnet.keys != {}


def test_an_expired_key_reports_the_whole_credential(
    module_args: Any, module_result: Any, held: Any
) -> None:
    held(_auth())
    module_args(_task(_auth()))

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["key"]["expires"] == "2026-01-02T00:00:00Z"
    assert result["key"]["expirySeconds"] == 86400


def test_a_key_selected_by_id_reports_that_id_unaltered(
    module_args: Any, module_result: Any, held: Any
) -> None:
    """The id the task named comes back readable, which is what `no_log: false` buys.

    Ansible censors any option whose name carries "key", so both `key_type` and
    `key_id` opt out, and neither is key material. The harness keeps the
    controller's redaction list rather than applying it, so what this asserts is
    the value itself reaching the result: with the option censored, the
    controller replaces this id with a placeholder everywhere it appears.
    """
    tailnet = held(_client())
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "client",
            "key_id": "kHeld00000002CNTRL",
            "description": "renamed",
            "scopes": ["dns:read", "devices:core:read"],
        }
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert result["key"]["id"] == "kHeld00000002CNTRL"
    assert result["diff"]["after"]["keyType"] == "client"
    assert tailnet.bodies[0]["description"] == "renamed"


def test_a_credential_never_reaches_the_result(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "client",
            "description": "reporter",
            "scopes": ["dns:read"],
        }
    )

    with module_result.success() as result:
        tailscale_auth_key.main()

    assert TOKEN not in json.dumps(result, default=str)


def test_no_credential_at_all_fails_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"key_type": "client", "description": "reporter", "scopes": ["dns:read"]})

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "api_token" in result["msg"]
    assert server.requests == []


def test_a_task_naming_neither_an_id_nor_a_description_is_refused(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({"api_token": TOKEN, "key_type": "client", "scopes": ["dns:read"]})

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "one of the following" in result["msg"] or "required" in result["msg"]
    assert server.requests == []


def test_a_tag_the_tailnet_does_not_own_is_reported_with_the_advice(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    class NoSuchTag(Tailnet):
        def __call__(
            self,
            url: str,
            data: Any = None,
            headers: Any = None,
            method: str = "GET",
            **kwargs: Any,
        ) -> Any:
            if method == "POST":
                self.requests.append(f"POST {url.partition(BASE)[2]}")
                return _reply(
                    400,
                    json.dumps(
                        {"message": "requested tags [tag:no-owner] are invalid or not permitted"}
                    ),
                )
            return super().__call__(url, data=data, headers=headers, method=method, **kwargs)

    mocker.patch(_API_URL, NoSuchTag())
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "auth",
            "description": "build runners",
            "capabilities": {"devices": {"create": {"tags": ["tag:no-owner"]}}},
        }
    )

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "tagOwners" in result["msg"]
    assert "tag:no-owner" in result["msg"]


def test_a_key_list_that_is_not_a_list_is_refused(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    class Broken:
        def __init__(self) -> None:
            self.requests: list[str] = []

        def __call__(
            self,
            url: str,
            data: Any = None,
            headers: Any = None,
            method: str = "GET",
            **kwargs: Any,
        ) -> Any:
            self.requests.append(method)
            if "/keys" in url:
                return _reply(200, json.dumps({"keys": {"id": "kOne000000001CNTRL"}}))
            return _reply(404, "{}")

    broken = Broken()
    mocker.patch(_API_URL, broken)
    module_args(
        {
            "api_token": TOKEN,
            "key_type": "client",
            "description": "reporter",
            "scopes": ["dns:read"],
        }
    )

    with module_result.failure() as result:
        tailscale_auth_key.main()

    assert "no list of keys" in result["msg"]
    assert "POST" not in broken.requests, "assuming no keys would mint a second credential"
