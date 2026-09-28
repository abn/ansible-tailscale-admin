#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_auth_key
short_description: Manage the credentials of a tailnet
version_added: 0.1.0
description:
  - Creates, updates and removes the credentials of a Tailscale tailnet, which
    are auth keys, OAuth clients and federated identities.
  - The three kinds share one endpoint and three request shapes rather than being
    one resource, so O(key_type) selects which shape the task uses, and the module
    refuses an option belonging to another kind rather than passing it on to be
    refused for the wrong reason.
  - The secret of a new credential is returned once, by the run that created it.
    The API never returns it again, so a run that finds the credential already in
    place reports no secret, and no later run can compare one. Take it from a
    C(register) on the run that reported a change.
  - An auth key cannot be updated once it exists, so a task describing an
    existing auth key differently fails rather than reporting a change it cannot
    make. Remove the key and let the next run mint another.
  - Option names are snake case, as Ansible requires. The API spells the same
    fields in camel case, and the mapping happens here.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.check_mode_diff_mode
  - abn.tailscale._attributes.connection_delegation
options:
  state:
    description:
      - Whether the credential is present or absent.
      - Absent removes it, and the removal cannot be undone. The secret of a
        removed key is gone, and a device that registered with it keeps its
        registration until the device is removed.
    type: str
    choices:
      - present
      - absent
    default: present
    version_added: 0.1.0
  key_type:
    description:
      - Which kind of credential this task manages, which is the API's own
        C(keyType) value.
      - The key is found by O(key_id) when one is given and by O(description)
        otherwise, and a credential found under a different kind is a failure
        rather than a second credential with the same description.
    type: str
    choices:
      - auth
      - client
      - federated
    default: auth
    version_added: 0.1.0
  key_id:
    description:
      - The id of an existing credential, as the API reports it.
      - The id is opaque, so O(description) is the practical way to name a
        credential in a playbook. Given an id, the lookup is by id alone.
    type: str
    version_added: 0.1.0
  description:
    description:
      - The short purpose of the credential, which the admin console shows and
        which is the handle this module selects by.
      - The API accepts up to 50 alphanumeric characters, hyphens and spaces,
        and refuses anything else, so a value with a dot in it is rejected.
      - Left as the credential already has it when not given and O(key_id) is
        given, which is the only way to update a credential without naming it.
    type: str
    version_added: 0.1.0
  expiry_seconds:
    description:
      - How long an auth key stays valid, counted from the moment it is created.
      - Fixed at creation. The API refuses to update an auth key at all, so a
        different value on an existing key is a failure rather than a change.
      - Left to the API, which grants 90 days, when not given.
    type: int
    version_added: 0.1.0
  capabilities:
    description:
      - What an auth key may do, in the API's own shape.
      - Left as the key already has it when not given. The API stores all three
        flags whether or not they were sent, so an omitted one is compared as
        false, which is what the API grants for it.
    type: dict
    version_added: 0.1.0
    suboptions:
      devices:
        description: What the key may do with devices.
        type: dict
        required: true
        version_added: 0.1.0
        suboptions:
          create:
            description: What the key may do when registering a device.
            type: dict
            required: true
            version_added: 0.1.0
            suboptions:
              reusable:
                description:
                  - Whether the key may register more than one device.
                type: bool
                version_added: 0.1.0
              ephemeral:
                description:
                  - Whether a device registered with the key removes itself when
                    it disconnects for good.
                type: bool
                version_added: 0.1.0
              preauthorized:
                description:
                  - Whether a device registered with the key joins without
                    waiting for an administrator to approve it.
                type: bool
                version_added: 0.1.0
              tags:
                description:
                  - The tags applied to a device registered with the key.
                  - Required for an auth key created with an OAuth client or a
                    federated identity, because such a key belongs to the tailnet
                    rather than to a user, and refused with
                    C(tailnet-owned auth key must have tags set) without them.
                    Optional for an auth key created with an API access token.
                  - A tag exists only where the policy file's C(tagOwners) grants
                    it, and the API refuses a key naming a tag the tailnet does
                    not own.
                type: list
                elements: str
                version_added: 0.1.0
  scopes:
    description:
      - The OAuth scopes granted to a client or a federated identity.
      - The order carries no meaning and the comparison ignores it.
    type: list
    elements: str
    version_added: 0.1.0
  tags:
    description:
      - The tags a client or a federated identity may put on the auth keys it
        creates, which must be these tags or tags owned by them.
      - Required for a client whose scopes include C(devices:core) or
        C(auth_keys), and refused without them.
    type: list
    elements: str
    version_added: 0.1.0
  issuer:
    description:
      - The issuer of the OIDC identity token a federated identity is exchanged
        from, which must be a publicly reachable https URL.
    type: str
    version_added: 0.1.0
  subject:
    description:
      - The pattern matched against the C(sub) claim of the identity token, where
        an asterisk matches any character.
    type: str
    version_added: 0.1.0
  audience:
    description:
      - The value matched against the C(aud) claim of the identity token.
      - The API generates a secure one at creation, so this is only worth setting
        when the identity provider needs a particular format.
    type: str
    version_added: 0.1.0
  custom_claim_rules:
    description:
      - A map from a claim name to the pattern matched against that claim of the
        identity token, where an asterisk matches any character.
    type: dict
    version_added: 0.1.0
seealso:
  - module: abn.tailscale.tailscale_policy
  - name: OAuth clients, their scopes, and the tags they may carry
    link: https://tailscale.com/kb/1215/oauth-clients
    description: >-
      What Tailscale documents about the kind of credential this module mints
      when ``key_type`` is ``client``.
"""

EXAMPLES = r"""
- name: Mint an auth key that registers one ephemeral device under a tag
  abn.tailscale.tailscale_auth_key:
    api_token: "{{ tailscale_api_token }}"
    key_type: auth
    description: build runners
    expiry_seconds: 86400
    capabilities:
      devices:
        create:
          reusable: false
          ephemeral: true
          preauthorized: true
          tags:
            - tag:ci
  register: auth_key
  no_log: false

- name: Hand the key to something that joins a device with it
  # The secret exists only in the result of the run that minted it, so a
  # credential already in place reports none and a later run cannot recover it.
  ansible.builtin.debug:
    msg: "{{ auth_key.secret }}"

- name: Create an OAuth client the collection itself could authenticate with
  abn.tailscale.tailscale_auth_key:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    key_type: client
    description: read only reporter
    scopes:
      - devices:core:read
      - dns:read
  register: client
  no_log: false

- name: Narrow the scopes of that client
  abn.tailscale.tailscale_auth_key:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    key_type: client
    description: read only reporter
    scopes:
      - dns:read

- name: Create a federated identity for an external identity provider
  abn.tailscale.tailscale_auth_key:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    key_type: federated
    description: partner identity
    issuer: https://login.example.com
    subject: team-42-*
    scopes:
      - devices:core:read
    custom_claim_rules:
      team: "42"

- name: Remove a key the tailnet should stop accepting
  abn.tailscale.tailscale_auth_key:
    api_token: "{{ tailscale_api_token }}"
    key_type: auth
    description: build runners
    state: absent

- name: Report whether a key would be minted, without minting it
  abn.tailscale.tailscale_auth_key:
    api_token: "{{ tailscale_api_token }}"
    key_type: auth
    description: build runners
    capabilities:
      devices:
        create:
          ephemeral: true
          tags:
            - tag:ci
  check_mode: true
"""

RETURN = r"""
key:
  description:
    - The credential the tailnet holds after the run, in the API's own camel case
      spelling and with the secret removed, empty when it holds no such
      credential.
  returned: always
  type: dict
  sample:
    id: kABCD123456CNTRL
    keyType: auth
    description: build runners
    expirySeconds: 86400
    expires: '2026-09-28T10:45:12Z'
    capabilities:
      devices:
        create:
          reusable: false
          ephemeral: true
          preauthorized: true
          tags:
            - tag:ci
removed_key:
  description:
    - The credential this run removed, in the same shape as RV(key), empty when
      it removed none.
  returned: always
  type: dict
  sample:
    id: kABCD123456CNTRL
    keyType: auth
    description: build runners
secret:
  description:
    - >-
      The key material of the credential, which the API returns only in the
      response that creates it.
    - >-
      Empty on every run but the one that created the credential, and empty under
      check mode, which mints nothing. A federated identity has no key material
      and never reports one.
    - >-
      Read it from a C(register) on the run that reported a change, and set
      C(no_log) to false on that task, because the value is a working
      credential.
  returned: when created
  type: str
  sample: tskey-auth-kABCD123456CNTRL-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
changed_fields:
  description:
    - The API field names this run set, empty when it set none. On a removal it
      names nothing, because a removal replaces the credential rather than
      changing a field of it.
  returned: always
  type: list
  elements: str
  sample:
    - scopes
diff:
  description:
    - The credential as the tailnet held it and the one it was reconciled to,
      rendered by C(--diff). It never carries key material, because the secret
      exists only in the response that created the credential and C(after) is
      what a check run would have written.
  returned: always
  type: dict
  contains:
    before:
      description: The credential as the tailnet held it, empty when it held none.
      returned: always
      type: dict
    after:
      description:
        - The credential reconciled to, or what a check run would have written,
          empty when the run removed the credential.
      returned: always
      type: dict
"""

from typing import Any
from typing import NoReturn

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleNotFound,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import (
    connection_arguments,
)

#: The API fields each kind of credential carries. A field belonging to another
#: kind is refused by the API with a message naming the wrong kind rather than
#: ignored, so the module refuses it first and says which kind does take it.
_OWNED: dict[str, tuple[str, ...]] = {
    "auth": ("expirySeconds", "capabilities"),
    "client": ("scopes", "tags"),
    "federated": ("scopes", "tags", "issuer", "subject", "audience", "customClaimRules"),
}

#: Module option to API field. The API is Go, and Go marshals to camel case.
_FIELDS: dict[str, str] = {
    "expiry_seconds": "expirySeconds",
    "scopes": "scopes",
    "tags": "tags",
    "issuer": "issuer",
    "subject": "subject",
    "audience": "audience",
    "custom_claim_rules": "customClaimRules",
}

#: Fields whose order carries no meaning, so the comparison sorts them and the
#: module never reports a change because a task listed them differently.
_UNORDERED = frozenset({"scopes", "tags"})

#: The capability flags, which the API stores and returns whether or not they
#: were sent, false included.
_FLAGS = ("reusable", "ephemeral", "preauthorized")

#: What an absent field means for the comparison. Measured: the API drops an
#: absent tag list and stores an absent claim rule map as an empty one, so those
#: are read as empty rather than as a difference on every run.
_ABSENT: dict[str, Any] = {
    "scopes": [],
    "tags": [],
    "customClaimRules": {},
}

ARGUMENT_SPEC = connection_arguments(
    state={"type": "str", "choices": ["present", "absent"], "default": "present"},
    # Ansible's own heuristic treats any option whose name carries "key" as a
    # secret and would censor these in every log line. Neither is key material:
    # one names a kind and the other names a resource the API already issues.
    key_type={
        "type": "str",
        "choices": ["auth", "client", "federated"],
        "default": "auth",
        "no_log": False,
    },
    key_id={"type": "str", "no_log": False},
    description={"type": "str"},
    expiry_seconds={"type": "int"},
    capabilities={
        "type": "dict",
        "options": {
            "devices": {
                "type": "dict",
                "required": True,
                "options": {
                    "create": {
                        "type": "dict",
                        "required": True,
                        "options": {
                            "reusable": {"type": "bool"},
                            "ephemeral": {"type": "bool"},
                            "preauthorized": {"type": "bool"},
                            "tags": {"type": "list", "elements": "str"},
                        },
                    }
                },
            }
        },
    },
    scopes={"type": "list", "elements": "str"},
    tags={"type": "list", "elements": "str"},
    issuer={"type": "str"},
    subject={"type": "str"},
    audience={"type": "str"},
    custom_claim_rules={"type": "dict"},
)


def named_flags(capabilities: dict) -> dict:
    """The flags the task set, and only those.

    An unset suboption arrives as None rather than absent, so `is not None` is
    what separates a flag the task wrote from one it said nothing about.
    """
    create = (capabilities.get("devices") or {}).get("create") or {}
    block: dict[str, Any] = {}
    for flag in _FLAGS:
        if create.get(flag) is not None:
            block[flag] = bool(create[flag])
    if create.get("tags") is not None:
        block["tags"] = list(create["tags"] or [])
    return block


def complete_flags(flags: dict) -> dict:
    """A block with every flag resolved, for a credential that does not exist yet.

    A create has no block to inherit from, so a flag the task left out takes the
    false the API grants for it. Making it explicit also keeps the request from
    being a partial description of the key it is minting.
    """
    resolved: dict[str, Any] = {flag: bool(flags.get(flag, False)) for flag in _FLAGS}
    resolved["tags"] = list(flags.get("tags") or [])
    return {"devices": {"create": resolved}}


def merged_flags(current: Any, asked: dict) -> dict:
    """The flags the task set over the ones the credential already has.

    The same rule as every other option: a flag the task left out is left as the
    tailnet has it. Reading it the other way would make a task that names one flag
    a request to turn the other two off, and an auth key cannot be updated, so the
    task would fail rather than converge.
    """
    stored = ((current or {}).get("devices") or {}).get("create") or {}
    resolved = complete_flags(stored)["devices"]["create"]
    resolved.update(asked)
    return {"devices": {"create": resolved}}


def asked_for(params: dict) -> dict[str, Any]:
    """The API fields the options that were given ask for, and only those.

    A field the task never mentioned is not here, which is what keeps a change
    this module cannot make out of the comparison.
    """
    body: dict[str, Any] = {}
    for option, field in _FIELDS.items():
        value = params.get(option)
        if value is not None:
            body[field] = value
    if params.get("capabilities") is not None:
        body["capabilities"] = named_flags(params["capabilities"])
    return body


def canonical(field: str, value: Any) -> Any:
    """One value in the form the comparison makes, whatever the API stored."""
    if field in _UNORDERED:
        return sorted(value or [])
    if field == "capabilities":
        return complete_flags(named_flags(value or {}))
    if field == "customClaimRules":
        return dict(value or {})
    return value


def differing(key: dict, desired: dict) -> dict[str, Any]:
    """The fields of `desired` the credential does not already hold.

    Scoped to the fields `desired` carries, which are the ones the task named plus
    the ones an update has to repeat because the endpoint replaces the credential.
    Comparing whole credentials would let the id, the creation time and the expiry
    the API computes report a change on every run, and none of them is something a
    playbook can set.
    """
    changed: dict[str, Any] = {}
    for field, wanted in desired.items():
        current = key.get(field)
        if current is None:
            current = _ABSENT.get(field)
        if canonical(field, current) == canonical(field, wanted):
            continue
        changed[field] = wanted
    return changed


def desired(params: dict, key: dict) -> dict[str, Any]:
    """The document the credential would hold, which is also the update request.

    `keys_set` replaces the whole document rather than merging into it. Measured:
    setting only the scopes of a client dropped its description and its tags
    without complaint. So every field the task did not name is carried over from
    the credential the tailnet already has, and the result is what an update
    sends.
    """
    body: dict[str, Any] = {"keyType": params["key_type"]}
    if params.get("description") is not None:
        body["description"] = params["description"]
    asked = asked_for(params)
    for field in _OWNED[params["key_type"]]:
        if field == "capabilities" and field in asked:
            body[field] = merged_flags(key.get("capabilities"), asked[field])
        elif field in asked:
            body[field] = asked[field]
        elif key.get(field) is not None:
            body[field] = key[field]
    return body


def create_body(params: dict) -> dict[str, Any]:
    """The document that mints a credential.

    A capability block is always sent for an auth key. Measured: a body carrying
    only `keyType` and `description` comes back 400 with C(exactly one capability
    scope must be populated), which reads as a permissions problem and is not one.
    """
    body: dict[str, Any] = {"keyType": params["key_type"]}
    if params.get("description") is not None:
        body["description"] = params["description"]
    body.update(asked_for(params))
    if params["key_type"] == "auth":
        asked = named_flags(params.get("capabilities") or {})
        body["capabilities"] = complete_flags(asked)
    return body


def _refuse_foreign_options(module: AnsibleModule, params: dict) -> None:
    """Refuse an option that belongs to another kind of credential."""
    mine = _OWNED[params["key_type"]]
    foreign = [
        option
        for option, field in _FIELDS.items()
        if field not in mine and params.get(option) is not None
    ]
    if params.get("capabilities") is not None and "capabilities" not in mine:
        foreign.append("capabilities")
    if not foreign:
        return
    owners = []
    for option in sorted(foreign):
        field = _FIELDS.get(option, option)
        kinds = [kind for kind, fields in _OWNED.items() if field in fields]
        owners.append(
            f"`{option}`, which a key of type {' or '.join(f'`{k}`' for k in kinds)} takes"
        )
    module.fail_json(
        msg=(
            f"The task manages a key of type `{params['key_type']}` and also set "
            + ", ".join(owners)
            + ". Each kind of credential has its own request shape and the API refuses a "
            "field that does not apply to it, so the field is refused here rather than "
            "sent to be rejected with a message about the wrong kind."
        )
    )


def _refuse_incomplete(module: AnsibleModule, params: dict) -> None:
    """Refuse a create the API would refuse, before sending it."""
    kind = params["key_type"]
    missing: list[str] = []
    if kind in ("client", "federated") and not params.get("scopes"):
        missing.append("`scopes`, of which an OAuth client needs at least one")
    if kind == "federated":
        for option in ("issuer", "subject"):
            if not params.get(option):
                missing.append(f"`{option}`")
    if kind == "auth" and not params.get("api_token"):
        # A key minted with an OAuth client or a federated identity belongs to the
        # tailnet rather than to a user, and the API refuses one with no tags. A
        # key minted with an API access token belongs to that user and may omit
        # them, so the requirement is decided by the credential in use rather than
        # asserted for every auth key.
        tags = ((params.get("capabilities") or {}).get("devices") or {}).get("create") or {}
        if not tags.get("tags"):
            missing.append(
                "at least one tag under `capabilities.devices.create.tags`, which a "
                "tailnet-owned auth key must carry and this credential's is"
            )
    if not missing:
        return
    module.fail_json(
        msg=(
            f"The task cannot mint a key of type `{kind}` because it left out "
            + ", ".join(missing)
            + ". Nothing was written."
        )
    )


def _document(module: AnsibleModule, value: Any, what: str) -> dict:
    if not isinstance(value, dict):
        module.fail_json(
            msg=(
                f"The {what} read back was not a JSON object, so what the tailnet holds "
                "could not be read and nothing was written. A proxy answering 200 is the "
                "ordinary way to see this."
            )
        )
    return value


def _find(module: AnsibleModule, api: Any, params: dict) -> dict | None:
    """The credential this task names, or None when the tailnet holds none.

    A key the API no longer knows is None rather than a failure, because both
    states of the task want that: `absent` has nothing to remove and `present`
    has something to mint. It applies to the lookup by id only, since the list
    cannot return a credential that is not in it.
    """
    key_id = params.get("key_id")
    if key_id:
        try:
            return _document(
                module,
                api.call("keys_get", "GET", params={"keyId": key_id}).body,
                "key",
            )
        except TailscaleNotFound:
            return None

    body = _document(module, api.call("keys_list", "GET").body, "key list")
    if not isinstance(body.get("keys"), list):
        module.fail_json(
            msg=(
                "The key list carried no list of keys, so whether the tailnet already "
                "holds this credential could not be read. Refused rather than assumed "
                "empty, because assuming empty mints a second credential under the same "
                "description. Nothing was written."
            )
        )
    matches = [
        key
        for key in body["keys"]
        if isinstance(key, dict) and key.get("description") == params["description"]
    ]
    if len(matches) > 1:
        ids = ", ".join(str(key.get("id")) for key in matches)
        module.fail_json(
            msg=(
                f"The tailnet holds {len(matches)} credentials described "
                f"`{params['description']}` ({ids}), so this task does not name one of "
                "them in particular. The API accepts a duplicate description, and this "
                "module will not pick between them: give the one to act on in `key_id`, "
                "or make the descriptions unique. Nothing was written."
            )
        )
    if not matches:
        return None
    # The list is a projection of what the credential in use may see, and the get
    # is the resource, so the document acted on is the one the get returns.
    return _document(
        module,
        api.call("keys_get", "GET", params={"keyId": str(matches[0].get("id") or "")}).body,
        "key",
    )


def _check_kind(module: AnsibleModule, params: dict, key: dict) -> None:
    found = key.get("keyType")
    if found != params["key_type"]:
        module.fail_json(
            msg=(
                f"The task manages a key of type `{params['key_type']}` and the "
                f"credential it found is a key of type `{found}`. A description is not "
                "unique across kinds, so acting on it would change a credential of "
                "another kind. Give the one to act on in `key_id`, or set `key_type` to "
                f"`{found}`. Nothing was written."
            )
        )


def _report(module: AnsibleModule, key: dict) -> NoReturn:
    module.exit_json(
        changed=False,
        key=key,
        secret=None,
        removed_key=None,
        changed_fields=[],
        diff={"before": key, "after": key},
    )


def _create(
    module: AnsibleModule, api: Any, params: dict, before: dict | None, removed: dict | None = None
) -> NoReturn:
    body = create_body(params)
    if module.check_mode:
        module.exit_json(
            changed=True,
            # The document as it would be sent, because a check run mints nothing
            # and so has no server's answer to report.
            key=body,
            secret=None,
            removed_key=removed,
            changed_fields=sorted(body),
            diff={"before": before, "after": body},
        )
    created = _document(module, api.call("keys_create", "POST", body=body).body, "created key")
    module.exit_json(
        changed=True,
        # The secret is lifted out of the document and never rendered inside it,
        # so the diff, and anything else that prints the document, cannot carry it.
        key={field: value for field, value in created.items() if field != "key"},
        secret=created.get("key") or None,
        removed_key=removed,
        changed_fields=sorted(body),
        diff={"before": before, "after": body},
    )


def _present(module: AnsibleModule, api: Any, params: dict) -> NoReturn:
    key = _find(module, api, params)
    if key is None:
        _refuse_incomplete(module, params)
        _create(module, api, params, before=None)
    if key.get("invalid"):
        # A revoked credential is still described by the API and cannot authenticate
        # anything, so a task asking for it wants a working one. That converges only
        # when the credential is named by description: the replacement carries the
        # description, the dead one is removed, and the next run finds one valid
        # match. A task naming the dead `key_id` cannot converge, because the
        # replacement has a different id and the task would mint on every run.
        if params.get("key_id"):
            module.fail_json(
                msg=(
                    "The credential this task names by `key_id` is revoked or expired, and "
                    "a replacement is a new credential with a new id. A task naming this id "
                    "would therefore mint another credential on every run, which is not a "
                    "state it can reach. Name the credential by `description` instead, so "
                    "the dead one is replaced and removed, or drop this task. Nothing was "
                    "written."
                )
            )
        _refuse_incomplete(module, params)
        if not module.check_mode:
            api.call("keys_delete", "DELETE", params={"keyId": key["id"]})
        _create(module, api, params, before=key, removed=key)
    _check_kind(module, params, key)
    document = desired(params, key)
    wanted = differing(key, document)
    if not wanted:
        _report(module, key)
    if params["key_type"] == "auth":
        module.fail_json(
            msg=(
                "The auth key this task names already exists and differs from it in "
                + ", ".join(f"`{field}`" for field in sorted(wanted))
                + ". The API refuses to update a key of type `auth`, so the difference "
                "cannot be reconciled: a key's lifetime and capabilities are fixed when "
                "it is minted. Remove it with `state: absent` and let the next run mint "
                "another, which also leaves the devices that registered with it holding a "
                "key that no longer works. Nothing was written."
            )
        )
    before = key
    if not module.check_mode:
        after = api.call("keys_set", "PUT", params={"keyId": key["id"]}, body=document).body
        key = after if isinstance(after, dict) else document
    module.exit_json(
        changed=True,
        key=key,
        secret=None,
        removed_key=None,
        changed_fields=sorted(wanted),
        diff={"before": before, "after": document},
    )


def _absent(module: AnsibleModule, api: Any, params: dict) -> NoReturn:
    key = _find(module, api, params)
    if key is None or key.get("invalid"):
        # An expired or revoked credential cannot authenticate anything, so the
        # state this task asks for already holds.
        module.exit_json(
            changed=False,
            key=None,
            secret=None,
            removed_key=None,
            changed_fields=[],
            diff={"before": None, "after": None},
        )
    if not module.check_mode:
        api.call("keys_delete", "DELETE", params={"keyId": key["id"]})
    module.exit_json(
        changed=True,
        key=None,
        secret=None,
        removed_key=key,
        changed_fields=[],
        diff={"before": key, "after": None},
    )


def run(module: AnsibleModule) -> None:
    try:
        params = module.params
        _refuse_foreign_options(module, params)
        api = build_client(params)
        if params["state"] == "absent":
            _absent(module, api, params)
        _present(module, api, params)
    except CredentialError as error:
        module.fail_json(msg=str(error))
    except TailscaleError as error:
        module.fail_json(msg=str(error))


def main() -> None:
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        required_together=[("oauth_client_id", "oauth_client_secret")],
        mutually_exclusive=[
            ("api_token", "oauth_client_id"),
            ("api_token", "oauth_client_secret"),
        ],
        required_one_of=[("key_id", "description")],
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
