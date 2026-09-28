#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_webhook
short_description: Manage the webhook endpoints of a tailnet
version_added: 1.0.0
description:
  - Reconciles the webhook endpoints Tailscale posts tailnet events to. An
    endpoint is addressed by the URL events are sent to, which is the natural key
    and the one the API treats as unique. A second endpoint on the same URL is
    refused by the server.
  - The endpoint URL and the provider type are fixed when the endpoint is
    created. The update operation takes the subscription list and nothing else,
    so a task that declares a different provider type on an endpoint that already
    exists is refused rather than quietly ignored. Changing either means removing
    the endpoint and creating another, which issues a new signing secret.
  - The subscription list is replaced by an update, not merged into the list the
    endpoint already holds. It is compared as a set, because the server returns
    the events in an order of its own with duplicates removed, so the order a task
    declares is not part of the state.
  - An empty subscription list cannot be written. The API refuses to clear the
    list and stores an absent one on a create, and an endpoint subscribed to
    nothing never receives an event, so the module declines one.
  - The test and rotate operations are deliberately not exposed. One queues a
    real event to the endpoint and changes nothing the API reports; the other
    issues a signing secret that is returned once and cannot be read again.
    Neither could reach C(changed=false) on a second run.
  - Option names are snake case, as Ansible requires. The API spells the same
    fields in camel case, and the mapping happens here.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.check_mode_diff_mode
  - abn.tailscale._attributes.connection_delegation
options:
  endpoint_url:
    description:
      - The URL Tailscale sends events to with a POST request.
      - This is the selector. The module reads the tailnet's endpoints and finds
        the one holding this URL, so O(state=absent) removes the endpoint at this
        URL and a URL the tailnet does not hold is created.
      - The API accepts only an absolute HTTPS URL. Anything else is refused by
        the module before a request is made.
    type: str
    required: true
    version_added: 1.0.0
  state:
    description:
      - Whether the endpoint should exist.
      - C(absent) removes it. The removal also invalidates the signing secret and
        cannot be undone, because a new endpoint on the same URL is a different
        endpoint with a new id.
    type: str
    choices:
      - present
      - absent
    default: present
    version_added: 1.0.0
  provider_type:
    description:
      - The format outgoing events are sent in, for a destination that expects
        one. One of C(slack), C(mattermost), C(googlechat) or C(discord), or an
        empty string for the generic JSON body.
      - Fixed when the endpoint is created, and not part of what an update can
        change. Omitted leaves the provider of an existing endpoint alone, and a
        value that differs from the one an existing endpoint holds is refused.
    type: str
    version_added: 1.0.0
  subscriptions:
    description:
      - The events that trigger a POST to O(endpoint_url). Required when
        O(state=present), and at least one event is required.
      - The order is not part of the state. The server stores the list in its own
        order and removes duplicates, so the same set in another order is not a
        change.
    type: list
    elements: str
    choices:
      - nodeCreated
      - nodeNeedsApproval
      - nodeApproved
      - nodeKeyExpiringInOneDay
      - nodeKeyExpired
      - nodeDeleted
      - nodeSigned
      - nodeNeedsSignature
      - policyUpdate
      - userCreated
      - userNeedsApproval
      - userSuspended
      - userRestored
      - userDeleted
      - userApproved
      - userRoleUpdated
      - subnetIPForwardingNotEnabled
      - exitNodeIPForwardingNotEnabled
    version_added: 1.0.0
"""

EXAMPLES = r"""
- name: Send device and policy events to a chat channel
  abn.tailscale.tailscale_webhook:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    endpoint_url: https://hooks.example.com/tailscale/events
    provider_type: slack
    subscriptions:
      - nodeCreated
      - nodeNeedsApproval
      - policyUpdate

- name: Keep the endpoint and change only what it subscribes to
  abn.tailscale.tailscale_webhook:
    api_token: "{{ tailscale_api_token }}"
    endpoint_url: https://hooks.example.com/tailscale/events
    subscriptions:
      - nodeCreated
      - nodeNeedsApproval

- name: Read the signing secret on the run that creates the endpoint
  abn.tailscale.tailscale_webhook:
    api_token: "{{ tailscale_api_token }}"
    endpoint_url: https://hooks.example.com/tailscale/events
    subscriptions:
      - nodeCreated
  register: webhook
  no_log: false

- name: Take the endpoint out of the tailnet
  abn.tailscale.tailscale_webhook:
    api_token: "{{ tailscale_api_token }}"
    endpoint_url: https://hooks.example.com/tailscale/events
    state: absent
"""

RETURN = r"""
webhook:
  description:
    - The endpoint the tailnet holds after the run, in the API's own camel case
      spelling, reduced to the fields this module manages.
    - The id is the server's, and is returned so a task can name the endpoint in
      the admin console. C(endpointId) is absent on a check run that would create
      the endpoint, because only the server assigns it.
    - Empty when O(state=absent) or when the tailnet holds no such endpoint.
  returned: always
  type: dict
  sample:
    endpointId: w37DEvfyhv11CNTRL
    endpointUrl: https://hooks.example.com/tailscale/events
    providerType: slack
    subscriptions:
      - nodeCreated
      - nodeNeedsApproval
      - policyUpdate
secret:
  description:
    - The signing secret the API returns only in the response that creates the
      endpoint, used to verify the C(Tailscale-Webhook-Signature) header on the
      requests the endpoint receives.
    - Empty on every run but the one that created the endpoint, and empty under
      check mode, which creates nothing.
    - Read it from a C(register) on the run that reported a change, and set
      C(no_log) to false on that task, because a signing secret is a credential.
  returned: when created
  type: str
  sample: whsec-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
diff:
  description:
    - The endpoint as the tailnet held it and the endpoint it was reconciled to,
      rendered by C(--diff). Both sides are equal when nothing would change,
      C(before) is absent when the endpoint did not exist, and C(after) is absent
      when it was removed.
    - The signing secret is not part of either side, because it exists only in the
      response that created the endpoint and C(after) is what a check run would
      have written.
  returned: always
  type: dict
  contains:
    before:
      description: The endpoint as the tailnet held it.
      returned: always
      type: dict
    after:
      description: The endpoint reconciled to, or what a check run would have
        written.
      returned: always
      type: dict
"""

from urllib.parse import urlsplit

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import (
    connection_arguments,
)

#: The events a webhook can subscribe to, from the API description's enum. The
#: server refuses a name outside it with `invalid webhook event type`, so the list
#: is a snapshot of what the description declares rather than something the
#: module decided.
_EVENTS = (
    "nodeCreated",
    "nodeNeedsApproval",
    "nodeApproved",
    "nodeKeyExpiringInOneDay",
    "nodeKeyExpired",
    "nodeDeleted",
    "nodeSigned",
    "nodeNeedsSignature",
    "policyUpdate",
    "userCreated",
    "userNeedsApproval",
    "userSuspended",
    "userRestored",
    "userDeleted",
    "userApproved",
    "userRoleUpdated",
    "subnetIPForwardingNotEnabled",
    "exitNodeIPForwardingNotEnabled",
)

#: The provider types the server accepts, measured against the real API. The
#: description's enum matches, and an empty string is accepted beside it for a
#: destination that wants the generic body, which is what a create without the
#: field stores. A name outside this set is answered 400 `unsupported provider`.
_PROVIDER_TYPES = frozenset({"", "slack", "mattermost", "googlechat", "discord"})

#: The fields this module returns from a stored endpoint. A whitelist, so a field
#: Tailscale adds later is not something this module has promised, and so the
#: signing secret, which arrives only in the create response, is lifted out
#: rather than rendered inside the document.
_RETURNED = ("endpointId", "endpointUrl", "providerType", "subscriptions")

#: What the API says when a task would leave an endpoint subscribed to nothing.
_EMPTY_ADVICE = (
    "the API refuses an update that clears the subscription list, and an endpoint "
    "subscribed to nothing never receives an event"
)

ARGUMENT_SPEC = connection_arguments(
    endpoint_url={"type": "str", "required": True},
    state={"type": "str", "choices": ["present", "absent"], "default": "present"},
    provider_type={"type": "str"},
    subscriptions={"type": "list", "elements": "str", "choices": list(_EVENTS)},
)


def task_refusal(params: dict) -> str | None:
    """Why this task cannot be sent at all, before anything has been read.

    Each of these is the task's own shape rather than the tailnet's, so refusing
    them here costs no request, and a check run reports them the same as a run
    that would write. The API answers a URL that is empty, unparseable or not
    HTTPS with a 400 that names no option, and a provider it does not know with
    `unsupported provider`, so the module names the fix instead.
    """
    url = params["endpoint_url"]
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc:
        return (
            f"{url!r} is not an absolute HTTPS URL. The API requires the endpoint URL to use "
            "HTTPS, and treats an empty or unparseable one as an error rather than as absent."
        )

    provider = params.get("provider_type")
    if provider is not None and provider not in _PROVIDER_TYPES:
        accepted = ", ".join(sorted(name for name in _PROVIDER_TYPES if name))
        return (
            f"{provider!r} is not a provider the API accepts. Give one of {accepted}, or an "
            "empty string for the generic JSON body."
        )

    if params["state"] == "present" and not params["subscriptions"]:
        return f"subscriptions is empty: {_EMPTY_ADVICE}."

    return None


def _projection(document: dict) -> dict:
    """The fields this module returns from a stored endpoint."""
    return {field: document[field] for field in _RETURNED if field in document}


def _read_endpoint(module: AnsibleModule, api: Api) -> dict | None:
    """The endpoint the tailnet holds at this URL, or ``None`` when it holds none.

    The list is the only way to reach an endpoint by its URL, because the id the
    per-endpoint operations take is assigned by the server. The API answers an
    empty tailnet with an absent ``webhooks`` key rather than an empty list, and
    a body that is not an endpoint list is refused rather than read as an empty
    one: a proxy answering 200 with an error page would otherwise create an
    endpoint over the top of whatever it should have been.
    """
    url = module.params["endpoint_url"]
    body = api.call("webhook_list", "GET").body
    if not isinstance(body, dict):
        module.fail_json(
            msg="The webhook endpoints read back were not a JSON object, so what the tailnet "
            "already holds could not be compared against what the task asks for. Nothing was "
            "written."
        )
    endpoints = body.get("webhooks") or []
    if not isinstance(endpoints, list):
        module.fail_json(
            msg="The webhook endpoints read back were not a list, so what the tailnet already "
            "holds could not be compared against what the task asks for. Nothing was written."
        )
    matches = [entry for entry in endpoints if entry.get("endpointUrl") == url]
    if len(matches) > 1:
        module.fail_json(
            msg=f"The tailnet holds {len(matches)} webhook endpoints at {url!r}, and this module "
            "will not choose between them. The API refuses a second endpoint on a URL, so this "
            "is a state the module cannot reconcile; remove the duplicates by hand."
        )
    return matches[0] if matches else None


def _manage(module: AnsibleModule, api: Api) -> None:
    """Reconcile one endpoint: create it, update its subscriptions, or remove it."""
    url = module.params["endpoint_url"]
    reason = task_refusal(module.params)
    if reason is not None:
        module.fail_json(msg=reason)

    current = _read_endpoint(module, api)

    if module.params["state"] == "absent":
        if current is None:
            module.exit_json(
                changed=False,
                webhook={},
                secret=None,
                diff={"before": None, "after": None},
            )
        if not module.check_mode:
            api.call(
                "webhook_delete",
                "DELETE",
                params={"endpointId": current["endpointId"]},
            )
        module.exit_json(
            changed=True,
            webhook={},
            secret=None,
            diff={"before": _projection(current), "after": None},
        )

    # Required when present, and the empty list is refused above, so the sorted
    # set is never empty here. The server stores this list in its own order and
    # removes duplicates, which is why the comparison below is by set.
    wanted = sorted(set(module.params["subscriptions"]))

    if current is None:
        body: dict = {"endpointUrl": url, "subscriptions": wanted}
        provider = module.params.get("provider_type")
        if provider is not None:
            body["providerType"] = provider
        if module.check_mode:
            module.exit_json(
                changed=True,
                webhook=_projection(body),
                secret=None,
                diff={"before": None, "after": _projection(body)},
            )
        written = api.call("webhook_create", "POST", body=body)
        stored = dict(written.body) if isinstance(written.body, dict) else body
        # Lifted out rather than returned inside the document, so a later read,
        # which does not carry it, can be compared against this one.
        secret = stored.pop("secret", None)
        module.exit_json(
            changed=True,
            webhook=_projection(stored),
            secret=secret,
            diff={"before": None, "after": _projection(stored)},
        )

    provider = module.params.get("provider_type")
    if provider is not None and provider != (current.get("providerType") or ""):
        module.fail_json(
            msg=f"The endpoint at {url!r} has provider type "
            f"{(current.get('providerType') or '')!r}, and the task declares {provider!r}. The "
            "API fixes the provider type when the endpoint is created and has no update for it, "
            "so the two cannot be reconciled. Remove the endpoint and create another to change "
            "it, accepting that the signing secret changes with it."
        )

    stored_subs = set(current.get("subscriptions") or [])
    if stored_subs == set(wanted):
        module.exit_json(
            changed=False,
            webhook=_projection(current),
            secret=None,
            diff={"before": _projection(current), "after": _projection(current)},
        )

    reconciled = {**current, "subscriptions": wanted}
    if module.check_mode:
        module.exit_json(
            changed=True,
            webhook=_projection(reconciled),
            secret=None,
            diff={"before": _projection(current), "after": _projection(reconciled)},
        )
    written = api.call(
        "webhook_update",
        "PATCH",
        params={"endpointId": current["endpointId"]},
        body={"subscriptions": wanted},
    )
    stored = dict(written.body) if isinstance(written.body, dict) else reconciled
    stored.pop("secret", None)
    module.exit_json(
        changed=True,
        webhook=_projection(stored),
        secret=None,
        diff={"before": _projection(current), "after": _projection(stored)},
    )


def run(module: AnsibleModule) -> None:
    try:
        api = build_client(module.params)
        _manage(module, api)
    except CredentialError as error:
        module.fail_json(msg=str(error))
    except TailscaleError as error:
        module.fail_json(msg=str(error))


def main() -> None:
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        required_together=[("oauth_client_id", "oauth_client_secret")],
        required_if=[("state", "present", ["subscriptions"])],
        mutually_exclusive=[
            ("api_token", "oauth_client_id"),
            ("api_token", "oauth_client_secret"),
        ],
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
