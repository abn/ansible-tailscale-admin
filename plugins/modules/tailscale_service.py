#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_service
short_description: Manage the Services published into a tailnet
version_added: 1.0.0
description:
  - Reconciles a Tailscale Service, a named resource published into the tailnet
    with its own MagicDNS name, its own addresses and its own access control,
    fronting one or more back-end hosts.
  - A Service is created by a PUT to a name that does not exist yet, so the
    module reads the Service first and writes only when what the task asked for
    differs from what the tailnet holds.
  - The PUT replaces the whole Service, so a field the task does not mention is
    sent back as the value the Service already holds rather than as a default.
    Two fields are not optional on the wire whatever the task says, and are
    carried forward for that reason. The addresses are the server's to assign,
    and the ports are refused empty.
  - A Service that is removed takes its MagicDNS name with it, and there is no
    way back to the same addresses.
  - Only the options the task gives are compared. A field this module does not
    manage cannot make a run report a change.
  - A device approval is one of this module's flows rather than a module of its
    own, because a user reads C(Services) as the whole feature. A Service and an
    approval are still two resources, so a task gives the device options or the
    options that describe the Service and never both, and a Service declared
    together with the hosts it may run on is two tasks. See the examples.
  - Option names are snake case, as Ansible requires. The API spells the same
    fields in camel case, and the mapping happens here.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.check_mode_diff_mode
  - abn.tailscale._attributes.connection_delegation
options:
  name:
    description:
      - The name of the Service. The API requires it to start with C(svc:), and
        the rest is a DNS label of letters, digits and hyphens, neither starting
        nor ending with one.
      - This is the selector. A Service that does not exist yet is created under
        this name, and O(state=absent) removes the Service holding it.
    type: str
    required: true
    version_added: 1.0.0
  state:
    description:
      - Whether the Service should exist.
      - C(absent) removes it. The removal also releases the MagicDNS name it
        published, and the addresses go with it.
    type: str
    choices:
      - present
      - absent
    default: present
    version_added: 1.0.0
  display_name:
    description:
      - A human-readable label for the Service, shown in the admin console and to
        clients with access to it. At most 64 characters, which the API enforces.
      - Left as the Service holds it when not given. An empty string clears it.
    type: str
    version_added: 1.0.0
  comment:
    description:
      - A free-text note about the Service.
      - Left as the Service holds it when not given. An empty string clears it,
        and the API stores a cleared comment as an absent key, so an empty string
        and no comment are the same state and a task clearing the comment
        converges.
    type: str
    version_added: 1.0.0
  ports:
    description:
      - The C(protocol:port) pairs the Service exposes, such as C(tcp:443).
        C(tcp) is the only protocol the API supports.
      - The API refuses a Service with no ports at all, so this is never sent
        empty. A list that leaves ports out is sent back as the ports the
        Service already has, and declaring an empty list is refused with the
        advice to use C(do-not-validate) to stop the API validating them.
    type: list
    elements: str
    version_added: 1.0.0
  tags:
    description:
      - Tags attached to the Service. They are access control rather than
        metadata. A device can host the Service only if it carries one of them,
        so a tag widens who may serve the Service.
      - A tag exists only where the policy file's C(tagOwners) grants it, and the
        API refuses one that has no owner.
      - Left as the Service holds it when not given. An empty list clears them.
    type: list
    elements: str
    version_added: 1.0.0
  addrs:
    description:
      - The addresses the Service answers on, the IPv4 followed by the IPv6.
      - For a Service that does not exist yet, either nothing, to let the server
        choose, or a single IPv4 to assign. The IPv6 is always the server's to
        assign.
      - For a Service that exists, the IPv4 and the IPv6 it holds, because the
        API refuses an update that does not carry both.
      - An address this task did not declare is never compared, so an address
        the server assigned cannot make a run report a change.
    type: list
    elements: str
    version_added: 1.0.0
  device_id:
    description:
      - The device that hosts the Service, named by the id the API lists, which
        the admin console shows and M(abn.tailscale.tailscale_device) accepts as
        its own O(device_id).
      - Naming a device makes the task manage whether that device may host the
        Service rather than the Service itself, so a device option is refused
        alongside every option that describes the Service.
      - This, O(device_name) and O(address) are one choice with three spellings,
        and a task gives exactly one of them. This is the only one that costs no
        read, because it is already the value the approval endpoint is addressed
        with.
    type: str
    version_added: 1.0.0
  device_name:
    description:
      - The device that hosts the Service, named by the label part of its
        MagicDNS name, which is the name without the suffix the tailnet appends
        to it. A device the tailnet has renamed is found by the label it holds
        now.
      - This is the Tailscale node name rather than the machine's own hostname,
        and the two need not agree. M(abn.tailscale.tailscale_device_info) reads
        both names for every device, which is the quickest way to see the one a
        task should use.
      - The device list is read and the selector applied to it, so a name that
        matches no device, or more than one, is refused rather than guessed at.
      - Mutually exclusive with O(device_id) and O(address).
    type: str
    version_added: 1.0.0
  address:
    description:
      - The device that hosts the Service, named by a Tailscale IP it holds.
        Either address family is accepted, and a device holding several matches
        on any one of them.
      - Mutually exclusive with O(device_id) and O(device_name).
    type: str
    version_added: 1.0.0
  approved:
    description:
      - Whether the device a device option named is approved to host the Service.
      - Required with O(device_id), O(device_name) or O(address), and the whole
        of what a device approval means. Unlike the rest of a Service, the API
        stores a false here as a real false, so a task that revokes an approval
        converges.
    type: bool
    version_added: 1.0.0
"""

EXAMPLES = r"""
- name: Publish an internal service, tagged for the devices that may host it
  abn.tailscale.tailscale_service:
    api_token: "{{ tailscale_api_token }}"
    name: svc:web
    display_name: Web front end
    comment: Fronted by the nginx containers
    ports:
      - tcp:443
    tags:
      - tag:web

- name: Choose the TailVIP the new service answers on
  abn.tailscale.tailscale_service:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    tailnet: "-1234567890123"
    name: svc:web
    ports:
      - tcp:443
    addrs:
      - 100.100.100.100

- name: Approve one device to host the service, by the id the API lists
  abn.tailscale.tailscale_service:
    api_token: "{{ tailscale_api_token }}"
    name: svc:web
    device_id: "1234567890123456"
    approved: true

- name: Approve a host by the name its role already knows
  abn.tailscale.tailscale_service:
    api_token: "{{ tailscale_api_token }}"
    name: svc:lab
    device_name: "nibbler"
    approved: true

- name: Declare a Service, and in a second task approve a host for it
  # A Service and a host approval are different resources, so a task declares one
  # of them. Two tasks, in order, are how a Service is declared with its hosts.
  abn.tailscale.tailscale_service:
    api_token: "{{ tailscale_api_token }}"
    name: svc:lab
    display_name: Lab service
    ports:
      - tcp:443

- name: Approve the host that runs it
  abn.tailscale.tailscale_service:
    api_token: "{{ tailscale_api_token }}"
    name: svc:lab
    device_name: "nibbler"
    approved: true

- name: Revoke a host by an address it holds
  abn.tailscale.tailscale_service:
    api_token: "{{ tailscale_api_token }}"
    name: svc:lab
    address: "100.64.0.5"
    approved: false

- name: Take a service out of the tailnet, and its DNS name with it
  abn.tailscale.tailscale_service:
    api_token: "{{ tailscale_api_token }}"
    name: svc:web
    state: absent
"""

RETURN = r"""
service:
  description:
    - The Service as the tailnet holds it after the run, in the API's own camel
      case spelling.
    - Absent when the Service was removed, and when the task is about a device
      approval rather than about the Service.
    - On a create the addresses are the ones the server assigned, which is why
      they are absent from the diff.
  returned: when the Service exists after the run
  type: dict
  sample:
    name: svc:web
    displayName: Web front end
    addrs:
      - 100.100.100.100
      - fd7a:115c:a1e0::b533:64c
    comment: Fronted by the nginx containers
    ports:
      - tcp:443
    tags:
      - tag:web
hosts:
  description:
    - The devices hosting the Service, in the API's own spelling.
    - Empty until a device carrying one of the Service's tags advertises the
      endpoint, which is every Service immediately after it is created.
    - Absent when the task is about a device approval.
  returned: when the task is about the Service
  type: list
  elements: dict
  sample:
    - stableNodeID: n292kg92CNTRL
      approvalLevel: approved:manual
      configured: ready
approval:
  description:
    - Whether the device is approved to host the Service, in the API's own
      spelling. C(autoApproved) is the server's own record of an automatic
      approval, which this module does not change.
  returned: when the task is about a device approval
  type: dict
  sample:
    approved: true
    autoApproved: false
diff:
  description:
    - The Service as it was and the Service it was reconciled to, rendered by
      C(--diff). Both sides are equal when nothing would change, C(before) is
      absent when the Service did not exist, and C(after) is absent when it was
      removed.
    - On a create the addresses are absent from C(after), because the server
      assigns them and a check run cannot know them.
  returned: always
  type: dict
  contains:
    before:
      description: The Service as the tailnet held it.
      returned: always
      type: dict
    after:
      description: The Service reconciled to, or what a check run would have
        written.
      returned: always
      type: dict
"""

import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import DeviceError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import identity
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import listing
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import resolve
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleNotFound,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import (
    connection_arguments,
)

#: Module option to API field. The API is Go, and Go marshals to camel case.
_FIELDS = {
    "display_name": "displayName",
    "comment": "comment",
    "ports": "ports",
    "tags": "tags",
    "addrs": "addrs",
}

#: What the API accepts as a Service name, measured rather than assumed. The
#: remainder is a DNS label, so an underscore, a dot, a percent sign or a space is
#: refused. A space is refused by the URL layer before a request is built, which
#: surfaces as a transport failure with nothing in it to act on, so the shape is
#: checked here instead of leaving the operator to read that.
_NAME = re.compile(r"svc:[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\Z")

#: What the API says when a Service would have no ports. Quoted back to the
#: operator rather than paraphrased, because it names the way out.
_PORTS_ADVICE = 'the API refuses a Service with no ports; use "do-not-validate" to skip validation'

#: The options that name a device. One of them, and only one, is what makes a task
#: an approval rather than a Service change, which is why the Service options and
#: these cannot be combined.
_DEVICE_SELECTORS = ("device_id", "device_name", "address")

ARGUMENT_SPEC = connection_arguments(
    name={"type": "str", "required": True},
    state={"type": "str", "choices": ["present", "absent"], "default": "present"},
    display_name={"type": "str"},
    comment={"type": "str"},
    ports={"type": "list", "elements": "str"},
    tags={"type": "list", "elements": "str"},
    addrs={"type": "list", "elements": "str"},
    device_id={"type": "str"},
    device_name={"type": "str"},
    address={"type": "str"},
    approved={"type": "bool"},
)


def _same(desired: dict, current: dict | None) -> bool:
    """Whole-document equality, except that ``tags`` is compared as a set.

    The server stores a Service's tags in an order of its own, so comparing the
    declared order against the one it returns reports a change for ever for a task
    that is already satisfied. Measured: a Service created with
    ``[tag:stress, tag:order-probe]`` and then updated to the reverse order reads
    back in the first order, so the second write is not the one that decides it.

    An absent key and an empty one are different states here even though the
    request builder treats an empty list as a removal, because that removal is the
    change being compared for.
    """
    if current is None:
        # No Service under this name, so there is nothing that could already match.
        return False
    if ("tags" in desired) != ("tags" in current):
        return False
    if "tags" not in desired:
        return desired == current
    return {**desired, "tags": sorted(desired["tags"])} == {
        **current,
        "tags": sorted(current["tags"]),
    }


def desired_document(params: dict, current: dict | None) -> dict:
    """The Service the task asks for, in the shape the PUT takes.

    ``current`` is the document the API returned, or ``None`` when it holds no
    Service under this name. The PUT replaces the whole Service, so anything the
    task did not mention is carried forward from what is already there rather than
    replaced by a default. Sending a default would clear a field nobody mentioned,
    which on this endpoint is indistinguishable from asking for it.

    A value the server will not store is not sent. Measured against the real
    endpoint: an empty comment, an empty display name and an empty tag list are
    each accepted and each stored as an absent key, so all three are removed from
    the request rather than sent empty. A document carrying them would differ from
    the tailnet on every run and a task clearing a comment would report a change
    for ever.

    ``addrs`` and ``ports`` fall out of the same rule rather than needing one of
    their own: both are mandatory on the wire, so the carry-forward is what makes
    an update naming only a comment possible at all.
    """
    body: dict = dict(current) if current else {}
    body["name"] = params["name"]

    for option, field in _FIELDS.items():
        value = params.get(option)
        if value is None:
            continue
        if value:
            body[field] = value
        else:
            body.pop(field, None)

    return body


def task_refusal(params: dict) -> str | None:
    """Why this task cannot be sent at all, before anything has been read.

    Each of these is the task's own shape rather than the tailnet's, so refusing
    them here costs no request, and a check run reports them the same as any
    other failure. A name the API would refuse is refused by the URL layer before
    a request exists, and that reaches the operator as a transport failure with
    nothing in it to act on. A task naming a device is asking about a different
    resource from a task describing the Service, so the two cannot be combined,
    and combining one with a removal would destroy a Service the task never
    mentioned. An approval that named no device would change nothing, so it is
    refused rather than quietly ignored. An empty port list is refused whether
    the Service is being created or updated, so it needs no read either.
    """
    name = params["name"]
    if not _NAME.fullmatch(name):
        return (
            f"{name!r} is not a name the API will accept for a Service. A Service name starts "
            "with 'svc:' and the rest is a DNS label: letters, digits and hyphens, starting and "
            "ending with a letter or a digit."
        )

    named = [option for option in _DEVICE_SELECTORS if params.get(option) is not None]
    describing = [option for option in _FIELDS if params.get(option) is not None]

    if named and describing:
        return (
            f"{' and '.join(named)} names a device while {' and '.join(describing)} describes "
            "the Service, and those are two different resources. A device approval is expressed "
            "by approved, and the rest describe the Service itself, so a task naming both would "
            "have to choose which one it meant. Split it into two tasks."
        )

    if named and params["state"] != "present":
        return (
            f"state is {params['state']!r} while {' or '.join(named)} is set, and those are two "
            "different resources. A device approval is expressed by approved, and state "
            "describes the Service itself, so a task naming one device cannot remove the "
            "Service it hosts. Use state: absent on its own to remove the Service."
        )

    if params.get("approved") is not None and not named:
        return (
            "approved says what to do to a device and no device was named, so this task would "
            "change nothing. Name the device with one of: " + ", ".join(_DEVICE_SELECTORS) + "."
        )

    if params.get("ports") is not None and not params["ports"]:
        return f"ports is an empty list: {_PORTS_ADVICE}."

    return None


def document_refusal(params: dict, current: dict | None) -> str | None:
    """Why this Service cannot be written as declared, or ``None`` when it can.

    Both cases here are requests the API would refuse with a message naming the
    constraint but not the fix, and both need to know whether the Service exists,
    which is what the read is for. Refusing them here also means check mode
    reports them: a check run that cannot tell whether the real run would be
    refused is a check run worth nothing.
    """
    name = params["name"]

    if current is None and not params.get("ports"):
        return (
            f"{name!r} does not exist yet, so creating it needs at least one port and the task "
            f"names none: {_PORTS_ADVICE}."
        )

    given = params.get("addrs")
    if given is None:
        return None
    if current is None:
        if len(given) == 1:
            return None
        return (
            f"addrs has {len(given)} elements and {name!r} does not exist yet, so there is "
            "nothing to update. A new Service takes either no addresses at all, to let the "
            "server choose, or a single IPv4 to assign it, and the IPv6 is the server's to "
            "assign either way."
        )
    if len(given) == 2:
        return None
    return (
        f"addrs has {len(given)} element{'s' if len(given) != 1 else ''} and {name!r} already "
        "exists, so an update has to carry both its addresses: the IPv4 it holds and the IPv6 "
        "the server assigned. Give both, or leave addrs out to keep the pair the Service holds."
    )


def _read_service(module: AnsibleModule, api: Api) -> dict | None:
    """The Service the tailnet holds under this name, or ``None`` when it holds none.

    A 404 is the answer to "is it there", not a failure: the two states this
    module reconciles between are a Service and no Service. A body that is not a
    Service is a different thing, and is refused: treating it as an absent Service
    would create one over the top of whatever it should have been, and a proxy
    answering 200 with an error page is how that happens.
    """
    name = module.params["name"]
    try:
        body = api.call("service_get", "GET", params={"serviceName": name}).body
    except TailscaleNotFound:
        return None
    if not isinstance(body, dict):
        module.fail_json(
            msg=f"The Service {name!r} was read back as something other than a Service "
            "document, so what it currently holds could not be compared against what the task "
            "asks for. Nothing was written."
        )
    return body


def _hosts(api: Api, name: str) -> list:
    """The devices hosting the Service, in the API's own spelling.

    A Service nobody advertises has no hosts, and the API answers that with an
    absent key rather than an empty list, the same way it drops a value that is
    already its default. A 404 is the right answer on the run that has just
    removed the Service, and on the run before it was created.
    """
    try:
        body = api.call("service_hosts_list", "GET", params={"serviceName": name}).body
    except TailscaleNotFound:
        return []
    hosts = body.get("hosts") if isinstance(body, dict) else None
    return hosts if isinstance(hosts, list) else []


def _manage_service(module: AnsibleModule, api: Api) -> None:
    """Reconcile the Service itself: create it, update it, or remove it."""
    name = module.params["name"]
    reason = task_refusal(module.params)
    if reason is not None:
        module.fail_json(msg=reason)

    current = _read_service(module, api)

    if module.params["state"] == "absent":
        if current is None:
            module.exit_json(changed=False, hosts=[], diff={"before": None, "after": None})
        if not module.check_mode:
            api.call("service_delete", "DELETE", params={"serviceName": name})
        module.exit_json(changed=True, hosts=[], diff={"before": current, "after": None})

    reason = document_refusal(module.params, current)
    if reason is not None:
        module.fail_json(msg=reason)

    desired = desired_document(module.params, current)
    if _same(desired, current):
        module.exit_json(
            changed=False,
            service=current,
            hosts=_hosts(api, name),
            diff={"before": current, "after": current},
        )
    if module.check_mode:
        module.exit_json(
            changed=True,
            service=desired,
            hosts=_hosts(api, name),
            diff={"before": current, "after": desired},
        )

    written = api.call("service_set", "PUT", params={"serviceName": name}, body=desired)
    # The response is the stored Service, which carries the addresses the server
    # assigned. Returning the request instead would report a document nobody holds.
    stored = written.body if isinstance(written.body, dict) else desired
    module.exit_json(
        changed=True,
        service=stored,
        hosts=_hosts(api, name),
        # The callback reads `result['diff']` and nothing else. A top-level
        # `before` and `after` look equivalent and render nothing at all.
        diff={"before": current, "after": desired},
    )


def _device_id(module: AnsibleModule, api: Api) -> str:
    """The device an approval names, however the task spelled it.

    A task that gave the API's own id needs no read. A task that named the device
    any other way needs the device list, and the selector is applied to that list
    rather than translated server-side, so a name or an address matching no
    device, or more than one, is a refusal this module can explain rather than a
    404 from a write the task never expected to depend on.
    """
    given = module.params.get("device_id")
    if given is not None:
        return str(given)

    try:
        selection = resolve(listing(api), module.params, many=False)
    except DeviceError as error:
        module.fail_json(msg=str(error))

    return identity(selection.devices[0])


def _manage_approval(module: AnsibleModule, api: Api) -> None:
    """Approve or revoke one device for the Service.

    Approving a host is a real access control action, and the two things that can
    go wrong with it are both refusals rather than partial successes: a device
    that is not there, and a Service that is not there. Neither is a state this
    module reconciles, so both are errors rather than something to write.
    """
    name = module.params["name"]
    wanted = bool(module.params["approved"])
    reason = task_refusal(module.params)
    if reason is not None:
        module.fail_json(msg=reason)

    device_id = _device_id(module, api)
    where = {"serviceName": name, "deviceId": device_id}

    try:
        body = api.call("service_approval_get", "GET", params=where).body
    except TailscaleNotFound:
        module.fail_json(
            msg=f"The API has no approval record for Service {name!r} on device {device_id!r}. "
            "Either the Service or the device is not in this tailnet: a device that is shared "
            "in from another tailnet is not one this API can approve a host on, and neither is "
            "one that has already been deleted. Nothing was written."
        )

    current: dict = body if isinstance(body, dict) else {}
    if bool(current.get("approved")) == wanted:
        module.exit_json(
            changed=False, approval=current, diff={"before": current, "after": current}
        )

    after: dict = dict(current, approved=wanted)
    if not module.check_mode:
        try:
            written = api.call(
                "service_approval_set", "POST", params=where, body={"approved": wanted}
            )
        except TailscaleNotFound:
            module.fail_json(
                msg=f"The API refused the approval of Service {name!r} on device "
                f"{device_id!r}, which it does not recognise. Nothing was written."
            )
        # The response carries `autoApproved` as well, which a manual write cannot
        # change, so it is read rather than guessed.
        after = written.body if isinstance(written.body, dict) else after
    module.exit_json(changed=True, approval=after, diff={"before": current, "after": after})


def run(module: AnsibleModule) -> None:
    try:
        api = build_client(module.params)
        if any(module.params.get(option) is not None for option in _DEVICE_SELECTORS):
            _manage_approval(module, api)
        else:
            _manage_service(module, api)
    except CredentialError as error:
        module.fail_json(msg=str(error))
    except TailscaleError as error:
        module.fail_json(msg=str(error))


def main() -> None:
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        required_together=[("oauth_client_id", "oauth_client_secret")],
        required_by={
            # `required_together` cannot express this: it fails when only some of
            # a tuple is given, so a task naming one selector would be refused for
            # the selectors it did not name. `required_by` asks the question in the
            # direction that fits: if this selector is given, `approved` must be.
            "device_id": "approved",
            "device_name": "approved",
            "address": "approved",
        },
        mutually_exclusive=[
            ("api_token", "oauth_client_id"),
            ("api_token", "oauth_client_secret"),
            # One device, named once. Two spellings of the same choice are two
            # answers to one question, and the selector would take the first and
            # leave the other unread. A device option combined with a Service
            # option is refused in `task_refusal` instead, because that pairing
            # has to name the option the task actually gave.
            ("device_id", "device_name"),
            ("device_id", "address"),
            ("device_name", "address"),
        ],
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
