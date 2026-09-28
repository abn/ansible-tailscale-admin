#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_policy
short_description: Manage a tailnet access control policy
version_added: 0.1.0
description:
  - Brings the access control policy of a Tailscale tailnet to the document the
    task gives it, writing only when the two differ.
  - The document comes from a HuJSON file or from HuJSON text the task carries,
    and the two are the same apart from where the text comes from. Exactly one of
    O(policy) and O(content) supplies it.
  - Whichever is given is read on the host running the module, which is the
    controller, because the module reaches the Tailscale API itself rather than
    the managed machine.
  - The whole document is replaced on a change, because that is the only thing
    the API offers, so a wrong file affects every device in the tailnet at once.
    Before anything is written, the server runs the access tests the document
    itself declares and the module reports any that fail. A warning it reports
    instead of a failure is surfaced as a warning and the write proceeds. The
    validator does not judge whether the ACLs would leave you able to reach the
    tailnet, so a document that would lock you out is caught by a C(tests) block
    rather than by the validator. A test the task declares is no safer than one
    the file writes, because the server runs the assertions it is given and
    judges nothing else.
  - O(groups), O(app_connectors) and O(tests) declare parts of the document on
    the task, for the three sections whose shape is regular enough to be
    mechanical. A declared section is merged into what the document holds, and a
    conflict between the two is an error rather than a choice, so a task cannot
    silently overwrite the policy it was given.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.check_mode_diff_mode
  - abn.tailscale._attributes.connection_delegation
options:
  policy:
    description:
      - Path to the HuJSON policy file, read on the host running the module.
      - The file may use JSON with comments, trailing commas and the other
        HuJSON relaxations, and is rendered back in canonical form before it is
        sent.
      - Exactly one of this and O(content) gives the document. This one is for a
        policy kept under version control, where the run reads and diffs a file.
    type: path
    version_added: 0.1.0
  content:
    description:
      - The policy document itself, as HuJSON text, for a document a template or a
        play has already produced.
      - It takes the same relaxations a file does, and O(groups), O(app_connectors)
        and O(tests) are spliced into it exactly as they are into a file's
        contents. The two differ only in where the text comes from.
      - Mutually exclusive with O(policy); exactly one of the two is required.
    type: str
    version_added: 0.1.0
  groups:
    description:
      - Groups to declare, as a mapping of group name to the list of its members.
      - Each name must begin with C(group:), and each member is a user login such
        as C(alice@example.com). A group cannot contain another group.
      - A declared group is added to the C(groups) section of the file. Naming a
        group the file already declares, with the same members in another order,
        is not a conflict and changes nothing. Naming it with different members is
        an error, because the module picks no winner between the file and the
        task.
      - A rule that names a group no section declares is reported as a warning
        rather than refused, because a group synced from an identity provider is
        a group the file is right not to declare. The server refuses such a
        document with C(group not found) when the group is not synced.
    type: dict
    version_added: 0.1.0
  app_connectors:
    description:
      - App connectors to declare, each routing the traffic for one application
        or set of domains through the devices carrying its tags.
      - A connector is declared under C(tailscale.com/app-connectors) in the
        C(nodeAttrs) section, which the server accepts only on an entry
        targeting every node. The module creates that entry, or adds to the one
        the file already has, and refuses a file that puts an app map on an entry
        targeting less.
      - A connector is identified by its C(name). Naming one the file already
        declares, with the same settings, is not a conflict and changes nothing.
        Naming it with different settings is an error.
      - A connector also needs the rest of what makes it work, which the server
        does not insist on. The module refuses a connector whose tags C(tagOwners)
        does not declare, because the server refuses the write, and reports a
        connector that no access rule makes reachable, or that has no route
        approver, as a warning, because the document is accepted and the connector
        routes nothing. See also R(warnings,returned).
      - The domains of a preset app are fetched by Tailscale, so a connector
        naming one must set neither C(domains) nor an empty list of them.
    type: list
    elements: dict
    version_added: 0.1.0
    suboptions:
      name:
        description:
          - Identifies the connector, and is how the console and the policy file
            name it. Two connectors in one document cannot share one.
        type: str
        required: true
        version_added: 0.1.0
      connectors:
        description:
          - The tags of the devices that route the application's traffic. Each is
            a tag C(tagOwners) declares, since a tag exists only where the policy
            grants it, and the server refuses the write otherwise.
        type: list
        elements: str
        required: true
        version_added: 0.1.0
      domains:
        description:
          - The domains this connector routes, required unless C(preset) or
            C(preset_id) is set. A wildcard is accepted for a subdomain, so
            C(*.example.com), and refused for a top-level domain.
        type: list
        elements: str
        version_added: 0.1.0
      preset:
        description:
          - An application Tailscale fetches the domains and routes for, named as
            Tailscale publishes it. The identifier it writes is not always the
            name, and the module holds the mapping.
          - The four applications whose identifier carries the region they apply
            to are listed here as well, and cannot be named this way, because the
            module does not hold the list of regions Tailscale recognises. Give
            those as C(preset_id) instead.
        type: str
        version_added: 0.1.0
        choices:
          - "AWS CloudFront (global)"
          - "Confluence"
          - "GitHub"
          - "Google Workspace"
          - "Jira"
          - "Microsoft 365"
          - "Okta"
          - "Oracle Services Network (global)"
          - "Salesforce (Hyperforce environment)"
          - "Salesforce (Salesforce-hosted)"
          - "Stripe"
          - "AWS EC2/ELB"
          - "AWS S3"
          - "Oracle Cloud Infrastructure (OCI)"
          - "Oracle Object Storage"
      preset_id:
        description:
          - The C(presetAppID) itself, for an application whose identifier carries
            a region, which is C(aws-ec2-REGION-AVAILABILITY-ZONE-LOCAL-ZONE) or
            C(aws-s3-REGION-AVAILABILITY-ZONE-LOCAL-ZONE) for the two AWS
            applications, and C(oracle-oci-REGION) or
            C(oracle-object-storage-REGION) for the two Oracle ones. The value is
            written as given and the server is the authority on it, refusing an
            identifier it does not recognise. Mutually exclusive with C(preset).
        type: str
        version_added: 0.1.0
      routes:
        description:
          - Routes the connector advertises, as CIDR ranges. A custom app has to
            have its routes approved through C(autoApprovers).
        type: list
        elements: str
        version_added: 0.1.0
  tests:
    description:
      - Access tests to declare, each asserting what a source may or may not
        reach under the access rules of the document.
      - The server runs the tests a document declares before accepting it, and
        refuses the write over any that fail. A test the task declares is run
        exactly as one the file writes, and is no safer, because the server runs
        the assertions it is given and does not judge whether the rules would
        leave you able to reach the tailnet.
      - A declared test is appended to the C(tests) section of the file.
    type: list
    elements: dict
    version_added: 0.1.0
    suboptions:
      src:
        description:
          - The identity the test runs from, which can be a user login, a
            C(group:) or C(tag:) selector, a host alias, or a Tailscale IP.
        type: str
        required: true
        version_added: 0.1.0
      accept:
        description:
          - Destinations the source must be able to reach, as C(host:port). The
            server refuses a test naming C(*) as a source or a destination.
        type: list
        elements: str
        version_added: 0.1.0
      deny:
        description:
          - Destinations the source must not be able to reach, as C(host:port).
        type: list
        elements: str
        version_added: 0.1.0
      proto:
        description:
          - The IP protocol the assertions apply to, so the test checks one
            protocol rather than either.
        type: str
        version_added: 0.1.0
      src_posture_attrs:
        description:
          - The device posture attributes to evaluate the assertions under, as a
            mapping of attribute to a string, a number or a boolean. Only needed
            when the access rules carry posture conditions.
        type: dict
        version_added: 0.1.0
  allow_all_traffic:
    description:
      - Confirm that a policy with no access rules is intended.
      - A document with neither O(policy) keys C(acls) nor C(grants) is read by
        Tailscale as permitting every device in the tailnet to reach every other.
        An absent key is easy to produce by accident, from an empty file or a
        truncated document, and the module refuses one without this.
      - An empty C(acls) list denies everything instead, which is the safe
        direction, and needs no confirmation.
    type: bool
    default: false
    version_added: 0.1.0
"""

EXAMPLES = r"""
- name: Manage the policy from a file on the controller
  abn.tailscale.tailscale_policy:
    api_token: "{{ tailscale_api_token }}"
    policy: "{{ playbook_dir }}/policies/tailnet.hujson"

- name: Manage a named tailnet through an OAuth client
  abn.tailscale.tailscale_policy:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    tailnet: "-1234567890123"
    policy: "{{ playbook_dir }}/policies/tailnet.hujson"

- name: Report what would change without writing it
  abn.tailscale.tailscale_policy:
    api_token: "{{ tailscale_api_token }}"
    policy: "{{ playbook_dir }}/policies/tailnet.hujson"
  check_mode: true
  diff: true

- name: Declare a group and the rule that uses it
  abn.tailscale.tailscale_policy:
    api_token: "{{ tailscale_api_token }}"
    policy: "{{ playbook_dir }}/policies/tailnet.hujson"
    groups:
      "group:engineering":
        - alice@example.com
        - bob@example.com
    tests:
      - src: bob@example.com
        accept:
          - "{{ hostvars['gateway']['tailscale_address'] }}:22"
        deny:
          - "100.64.0.1:3389"

- name: Route GitHub through a tagged connector device
  abn.tailscale.tailscale_policy:
    api_token: "{{ tailscale_api_token }}"
    policy: "{{ playbook_dir }}/policies/tailnet.hujson"
    app_connectors:
      - name: github
        connectors:
          - "tag:github-connector"
        preset: GitHub

- name: Route an application's own domains through a tagged device
  abn.tailscale.tailscale_policy:
    api_token: "{{ tailscale_api_token }}"
    policy: "{{ playbook_dir }}/policies/tailnet.hujson"
    app_connectors:
      - name: internal wiki
        connectors:
          - "tag:wiki-connector"
        domains:
          - wiki.example.com
          - "*.wiki.example.com"
        routes:
          - 100.64.0.0/10
"""

RETURN = r"""
etag:
  description:
    - The fingerprint of the policy as it was read, which is what guards the next
      write against a concurrent edit. It is not the fingerprint after the run
      when the run changed something, because the server issues a fresh one on
      every write and this value is the one the write carried.
  returned: always
  type: str
  sample: '"e0b2816b418"'
changed_paths:
  description:
    - The JSON Pointer of each node that writing the policy would change, empty
      when nothing would.
  returned: always
  type: list
  elements: str
  sample:
    - /acls/0/dst
warnings:
  description:
    - What was found in the document that the server would not object to, and that
      would not do what it looks like it does. Each entry says which it is, either
      one the module derived from the document, such as an access rule naming a
      group no section declares, or one the server reported about the document it
      was sent, such as a group that is not syncing from SCIM and will be ignored
      by the rules referring to it. Empty when there was none. A warning does not
      stop the write.
  returned: always
  type: list
  elements: str
  sample:
    - "The policy was accepted, with a warning the server reported. Each line is one
      entry the server reported:
        group:unknown@example.com: group is not syncing from SCIM and will be ignored
        by rules in the policy file"
diff:
  description:
    - The policy as the tailnet held it and the policy it was reconciled to,
      rendered by C(--diff). Both sides are equal when nothing would change, and
      C(after) is what a check run would have written, including the sections the
      task declared.
  returned: always
  type: dict
  contains:
    before:
      description: The policy as read.
      returned: always
      type: dict
    after:
      description: The policy reconciled to.
      returned: always
      type: dict
"""

from typing import Any

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import CanonError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import load_file
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import loads
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import (
    connection_arguments,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._policy import PolicyError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._policy import reconcile
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._vocabulary import (
    PRESET_NAMES,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._vocabulary import (
    VocabularyError,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._vocabulary import compose

ARGUMENT_SPEC = connection_arguments(
    policy={"type": "path"},
    content={"type": "str"},
    groups={"type": "dict"},
    app_connectors={
        "type": "list",
        "elements": "dict",
        "options": {
            "name": {"type": "str", "required": True},
            "connectors": {"type": "list", "elements": "str", "required": True},
            "domains": {"type": "list", "elements": "str"},
            "preset": {"type": "str", "choices": list(PRESET_NAMES)},
            "preset_id": {"type": "str"},
            "routes": {"type": "list", "elements": "str"},
        },
    },
    tests={
        "type": "list",
        "elements": "dict",
        "options": {
            "src": {"type": "str", "required": True},
            "accept": {"type": "list", "elements": "str"},
            "deny": {"type": "list", "elements": "str"},
            "proto": {"type": "str"},
            "src_posture_attrs": {"type": "dict"},
        },
    },
    allow_all_traffic={"type": "bool", "default": False},
)


def _document_of(params: dict) -> Any:
    """The document the task gave, from the file or from the text.

    One function rather than a branch at the call site, because the two sources
    differ only in where the text comes from: both are parsed the same way, and
    neither is treated differently once read.
    """
    path = params.get("policy")
    if path is not None:
        return load_file(path)
    return loads(params["content"])


def run(module: AnsibleModule) -> None:
    """Reconcile the policy, or fail with a message that says why.

    Every failure this module anticipates is the same thing to whoever is
    reading: the message. The types stay distinct because a caller can catch them
    apart; they do not stay distinct in the handling because nothing there tells
    them apart. Both blocks guard the same set, because an OAuth credential is
    exchanged on the first request rather than when the client is built, so a bad
    one surfaces in whichever block made that request.

    Reading the file and reconciling are two guarded blocks rather than one, so
    that what the module found in the document reaches the operator before the
    run can fail on it. A finding is most useful at the moment the server refuses
    the document, and `fail_json` carries only the warnings recorded before it.
    """
    anticipated = (CanonError, CredentialError, PolicyError, TailscaleError, VocabularyError)
    try:
        api = build_client(module.params)
        desired, findings = compose(
            _document_of(module.params),
            groups=module.params["groups"],
            app_connectors=module.params["app_connectors"],
            tests=module.params["tests"],
        )
    except anticipated as error:
        module.fail_json(msg=str(error))

    for finding in findings:
        module.warn(finding)

    try:
        outcome = reconcile(
            api,
            desired,
            allow_all_traffic=module.params["allow_all_traffic"],
            check_mode=module.check_mode,
        )
    except anticipated as error:
        module.fail_json(msg=str(error))

    for warning in outcome.warnings:
        module.warn(warning)

    module.exit_json(
        changed=outcome.changed,
        etag=outcome.etag,
        changed_paths=[difference["path"] for difference in outcome.differences],
        # The callback reads `result['diff']` and nothing else. A top-level
        # `before` and `after` look equivalent and render nothing at all, which
        # is what `diff_mode: support: full` did here until this was tried.
        diff={"before": outcome.before, "after": outcome.after},
    )


def main() -> None:
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        required_together=[("oauth_client_id", "oauth_client_secret")],
        required_one_of=[("policy", "content")],
        mutually_exclusive=[
            ("api_token", "oauth_client_id"),
            ("api_token", "oauth_client_secret"),
            ("policy", "content"),
        ],
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
