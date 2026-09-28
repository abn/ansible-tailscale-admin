#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_aws_external_id
short_description: Read a tailnet's AWS external id and validate a trust policy
version_added: 0.1.0
description:
  - Returns the external id Tailscale supplies to AWS when it assumes an IAM role
    to stream logs to S3, and the AWS account id it presents from, and optionally
    asks Tailscale to validate an IAM role trust policy against that external id.
  - A tailnet has one external id and the API offers no delete, so it is a read.
    The module reports C(changed=False) on every run. There is no resource to
    reconcile and nothing to remove.
  - The API exposes the id through a create-or-get operation rather than a read.
    The module asks for a reusable id, which is what makes the operation
    idempotent. Tailscale creates one for a tailnet that has none and returns the
    same one on every later call, as long as it has not been linked to an AWS
    account. Tailscale gives no answer that tells a creation apart from a read, so
    the module cannot report whether the first run created the id and does not
    claim to. The first run is the only one that changes anything, and it is
    reported as no change because the module cannot observe it.
  - Once the id has been linked to an AWS account Tailscale no longer returns it
    as reusable, so the next call may create a new one. That is the API's rule for
    a linked id rather than this module's, and it is not something a task can
    prevent from here.
  - O(role_arn) asks the server to assume the named role with this external id and
    report whether it can. The validator changes nothing on the tailnet, so its
    verdict is returned rather than raised. A trust policy that does not yet allow
    Tailscale is the answer the task asked for, not a failure.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.connection_delegation
options:
  role_arn:
    description:
      - The ARN of the AWS IAM role whose trust policy should be validated against
        this external id.
      - When set, the module calls the validator after reading the id and returns
        its verdict under R(validation,returned). The validator asks Tailscale to
        assume the role, so it exercises the AWS account's trust policy and changes
        nothing in the tailnet.
      - Leave it out to read the id and the account id without validating anything.
    type: str
    version_added: 0.1.0
attributes:
  check_mode:
    description: >-
      The module only reads, so a check run reads and returns the same result as a
      real one. There is no write for check mode to hold back.
    support: full
  diff_mode:
    description: >-
      The module returns no diff. There is one state to read and nothing to
      reconcile it against.
    support: none
"""

EXAMPLES = r"""
- name: Read the tailnet's AWS external id
  abn.tailscale.tailscale_aws_external_id:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
  register: aws

- name: Show the account Tailscale would assume the role from
  ansible.builtin.debug:
    var: aws.tailscale_aws_account_id

- name: Check an IAM role's trust policy before streaming logs to S3
  abn.tailscale.tailscale_aws_external_id:
    api_token: "{{ tailscale_api_token }}"
    role_arn: arn:aws:iam::123456789012:role/tailscale-log-writer
  register: trust

- name: Fail while the trust policy does not yet allow Tailscale
  ansible.builtin.assert:
    that: trust.validation.valid
    fail_msg: "{{ trust.validation.message }}"
"""

RETURN = r"""
external_id:
  description:
    - The external id Tailscale supplies to AWS when it authenticates to an IAM
      role with role-based authentication.
  returned: always
  type: str
  sample: 60fe9ce7-7791-4ab3-ab34-4294f5972725
tailscale_aws_account_id:
  description:
    - The AWS account id Tailscale supplies to AWS alongside the external id.
  returned: always
  type: str
  sample: "001234567890"
validation:
  description:
    - The verdict of the trust-policy validator, empty when O(role_arn) was not
      given.
  returned: always
  type: dict
  contains:
    role_arn:
      description: The role the verdict is about, as the task gave it.
      returned: always
      type: str
      sample: arn:aws:iam::123456789012:role/tailscale-log-writer
    valid:
      description:
        - Whether Tailscale could assume the role with this external id. True when
          the validator answered 200, False when it answered 422 with a reason.
      returned: always
      type: bool
    message:
      description:
        - The reason the validation failed, rendered from the server's own message,
          empty when it succeeded. The collection renders it with the operation it
          failed at rather than passing the raw body through, so it is the message
          to show an operator and not a document to parse.
      returned: always
      type: str
  sample:
    role_arn: arn:aws:iam::123456789012:role/tailscale-log-writer
    valid: false
    message: >-
      Tailscale was unable to assume the given role. Please ensure your trust
      policy allows our account (001234567890) and requires the external ID.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleApiError,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import (
    connection_arguments,
)

#: The status the validator answers when it could not assume the role. It is a
#: verdict rather than a refusal of the request, which is why the collection maps
#: it to no specific remedy and it arrives as the base API error.
_INVALID_TRUST_POLICY = 422


class ExternalIdError(Exception):
    """A request this module refuses to make, or a response it refuses to read."""


ARGUMENT_SPEC = connection_arguments(
    role_arn={"type": "str"},
)


def _read_external_id(api: Api) -> dict:
    """The tailnet's external id document, or a read this module refuses to trust.

    The request marks the id reusable, which is what makes the create-or-get
    idempotent: a tailnet that has a reusable id gets it back, and a tailnet that
    has none gets one that every later call returns. Without the marker the API
    mints a new id on every call, which is a write no declarative task can survive.

    A body without an external id is the response of a proxy or a version that no
    longer holds this document. It is refused rather than returned empty, because a
    task given an empty id would configure an IAM role against nothing.
    """
    body = api.call("aws_external_id_get", "POST", body={"reusable": True}).body
    if not isinstance(body, dict) or not body.get("externalId"):
        raise ExternalIdError(
            "The AWS external id read answered without an external id, so there is "
            "nothing to configure an IAM role against. The response was not the "
            "document this endpoint returns."
        )
    return body


def _validate(api: Api, external_id: str, role_arn: str) -> dict:
    """The validator's verdict for one role, as a returnable document.

    A 422 is the verdict rather than a failure: the endpoint asks whether Tailscale
    can assume the role, and 422 is its answer that it cannot. Every other failure
    propagates, because it is about the request or the tailnet rather than about the
    trust policy the task asked to be judged.
    """
    try:
        api.call(
            "aws_external_id_validate",
            "POST",
            params={"id": external_id},
            body={"roleArn": role_arn},
        )
    except TailscaleApiError as error:
        if error.status != _INVALID_TRUST_POLICY:
            raise
        return {"role_arn": role_arn, "valid": False, "message": error.message}
    return {"role_arn": role_arn, "valid": True, "message": ""}


def run(module: AnsibleModule) -> None:
    given = module.params.get("role_arn")
    role_arn = (given or "").strip()
    if given is not None and not role_arn:
        module.fail_json(
            msg="O(role_arn) was given but is empty, so there is no role to validate. "
            "Give the ARN of an IAM role, or leave the option out to read the "
            "external id alone."
        )
    try:
        api = build_client(module.params)
        document = _read_external_id(api)
        external_id = str(document["externalId"])
        validation = _validate(api, external_id, role_arn) if role_arn else {}
    except (ExternalIdError, CredentialError, TailscaleError) as error:
        module.fail_json(msg=str(error))

    module.exit_json(
        # There is nothing to change and nothing to remove. The one run that asks a
        # bare tailnet for its first reusable id causes Tailscale to create one, and
        # the response carries no field that says so, so reporting a change would
        # report one on every run instead.
        changed=False,
        external_id=external_id,
        tailscale_aws_account_id=str(document.get("tailscaleAwsAccountId", "")),
        validation=validation,
    )


def main() -> None:
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        required_together=[("oauth_client_id", "oauth_client_secret")],
        mutually_exclusive=[
            ("api_token", "oauth_client_id"),
            ("api_token", "oauth_client_secret"),
        ],
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
