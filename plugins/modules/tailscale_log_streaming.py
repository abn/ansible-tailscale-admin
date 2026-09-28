#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_log_streaming
short_description: Manage where a tailnet streams its logs
version_added: 1.0.0
description:
  - Reconciles the log streaming destination for one log type, which is the system
    the tailnet posts that log to and how. A tailnet has one destination per log
    type, and setting it replaces the destination that is already there.
  - C(log_type) is part of the URL rather than of the destination, because the
    API marks it read-only. The log type chooses the endpoint, and the
    destination is the body.
  - The write replaces the whole destination, so an option the task left out is
    taken from the destination the tailnet already has rather than reset. Every
    option is therefore optional and a task that sets one leaves the rest alone.
  - A password cannot be compared, because the API never returns one. Two
    consequences follow, and both are the API's rather than this module's. A
    destination that holds a password cannot be reconciled field by field, because
    reading the destination back does not return it, so a task that changes any
    other field of such a destination has to give the password too or the write
    will clear it. And a task that gives a password writes on every run and
    reports a change on every run, because there is nothing to compare it against.
    The write is the same document each time, so the effect is idempotent even
    though the report is not.
  - Tailscale refuses every endpoint of this family on a plan that does not
    include log streaming, and answers with a status that is otherwise used for a
    missing scope. The module passes that answer on as a billing one.
  - The publishing status is read on every run, because a destination that is
    configured and not receiving anything is the failure an operator needs to see.
    It costs one more request, and a failure to read it fails the task, because the
    configuration is what the task asked for and a status it could not read is not
    something to report as healthy.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.connection_delegation
options:
  log_type:
    description:
      - Which of the tailnet's logs to stream.
      - C(configuration) is the audit log of changes made through the admin
        console and the API. C(network) is the network flow log, which records
        what the tailnet's devices connected to and has to be enabled as a tailnet
        setting before the tailnet records any.
    type: str
    required: true
    choices:
      - configuration
      - network
    version_added: 1.0.0
  state:
    description:
      - Whether the tailnet should stream this log to a destination.
      - C(absent) deletes the destination and is not an error when there is
        already none, so a task that removes a destination is quiet on a tailnet
        that has not got one.
    type: str
    choices:
      - present
      - absent
    default: present
    version_added: 1.0.0
  destination_type:
    description:
      - The kind of system the tailnet posts this log to.
      - Required when O(state=present).
    type: str
    choices:
      - splunk
      - elastic
      - panther
      - cribl
      - crowdstrike
      - datadog
      - axiom
      - s3
    version_added: 1.0.0
  url:
    description:
      - Where the tailnet posts the log stream.
      - May be left out for O(destination_type=s3), which is the one destination
        where an empty URL means the official Amazon endpoint rather than nowhere.
    type: str
    version_added: 1.0.0
  user:
    description:
      - The username the tailnet authenticates to the destination with.
    type: str
    version_added: 1.0.0
  token:
    description:
      - The token or password the tailnet authenticates to the destination with.
      - This is a credential for the destination system, not for the tailnet, and
        it is never returned by the API. The module cannot tell whether the one it
        holds is the one in use, so a task giving it writes on every run.
      - Marked C(no_log), so Ansible redacts it in task output.
    type: str
    version_added: 1.0.0
  upload_period_minutes:
    description:
      - How many minutes to wait between uploads of new logs.
      - Leave it out to keep the destination's own setting. The API caps it at
        1440, which is a day.
    type: int
    version_added: 1.0.0
  compression_format:
    description:
      - How the tailnet compresses the log stream.
      - Leave it out to keep the destination's own setting. The API documents
        C(none) as the default.
    type: str
    choices:
      - zstd
      - gzip
      - none
    version_added: 1.0.0
  s3_bucket:
    description:
      - The S3 bucket the tailnet writes the log stream to. Required when
        O(destination_type=s3).
    type: str
    version_added: 1.0.0
  s3_region:
    description:
      - The region the O(s3_bucket) is in. Required when O(destination_type=s3).
    type: str
    version_added: 1.0.0
  s3_key_prefix:
    description:
      - A key prefix to put in front of the name the tailnet generates for each
        object.
    type: str
    version_added: 1.0.0
  s3_authentication_type:
    description:
      - How the tailnet authenticates to S3. Required when
        O(destination_type=s3), and Tailscale recommends C(rolearn) over
        C(accesskey).
    type: str
    choices:
      - accesskey
      - rolearn
    version_added: 1.0.0
  s3_access_key_id:
    description:
      - The S3 access key ID, required when O(s3_authentication_type=accesskey).
      - The module never returns it, and it is not marked C(no_log) because AWS
        treats the ID as an identifier rather than a secret. The secret beside it
        is what must not leak.
    type: str
    version_added: 1.0.0
  s3_secret_access_key:
    description:
      - The S3 secret access key, required when
        O(s3_authentication_type=accesskey).
      - The API never returns it, so a task giving it writes on every run, as
        O(token) does. Marked C(no_log), so Ansible redacts it in task output.
    type: str
    version_added: 1.0.0
  s3_role_arn:
    description:
      - The IAM role the tailnet assumes in the account holding O(s3_bucket),
        required when O(s3_authentication_type=rolearn).
    type: str
    version_added: 1.0.0
"""

EXAMPLES = r"""
- name: Stream the configuration audit log to a collector in the tailnet
  abn.tailscale.tailscale_log_streaming:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    log_type: configuration
    destination_type: elastic
    url: https://logs.example.com:8080/config-log-datastream
    user: ansible
    token: "{{ vault_elastic_token }}"

- name: Report what would change, and how the stream is doing now, without writing
  abn.tailscale.tailscale_log_streaming:
    api_token: "{{ tailscale_api_token }}"
    log_type: configuration
    destination_type: elastic
    upload_period_minutes: 5
  check_mode: true
  register: stream

- name: Write the configuration audit log to S3, assuming a role
  abn.tailscale.tailscale_log_streaming:
    api_token: "{{ tailscale_api_token }}"
    log_type: configuration
    destination_type: s3
    s3_bucket: example-tailnet-logs
    s3_region: us-east-1
    s3_authentication_type: rolearn
    s3_role_arn: arn:aws:iam::123456789012:role/tailscale-log-writer
    upload_period_minutes: 15
    compression_format: zstd

- name: Stop streaming the network flow log
  abn.tailscale.tailscale_log_streaming:
    api_token: "{{ tailscale_api_token }}"
    log_type: network
    state: absent
"""

RETURN = r"""
stream_configuration:
  description:
    - The destination the tailnet holds after the run, in the API's own camel
      case spelling, reduced to the fields this module manages.
    - C(logType) and C(s3ExternalId) appear in it although the module takes
      neither, because the API sets them and they say which log the destination
      serves and which AWS role it authenticates with.
    - The fields the API marks write-only are absent, whether or not the
      destination has one set. The module does not return a credential it cannot
      compare, and does not return one echoed back to it either.
    - Empty when O(state=absent) or when the tailnet has no such destination.
  returned: always
  type: dict
  sample:
    logType: configuration
    destinationType: elastic
    url: https://logs.example.com:8080/config-log-datastream
    user: ansible
    compressionFormat: zstd
streaming_status:
  description:
    - What the API reports about publishing to the destination, read on every run.
    - Empty when the tailnet has no destination for this log type, which is what
      the API's not-found means, and when O(state=absent).
    - It is a moving target rather than a configuration, because the counters rise
      and the rates move on their own. A second run over an unchanged destination
      reports a different document and no change.
  returned: always
  type: dict
  sample:
    lastActivity: "2026-09-27T10:45:46Z"
    lastError: ""
    numEntriesSent: 8363
    numFailedRequests: 0
    rateEntriesSent: 0.0085
unverified_options:
  description:
    - The options this run wrote that it could not check, named as the task named
      them. Empty on a run that gave none.
    - A non-empty list means the run reported a change it had no way of
      confirming, and that the same task will report a change again next time.
  returned: always
  type: list
  elements: str
  sample:
    - token
diff:
  description:
    - The destination as read and the destination it was reconciled to, rendered
      by C(--diff). Both sides are equal when nothing would change, and C(after) is
      what a check run would have written.
    - The write-only options are shown as V((write-only)) rather than left out,
      so that a change involving one is visible in the diff without its value
      reaching a transcript. There is no before value for them to have, because
      the API does not return one.
  returned: always
  type: dict
  contains:
    before:
      description: The destination as the tailnet held it.
      returned: always
      type: dict
    after:
      description: The destination reconciled to.
      returned: always
      type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
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
    "destination_type": "destinationType",
    "url": "url",
    "user": "user",
    "token": "token",
    "upload_period_minutes": "uploadPeriodMinutes",
    "compression_format": "compressionFormat",
    "s3_bucket": "s3Bucket",
    "s3_region": "s3Region",
    "s3_key_prefix": "s3KeyPrefix",
    "s3_authentication_type": "s3AuthenticationType",
    "s3_access_key_id": "s3AccessKeyId",
    "s3_secret_access_key": "s3SecretAccessKey",
    "s3_role_arn": "s3RoleArn",
}

#: The fields the API marks write-only. There is no before value for any of them
#: to differ from, which is what makes a run that gives one unreconcilable.
_WRITE_ONLY = frozenset({"token", "s3SecretAccessKey"})

#: The fields the API marks read-only. They are returned to the operator because
#: they say what the destination serves and which role it authenticates with, and
#: they are not sent back: the description says the server sets them, and a write
#: carrying a read-only field is a field this collection has no business setting.
_READ_ONLY = frozenset({"logType", "s3ExternalId"})

#: API field to module option for the write-only fields, so a task is told which
#: of its own options went unverified rather than which field the API calls it.
_WRITE_ONLY_OPTIONS = {
    "token": "token",
    "s3SecretAccessKey": "s3_secret_access_key",
}

#: What the diff shows in place of a write-only value. Not a redaction marker the
#: collection uses anywhere else, because there is no before value to redact
#: against: the field is absent on one side by construction.
_WRITE_ONLY_PLACEHOLDER = "(write-only)"

#: The fields the module returns. A whitelist rather than the stored document, for
#: two reasons: a field Tailscale adds later is not this module's to promise, and
#: the stored document is where a credential echoed back to it would arrive.
_RETURNED = (
    "logType",
    "destinationType",
    "url",
    "user",
    "uploadPeriodMinutes",
    "compressionFormat",
    "s3Bucket",
    "s3Region",
    "s3KeyPrefix",
    "s3AuthenticationType",
    "s3AccessKeyId",
    "s3RoleArn",
    "s3ExternalId",
)

#: What each S3 authentication type needs beyond the bucket and the region, as
#: the API's description states them. Checked here because a 400 from the API
#: names the missing field without saying which option supplies it.
_S3_REQUIRES = {
    "accesskey": ("s3_access_key_id", "s3_secret_access_key"),
    "rolearn": ("s3_role_arn",),
}

#: The most the API accepts for a delay between uploads, in minutes.
_MAX_UPLOAD_PERIOD = 1440


class StreamingRequestError(Exception):
    """A destination this module refuses to write, and the option at fault.

    A distinct type from the API's own failures because it is this collection
    declining rather than Tailscale refusing, and the message says which option to
    change. Handled identically at the end, because whoever reads the result
    wants the message either way.
    """


ARGUMENT_SPEC = connection_arguments(
    log_type={"type": "str", "required": True, "choices": ["configuration", "network"]},
    state={"type": "str", "choices": ["present", "absent"], "default": "present"},
    destination_type={
        "type": "str",
        "choices": [
            "splunk",
            "elastic",
            "panther",
            "cribl",
            "crowdstrike",
            "datadog",
            "axiom",
            "s3",
        ],
    },
    url={"type": "str"},
    user={"type": "str"},
    token={"type": "str", "no_log": True},
    upload_period_minutes={"type": "int"},
    compression_format={"type": "str", "choices": ["zstd", "gzip", "none"]},
    s3_bucket={"type": "str"},
    s3_region={"type": "str"},
    # Matches the secret-name pattern on "key" and is a path, not a credential.
    s3_key_prefix={"type": "str", "no_log": False},
    s3_authentication_type={"type": "str", "choices": ["accesskey", "rolearn"]},
    s3_access_key_id={"type": "str"},
    s3_secret_access_key={"type": "str", "no_log": True},
    s3_role_arn={"type": "str"},
)


def _check_destination(params: dict) -> None:
    """Refuse a destination the API documents as incomplete, before writing it.

    Each of these is stated in the API's description as required for a particular
    destination rather than enforced by a type, so a task that leaves one out is
    refused by the server with a message naming a field of its own document. The
    option that would satisfy it is more use than that.
    """
    if (params.get("upload_period_minutes") or 0) > _MAX_UPLOAD_PERIOD:
        raise StreamingRequestError(
            f"upload_period_minutes cannot be more than {_MAX_UPLOAD_PERIOD}, which is "
            "a day, and is the maximum the API accepts."
        )
    if params["destination_type"] != "s3":
        return
    for option in ("s3_bucket", "s3_region", "s3_authentication_type"):
        if not params.get(option):
            raise StreamingRequestError(
                f"O(destination_type=s3) needs {option}. The API requires it for an S3 "
                "destination and refuses the write without it."
            )
    for option in _S3_REQUIRES.get(params["s3_authentication_type"], ()):
        if not params.get(option):
            raise StreamingRequestError(
                f"O(s3_authentication_type={params['s3_authentication_type']}) needs "
                f"{option}, which the API requires for that authentication type."
            )


def _wanted(params: dict) -> dict:
    """The API fields for the options the task gave, and only those.

    No option carries a default, so an option left out arrives as None and is
    dropped here. The endpoint replaces the whole destination, so what is not sent
    has to come from what the tailnet already has, which is what
    :func:`desired_destination` builds.
    """
    return {
        field: params[option] for option, field in _FIELDS.items() if params.get(option) is not None
    }


def desired_destination(params: dict, current: dict) -> dict:
    """The destination the tailnet holds, with the task's options applied over it.

    The endpoint replaces the whole destination, so anything the task did not
    mention has to be carried over from what is already there. Sending a default
    instead would silently reset a field the operator never mentioned, and on a
    replace endpoint that is indistinguishable from asking for it.

    A write-only field is the exception, and it is the reason a task changing any
    other field of a destination that has a password has to repeat the password.
    The API never returns one, so the field is absent from what is read and
    dropping it from the write would clear the password the destination is
    authenticating with.
    """
    merged = dict(current)
    for field, value in _wanted(params).items():
        merged[field] = value
    return merged


def _diffable(document: dict) -> dict:
    """A destination with the write-only fields shown as a placeholder.

    Without this a change to a password would be invisible in the diff, and with
    the value in it the credential would reach every transcript that rendered the
    diff. The placeholder is the honest third option: the field is part of the
    change, and the collection cannot show what changed.
    """
    return {
        field: _WRITE_ONLY_PLACEHOLDER if field in _WRITE_ONLY else value
        for field, value in document.items()
    }


def _sendable(document: dict) -> dict:
    """A destination without the fields the API sets for itself.

    The merged destination carries C(logType) and C(s3ExternalId) because the read
    returned them and the operator is shown them. Sending them back would be a
    write of fields the description marks read-only, which is this collection
    asking the server to set something it said it would set.
    """
    return {field: value for field, value in document.items() if field not in _READ_ONLY}


def _projection(document: dict) -> dict:
    """The fields the module returns from a stored destination.

    A whitelist, so that a field Tailscale adds later is not something this
    module has promised, and so that a credential the server echoed back does not
    reach the result. The write-only fields are dropped for the second reason;
    the two the API sets itself are kept, because they say what the destination
    serves and which role it authenticates with.
    """
    return {field: document[field] for field in _RETURNED if field in document}


def _read_destination(api: Api, log_type: str) -> dict:
    """The destination the tailnet holds, or an empty one where it holds none.

    A not-found is a state rather than a failure here, because this endpoint
    documents it as what it answers when log streaming is not configured for the
    log type. It is also the answer for a log type Tailscale does not support and
    for a credential that may not see the destination, and the response does not
    tell those three apart. Creating the destination is then the honest answer to
    a 404, and the write that follows either succeeds or says why not.
    """
    try:
        body = api.call("logging_stream_get", "GET", params={"logType": log_type}).body
    except TailscaleNotFound:
        return {}
    if not isinstance(body, dict):
        raise StreamingRequestError(
            "The streaming destination read back was not a JSON object, so what the "
            "tailnet streams to could not be read. Writing a whole destination over a "
            "document this module could not read would replace it blind."
        )
    return body


def _publishing_status(api: Api, log_type: str) -> dict:
    """What the API reports about publishing to the destination, or an empty one.

    A not-found is normal rather than a failure: the API uses it for a destination
    that is not configured, which is every state=absent run and the first run of a
    tailnet that has none. Anything else propagates, because a status this module
    could not read is not a status it may report as healthy.
    """
    try:
        body = api.call("logging_stream_status_get", "GET", params={"logType": log_type}).body
    except TailscaleNotFound:
        return {}
    return body if isinstance(body, dict) else {}


def run(module: AnsibleModule) -> None:
    log_type = module.params["log_type"]
    try:
        if module.params["state"] == "present":
            _check_destination(module.params)
        api = build_client(module.params)
        current = _read_destination(api, log_type)
        wanted = _wanted(module.params)
        unverified = sorted(_WRITE_ONLY_OPTIONS[field] for field in wanted if field in _WRITE_ONLY)

        if module.params["state"] == "absent":
            if not current:
                module.exit_json(
                    changed=False,
                    stream_configuration={},
                    streaming_status={},
                    unverified_options=[],
                    diff={"before": {}, "after": {}},
                )
            if not module.check_mode:
                api.call("logging_stream_delete", "DELETE", params={"logType": log_type})
            module.exit_json(
                changed=True,
                stream_configuration={},
                streaming_status={},
                unverified_options=[],
                diff={"before": _projection(current), "after": {}},
            )

        desired = desired_destination(module.params, current)
        if not unverified and desired == current:
            module.exit_json(
                changed=False,
                stream_configuration=_projection(current),
                streaming_status=_publishing_status(api, log_type),
                unverified_options=[],
                diff={"before": _projection(current), "after": _projection(current)},
            )
        if not module.check_mode:
            api.call(
                "logging_stream_set",
                "PUT",
                params={"logType": log_type},
                body=_sendable(desired),
            )
        module.exit_json(
            changed=True,
            # What a check run would have written, which is also what the write
            # sent, because the two take the same path.
            stream_configuration=_projection(desired),
            streaming_status=_publishing_status(api, log_type),
            unverified_options=unverified,
            diff={"before": _diffable(current), "after": _diffable(desired)},
        )
    except (StreamingRequestError, CredentialError, TailscaleError) as error:
        module.fail_json(msg=str(error))


def main() -> None:
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        required_together=[("oauth_client_id", "oauth_client_secret")],
        required_if=[["state", "present", ["destination_type"]]],
        mutually_exclusive=[
            ("api_token", "oauth_client_id"),
            ("api_token", "oauth_client_secret"),
        ],
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
