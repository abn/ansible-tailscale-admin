#!/usr/bin/python
# Copyright (c) 2026, Arun Babu Neelicattu <github.com/abn>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: tailscale_logs
short_description: Read a window of a tailnet's logs
version_added: 0.1.0
description:
  - Reads the log entries a tailnet recorded over a time window and returns them
    as they stand. This is a read, not a resource. There is nothing to reconcile,
    nothing to create and nothing to delete, so the module always reports
    C(changed=False) and has no C(state).
  - A window is part of the request rather than part of the tailnet's
    configuration. Two runs a second apart ask for different windows and so
    return different entries, which is not drift and is never reported as a
    change. Reconciling a log would mean comparing two windows that share no
    entries, so the collection does not pretend to do it.
  - The entries are evidence, not configuration, and are returned unaltered. An
    audit entry carries whatever the changed property was, and Tailscale adds
    fields to them, so projecting a fixed shape would drop information an
    operator reading the log needs.
  - The whole window is returned. A wide window over a busy tailnet produces a
    large result, so narrow the window or use the filters when only part of it
    matters, and use C(log_count) when only the number of entries does.
  - The two log types are separate endpoints with separate scopes, so
    C(log_type) chooses between them rather than filtering one of them. The
    filters apply to configuration logs only, and the module refuses rather than
    sending one the API would ignore.
  - Enabling network flow logging is a tailnet setting rather than this module's
    business, and Tailscale refuses the read on a plan that does not include it.
    That refusal is a billing answer and it reaches the operator as one.
author:
  - Arun Babu Neelicattu (@abn)
extends_documentation_fragment:
  - abn.tailscale._auth
  - abn.tailscale._attributes.connection_delegation
options:
  log_type:
    description:
      - Which of the tailnet's logs to read.
      - C(configuration) is the audit log of changes made through the admin
        console and the API. C(network) is the network flow log, which records
        what the tailnet's devices connected to.
      - The two are different endpoints with different scopes, so this option
        selects one rather than narrowing the other. See
        L(authentication.md, the authentication guide) for the scope each needs.
    type: str
    required: true
    choices:
      - configuration
      - network
    version_added: 0.1.0
  start:
    description:
      - The beginning of the window, as a timestamp in RFC 3339, for example
        C(2026-09-27T10:45:46Z).
      - The API accepts a C(Z) suffix or a numeric offset such as
        C(+02:00), and rejects a date on its own, a timestamp with no offset and
        anything it cannot parse. The module refuses a value it can tell is not a
        timestamp before making a request, and sends the rest for the API to
        judge.
      - A C(+) inside a query string means a space unless it is encoded, so a
        timestamp carrying a positive offset is percent-encoded here. Without
        that, the API would report a value the task never wrote.
    type: str
    required: true
    version_added: 0.1.0
  end:
    description:
      - The end of the window, in the same form as O(start).
      - The API does not block while it waits for the window to close, so an
        C(end) past the newest entry returns what exists rather than waiting for
        the rest of it.
      - An C(end) earlier than O(start) is not refused. The window is empty and
        the module reports no entries.
    type: str
    required: true
    version_added: 0.1.0
  actor:
    description:
      - Return only entries whose actor matches, as a list so that any one of
        several actors is enough.
      - An entry is kept when any one of the given values matches. A value
        beginning with a tilde is a wildcard search over the actor's login name
        and display name, and a value without one is an exact actor ID.
      - Configuration logs only. Refused with C(log_type=network), which has no
        actor to filter on.
    type: list
    elements: str
    version_added: 0.1.0
  target:
    description:
      - Return only entries whose target matches any part of any of the given
        strings, as a list.
      - Configuration logs only. Refused with C(log_type=network), which has no
        target to filter on.
    type: list
    elements: str
    version_added: 0.1.0
  event:
    description:
      - Return only entries for the given events, as a list, where a value is an
        event name such as C(API_KEY.CREATE).
      - An event the API does not recognise is refused with a 400 naming it, so a
        task naming an event Tailscale has withdrawn fails rather than quietly
        returning nothing.
      - Configuration logs only. Refused with C(log_type=network), which has no
        events to filter on.
    type: list
    elements: str
    version_added: 0.1.0
attributes:
  check_mode:
    description: >-
      The module only reads, so a check run reads and returns the same result as
      a real one. There is no write for check mode to hold back.
    support: full
  diff_mode:
    description: >-
      The module returns no diff. Two reads of the same tailnet over a window
      that has moved describe the passing of time rather than a change this
      module made, and rendering the difference between two sets of log entries
      as a diff would read as configuration drift.
    support: none
"""

EXAMPLES = r"""
- name: Read the audit log for the last hour
  abn.tailscale.tailscale_logs:
    oauth_client_id: "{{ tailscale_oauth_client_id }}"
    oauth_client_secret: "{{ tailscale_oauth_client_secret }}"
    log_type: configuration
    start: "{{ '%Y-%m-%dT%H:%M:%SZ' | strftime((ansible_date_time.epoch | int) - 3600) }}"
    end: "{{ '%Y-%m-%dT%H:%M:%SZ' | strftime(ansible_date_time.epoch | int) }}"
  register: recent_changes

- name: Count the credential changes in that window rather than reading them all
  ansible.builtin.debug:
    var: recent_changes.log_count

- name: Fail if anything created a key in the last day
  ansible.builtin.assert:
    that:
      - recent_changes.logs | selectattr('action', 'equalto', 'CREATE') | list | length == 0
    fail_msg: A credential was created in the last day

- name: Read the network flow log
  abn.tailscale.tailscale_logs:
    api_token: "{{ tailscale_api_token }}"
    log_type: network
    start: "2026-09-27T00:00:00Z"
    end: "2026-09-27T01:00:00Z"

- name: Read only the events an operator cares about
  abn.tailscale.tailscale_logs:
    api_token: "{{ tailscale_api_token }}"
    log_type: configuration
    start: "2026-09-20T00:00:00Z"
    end: "2026-09-27T00:00:00Z"
    event:
      - API_KEY.CREATE
      - API_KEY.REVOKE
"""

RETURN = r"""
logs:
  description:
    - The entries the API returned for the window, in the order it returned them,
      which is chronological. Empty when the window holds no entries.
    - The entries are the API's own documents, unaltered. An entry's C(old) and
      C(new) values carry whatever the changed property was, so their shape
      depends on the event.
    - An entry names its actor, which for a change made through the API is the
      OAuth client or the user the credential belongs to. A client id is not a
      secret and is not redacted, so a window in which this collection acted
      carries it.
  returned: always
  type: list
  elements: dict
  sample:
    - eventTime: "2026-09-27T10:45:46.89873924Z"
      type: CONFIG
      origin: CONFIG_API
      action: CREATE
      actor:
        id: kABCD123456CNTRL
        type: OAUTH_CLIENT
      target:
        id: kEFGH789012CNTRL
        type: API_KEY
log_count:
  description:
    - How many entries the window held, which is the cheap answer when the entries
      themselves are not wanted.
  returned: always
  type: int
  sample: 58
window:
  description:
    - The window that was asked for, as it was given. The entries are what fell
      inside it, and the API does not widen a window to a round unit, so this is
      the only place the exact boundaries appear.
  returned: always
  type: dict
  contains:
    start:
      description: The start of the window, as the task gave it.
      returned: always
      type: str
      sample: "2026-09-27T10:45:46Z"
    end:
      description: The end of the window, as the task gave it.
      returned: always
      type: str
      sample: "2026-09-27T10:45:48Z"
log_version:
  description:
    - The version of the response format, which the configuration audit log
      carries and the network flow log does not. It is empty for a flow log
      rather than absent, so a task reading it does not have to handle a missing
      key.
  returned: always
  type: str
  sample: "1.1"
"""

from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._auth import CredentialError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import build_client
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._module import (
    connection_arguments,
)

#: Module option to the operation that serves it. Two endpoints rather than one
#: with a filter, because the API authorises them separately: a credential allowed
#: to read the audit log is not thereby allowed to read the flow logs.
_OPERATIONS = {
    "configuration": "logging_configuration_get",
    "network": "logging_network_get",
}

#: The filters the configuration endpoint declares. The network endpoint declares
#: only the window, and a filter sent to it is not an error, it is a parameter the
#: server has no meaning for.
_FILTERS = ("actor", "target", "event")

#: What the API's own example of a timestamp looks like, quoted in the refusal so
#: that the operator has something to copy rather than a rule to look up.
_TIMESTAMP_SHAPE = "2026-09-27T10:45:46Z"


class LogRequestError(Exception):
    """A request this module refuses to make, or a response it refuses to read.

    A distinct type from the API's own failures because it is this collection
    declining rather than Tailscale refusing, and the message says so. The two are
    handled identically at the end, because whoever reads the result wants the
    message either way.
    """


ARGUMENT_SPEC = connection_arguments(
    log_type={"type": "str", "required": True, "choices": sorted(_OPERATIONS)},
    start={"type": "str", "required": True},
    end={"type": "str", "required": True},
    actor={"type": "list", "elements": "str"},
    target={"type": "list", "elements": "str"},
    event={"type": "list", "elements": "str"},
)


def _is_timestamp(value: str) -> bool:
    """Whether the value is a timestamp this module can tell is plausible.

    Deliberately permissive. The API has the final word on a value's exact
    spelling, and a module that refused a timestamp the API would have accepted
    would be a false refusal the operator cannot work around. What is caught here
    is the opposite case: a value that is not a timestamp at all, and a bare
    date, which is the mistake worth naming before a request is made.

    A missing offset is not caught. RFC 3339 asks for one and the API insists on
    it, but recognising that needs the API's parser rather than this one, and its
    own message already names the value it rejected.
    """
    if "T" not in value:
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


def _check_window(params: dict) -> None:
    """Refuse a request the API would only reject, before any request is made.

    Check mode reports this too, which is the point: a check run that cannot tell
    a bad window from a good one is a check run that has to be repeated for real
    to find out.
    """
    for option in ("start", "end"):
        if not _is_timestamp(params[option]):
            raise LogRequestError(
                f"The {option} option is not a timestamp the API can use: "
                f"{params[option]!r}. Give it in RFC 3339, such as "
                f"{_TIMESTAMP_SHAPE}, which is a UTC instant. The API accepts a "
                "numeric offset in place of the Z, and refuses a date on its own "
                "and a timestamp with no offset."
            )
    given = [name for name in _FILTERS if params.get(name)]
    if given and params["log_type"] != "configuration":
        raise LogRequestError(
            f"{', '.join(given)} filters the configuration audit log, and a "
            f"{params['log_type']} log has no such filter. Either drop them or read "
            "the configuration log. The API takes a parameter it has no meaning for "
            "without complaining, so a task asking for a filtered flow log would "
            "otherwise get the whole window and read as though the filter had worked."
        )


def _query_of(params: dict) -> dict[str, str | list[str]]:
    """The filters as the API's query parameters.

    Only the ones the task gave, and an empty list is left out rather than sent
    empty: the API reads a repeated parameter as one element, and sending none is
    the same as asking for no filter at all.
    """
    query: dict[str, str | list[str]] = {"start": params["start"], "end": params["end"]}
    for name in _FILTERS:
        values = params.get(name)
        if values:
            query[name] = list(values)
    return query


def _entries_of(body: object) -> list[dict]:
    """The entries in a response body, refusing one that is not a log document.

    A window holding nothing answers with a null list rather than an empty one,
    measured, so the null becomes an empty list here: the result promises a list
    and a task iterating it should not have to handle null.

    A body that is not an object at all is a different matter, and it fails.
    Treating it as an empty window would tell the operator the tailnet recorded
    nothing, which is a claim about the tailnet made from a response that never
    described it. A proxy error page answering 200 is enough to produce one.
    """
    if not isinstance(body, dict):
        raise LogRequestError(
            "The log read answered with something other than a JSON object, so its "
            "entries cannot be told from a response that never described the "
            "tailnet's logs. Reporting an empty window here would be a claim about "
            "the tailnet built from a document that does not support it."
        )
    entries = body.get("logs")
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise LogRequestError(
            "The log read answered with a `logs` field that is not a list, so the "
            "entries are not in the shape the API documents. Nothing was returned "
            "rather than a list of values of unknown meaning."
        )
    return entries


def run(module: AnsibleModule) -> None:
    try:
        _check_window(module.params)
        api = build_client(module.params)
        body = api.call(
            _OPERATIONS[module.params["log_type"]],
            "GET",
            query=_query_of(module.params),
        ).body
        entries = _entries_of(body)
    except (LogRequestError, CredentialError, TailscaleError) as error:
        module.fail_json(msg=str(error))

    module.exit_json(
        # A read has nothing to change. Reporting anything else would make every
        # run of a log task look like a mutation of the tailnet.
        changed=False,
        logs=entries,
        log_count=len(entries),
        window={"start": module.params["start"], "end": module.params["end"]},
        # Empty rather than absent for a flow log, because that response carries
        # no version field and a task reading the key should not have to ask
        # whether it was there.
        log_version=str(body.get("version", "")),
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
