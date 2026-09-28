# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the error-to-instruction mapping in ``_errors.py``."""

from __future__ import annotations

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleApiError,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleAuthError,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleBadRequest,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import TailscaleError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleNotFound,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleNotImplemented,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscalePermissionError,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscalePlanError,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscalePreconditionFailed,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleRateLimited,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import (
    TailscaleServerError,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._errors import from_response

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
POLICY_PATH = "/tailnet/-/acl"
DEVICE_PATH = "/device/nABCD123456CNTRL"
DNS_PATH = "/tailnet/-/dns/configuration"

# Tailscale's own request id format, REQ-<YYYYMMDDHHMMSSmmm><hex>.
REQUEST_ID = "REQ-202609270215431a2b3c4"


def _error(status, method="GET", path=POLICY_PATH, message="", headers=None):
    return from_response(
        status,
        method,
        path,
        upstream_message=message,
        response_headers=headers,
    )


def test_401_asks_for_all_three_credential_failures_to_be_checked() -> None:
    # Tailscale returns "API token invalid" for missing, malformed and expired
    # alike, so repeating the message would name no action at all.
    error = _error(401, message="API token invalid")

    assert isinstance(error, TailscaleAuthError)
    assert "missing, a malformed and an expired credential" in error.message
    assert "API token invalid" in error.message
    assert "has not expired" in error.message


def test_403_names_the_scope_the_operation_needs() -> None:
    error = _error(403, method="POST", path=POLICY_PATH)

    assert isinstance(error, TailscalePermissionError)
    assert "`policy_file`" in error.message


def test_403_on_a_device_mutation_names_the_device_scope_not_the_policy_one() -> None:
    error = _error(403, method="POST", path=f"{DEVICE_PATH}/tags")

    assert "`devices:core`" in error.message
    assert "policy_file" not in error.message


def test_403_says_a_policy_file_scope_also_needs_the_device_scopes() -> None:
    error = _error(403, method="GET", path=POLICY_PATH)

    assert "`devices:posture_attributes:read`" in error.message
    assert "`devices:core:read`" in error.message
    assert "most common reason" in error.message


def test_403_on_a_read_names_the_read_scope_of_the_policy_file() -> None:
    error = _error(403, method="GET", path=POLICY_PATH)

    assert "`policy_file:read`" in error.message


def test_403_explains_that_granting_a_scope_does_not_rescue_an_existing_token() -> None:
    error = _error(403, method="POST", path=POLICY_PATH)

    assert "fixed when it is issued" in error.message
    assert "owning user's role" in error.message


def test_403_quotes_the_reason_the_api_gave() -> None:
    # The API does not always refuse for want of a scope. Creating an OAuth
    # client was refused with this, from a credential holding every permission in
    # the tailnet, and the message then named `auth_keys` as the missing scope,
    # which sent the reader after a permission problem that did not exist.
    error = _error(
        403,
        method="POST",
        path="/tailnet/-/keys",
        message="actor cannot set scopes: [all]",
    )

    assert "actor cannot set scopes: [all]" in error.message


def test_403_with_a_reason_does_not_assert_an_inferred_scope_as_the_cause() -> None:
    error = _error(
        403,
        method="POST",
        path="/tailnet/-/keys",
        message="actor cannot set scopes: [all]",
    )

    assert "It needs the `auth_keys` scope" not in error.message, (
        "the API named a different reason, so inferring one contradicts it"
    )
    assert "The API's reason" in error.message


def test_403_without_a_reason_still_offers_the_inferred_scope() -> None:
    # Dropping the inference entirely would leave a caller with no starting point
    # on the 403s that carry no prose, which is most of them.
    error = _error(403, method="POST", path=POLICY_PATH)

    assert "It most likely needs the `policy_file` scope" in error.message
    assert "The API's reason" not in error.message, (
        "there was no reason to report, so reporting one would be inventing it"
    )


def test_403_on_settings_lists_the_other_scopes_that_gate_the_same_document() -> None:
    error = _error(403, method="GET", path="/tailnet/-/settings")

    assert "`feature_settings:read`" in error.message
    assert "`logs:network:read`" in error.message
    assert "`networking_settings:read`" in error.message
    assert "`policy_file:read`" in error.message


def test_403_on_an_operation_the_table_does_not_know_still_explains_itself() -> None:
    error = _error(403, method="GET", path="/tailnet/-/user-invites")

    assert isinstance(error, TailscalePermissionError)
    assert "not authorised" in error.message
    assert "does not correspond to an operation" in error.message


def test_402_blames_the_plan_and_echoes_which_billing_change_is_needed() -> None:
    error = _error(402, method="POST", path=DEVICE_PATH + "/authorized", message="payment required")

    assert isinstance(error, TailscalePlanError)
    assert "plan or billing state" in error.message
    assert "billing change, not a different request" in error.message
    assert '"payment required"' in error.message


def test_412_reports_a_concurrent_policy_edit_and_names_no_missing_option() -> None:
    error = _error(412, method="POST", path=POLICY_PATH, message="If-Match hash mismatch.")

    assert isinstance(error, TailscalePreconditionFailed)
    assert "changed after this run read it" in error.message
    assert "nothing was applied" in error.message
    assert "Re-run" in error.message
    # No module declares `force`, so the message must not advise it.
    assert "force" not in error.message


def test_a_token_echoed_inside_a_tag_list_is_redacted() -> None:
    """The tag branch embedded upstream text without cleaning it, unlike every other."""
    error = _error(
        400,
        method="POST",
        path="/tailnet/-/device/d1/tags",
        message=(
            'requested tags ["tag:ok", "tskey-api-abcdefghijklmnop"] are invalid or not permitted'
        ),
    )

    assert "tskey-api-abcdefghijklmnop" not in str(error)
    assert "[redacted]" in error.message


def test_a_very_long_tag_list_is_bounded() -> None:
    error = _error(
        400,
        method="POST",
        path="/tailnet/-/device/d1/tags",
        message=f"requested tags [{', '.join(['tag:x' * 40] * 40)}] are invalid or not permitted",
    )

    assert len(error.message) < 1200, "the upstream text is length-capped like every other path"
    assert "truncated" in error.message


def test_429_says_that_no_rate_limits_are_published() -> None:
    error = _error(429, message="too many requests")

    assert isinstance(error, TailscaleRateLimited)
    assert "publishes no rate limits" in error.message
    assert "no backoff interval" in error.message
    assert "wait, then re-run" in error.message


def test_501_on_a_device_delete_blames_a_device_shared_from_another_tailnet() -> None:
    error = _error(501, method="DELETE", path=DEVICE_PATH)

    assert isinstance(error, TailscaleNotImplemented)
    assert "shared into this tailnet from another one" in error.message
    assert "remove it there" in error.message


def test_501_on_anything_else_does_not_claim_a_shared_device() -> None:
    error = _error(501, method="GET", path="/tailnet/-/keys")

    assert isinstance(error, TailscaleNotImplemented)
    assert "does not implement this operation" in error.message
    assert "shared" not in error.message


def test_400_requested_tags_points_at_the_policy_file_tag_owners() -> None:
    upstream = 'requested tags ["tag:prod"] are invalid or not permitted'

    error = _error(400, method="POST", path=f"{DEVICE_PATH}/tags", message=upstream)

    assert isinstance(error, TailscaleBadRequest)
    assert '["tag:prod"]' in error.message
    assert "`tagOwners`" in error.message


def test_400_requested_tags_still_names_the_policy_when_the_list_is_absent() -> None:
    upstream = "requested tags are invalid or not permitted"

    error = _error(400, method="POST", path=f"{DEVICE_PATH}/tags", message=upstream)

    assert "`tagOwners`" in error.message


def test_400_taking_the_last_tag_off_says_the_device_has_to_re_authenticate() -> None:
    """Measured against the API: a tagged node cannot be untagged, so a task asking
    for an empty tag list is a failure and not a change."""
    upstream = "tagged nodes cannot be untagged without reauth"

    error = _error(400, method="POST", path=f"{DEVICE_PATH}/tags", message=upstream)

    assert isinstance(error, TailscaleBadRequest)
    assert "re-authenticate" in error.message
    assert "`tagOwners`" not in error.message, "the policy is not what has to change here"


def test_400_a_device_name_already_taken_names_the_name_and_says_why() -> None:
    upstream = 'name "build-host" is already taken'

    error = _error(400, method="POST", path=f"{DEVICE_PATH}/name", message=upstream)

    assert isinstance(error, TailscaleBadRequest)
    assert "build-host" in error.message
    assert "already taken" in error.message


def test_400_capability_scope_is_diagnosed_as_a_body_problem_not_a_permissions_one() -> None:
    upstream = "exactly one capability scope must be populated"

    error = _error(400, method="POST", path=POLICY_PATH, message=upstream)

    assert isinstance(error, TailscaleBadRequest)
    assert "malformed request body" in error.message
    assert "application/hujson" in error.message
    assert "application/json" in error.message
    assert "permission" in error.message


def test_400_magic_dns_without_a_nameserver_says_so() -> None:
    upstream = "need at least one nameserver to enable MagicDNS"

    error = _error(400, method="POST", path=DNS_PATH, message=upstream)

    assert isinstance(error, TailscaleBadRequest)
    assert "MagicDNS is enabled while the nameserver list is empty" in error.message
    assert "turn MagicDNS off" in error.message


def test_400_without_a_known_signature_quotes_the_api_instead_of_guessing() -> None:
    error = _error(400, method="POST", path=POLICY_PATH, message="unexpected end of input")

    assert isinstance(error, TailscaleBadRequest)
    assert "no specific remedy" in error.message
    assert '"unexpected end of input"' in error.message


def test_400_with_no_message_at_all_says_so_plainly() -> None:
    error = _error(400, method="POST", path=POLICY_PATH)

    assert isinstance(error, TailscaleBadRequest)
    assert "The API returned no message." in error.message


def test_404_names_the_ephemeral_device_race_as_an_ordinary_cause() -> None:
    error = _error(404, method="DELETE", path=DEVICE_PATH, message="not found")

    assert isinstance(error, TailscaleNotFound)
    assert "ephemeral device" in error.message
    assert "normal race" in error.message
    assert "not found" not in error.message.lower().replace("does not", "")


def test_a_5xx_is_a_server_failure_not_a_bad_request() -> None:
    error = _error(503)

    assert isinstance(error, TailscaleServerError)
    assert "server-side failure" in error.message
    assert "no change to the playbook will fix it" in error.message


def test_an_unmapped_status_names_the_status_and_the_api_message() -> None:
    error = _error(418, message="I am a teapot")

    assert isinstance(error, TailscaleApiError)
    assert "HTTP 418" in error.message
    assert "no specific remedy" in error.message
    assert '"I am a teapot"' in error.message


def test_an_unmapped_status_is_never_a_bare_status_code() -> None:
    error = _error(451)

    rendered = str(error)

    assert "451" in rendered
    assert len(error.message) > len("451")


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (400, TailscaleBadRequest),
        (401, TailscaleAuthError),
        (402, TailscalePlanError),
        (403, TailscalePermissionError),
        (404, TailscaleNotFound),
        (412, TailscalePreconditionFailed),
        (429, TailscaleRateLimited),
        (500, TailscaleServerError),
        (501, TailscaleNotImplemented),
        (502, TailscaleServerError),
        (504, TailscaleServerError),
        (409, TailscaleApiError),
        (422, TailscaleApiError),
    ],
)
def test_each_status_family_has_its_own_exception_type(status, expected) -> None:
    error = _error(status)

    # __class__, not type(): this asserts the exact family, where isinstance
    # would also accept a subclass, and pylint's C0123 rejects a type() check.
    assert error.__class__ is expected
    assert isinstance(error, TailscaleError)


def test_every_mapped_status_carries_its_own_status_code() -> None:
    statuses = [400, 401, 402, 403, 404, 412, 429, 500, 501, 502, 504, 418]

    assert [_error(status).status for status in statuses] == statuses


def test_the_request_id_is_surfaced_under_any_spelling_of_the_header() -> None:
    for name in ("x-tailscale-request-id", "X-Tailscale-Request-Id", "X-TAILSCALE-REQUEST-ID"):
        error = _error(500, headers={name: REQUEST_ID})

        assert error.request_id == REQUEST_ID, name
        assert f"tailscale request id: {REQUEST_ID}" in str(error)


def test_a_missing_request_id_is_simply_omitted() -> None:
    error = _error(500, headers={"content-type": "application/json"})

    assert error.request_id is None
    assert "request id" not in str(error)
    assert "request:" in str(error)


def test_the_request_line_is_always_rendered() -> None:
    error = _error(400, method="post", path=POLICY_PATH + "?details=1")

    assert error.method == "POST"
    assert error.path == POLICY_PATH
    assert f"  request: POST {POLICY_PATH}" in str(error)


def test_a_token_in_the_upstream_message_is_redacted() -> None:
    upstream = f"invalid credential {TOKEN} for this tailnet"

    error = _error(401, message=upstream)

    assert TOKEN not in str(error)
    assert "[redacted]" in error.message
    assert "for this tailnet" in error.message


def test_a_token_in_the_request_path_is_redacted() -> None:
    error = from_response(400, "GET", f"/tailnet/-/acl?token={TOKEN}")

    assert TOKEN not in str(error)
    assert TOKEN not in error.path


def test_no_request_header_reaches_the_message() -> None:
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "If-Match": '"e0b2816b418"',
        "Content-Type": "application/hujson",
        "x-tailscale-request-id": REQUEST_ID,
    }

    error = _error(403, method="POST", path=POLICY_PATH, headers=headers)
    rendered = str(error)

    assert TOKEN not in rendered
    assert "Authorization" not in rendered
    assert "If-Match" not in rendered
    assert "e0b2816b418" not in rendered


def test_a_whole_header_echo_inside_the_upstream_message_is_stripped() -> None:
    # The marker exists only in the upstream body, so finding it proves the
    # upstream was echoed. Asserting on a word the prose also uses would pass
    # whether or not the echo happened.
    upstream = f'{{"Authorization": "Bearer {TOKEN}"}} upstream-marker'

    error = _error(401, message=upstream)

    assert TOKEN not in str(error)
    assert "upstream-marker" in error.message


def test_a_basic_auth_credential_in_the_upstream_message_is_stripped() -> None:
    upstream = "Authorization: Basic ZGV2ZWxvcGU6cGFzc3dvcmQ="

    error = _error(401, message=upstream)

    assert "ZGV2ZWxvcGU6cGFzc3dvcmQ=" not in str(error)
    assert "[redacted]" in error.message


def test_newlines_in_the_upstream_message_cannot_forge_extra_log_lines() -> None:
    upstream = "bad request\nfatal: task FAILED on host secret-box"

    error = _error(400, message=upstream)

    assert "\n" not in error.message
    assert "fatal: task FAILED on host secret-box" in error.message


def test_an_over_long_upstream_message_is_truncated() -> None:
    error = _error(400, message="x" * 5000)

    assert error.message.endswith("(truncated)")
    assert len(error.message) < 600


def test_the_exception_never_carries_a_header_mapping_or_a_body() -> None:
    headers = {"Authorization": f"Bearer {TOKEN}"}
    error = _error(401, message="API token invalid", headers=headers)

    for attribute in vars(error):
        assert attribute in {"message", "status", "method", "path", "request_id"}

    assert "data" not in vars(error)
    assert "headers" not in vars(error)
    assert "body" not in vars(error)


def test_a_caller_can_fail_the_task_with_the_string_form_alone() -> None:
    error = _error(
        403, method="POST", path=POLICY_PATH, headers={"x-tailscale-request-id": REQUEST_ID}
    )
    fail_json_kwargs = {"msg": str(error)}

    assert fail_json_kwargs["msg"].startswith("The Tailscale API refused the request")
    assert "  request: POST /tailnet/-/acl" in fail_json_kwargs["msg"]
    assert REQUEST_ID in fail_json_kwargs["msg"]


def test_a_403_naming_the_billing_plan_is_a_billing_answer_and_not_a_scope_one() -> None:
    """The status is the one used for a missing scope, and the two need opposite advice.

    Measured against a free plan: the network flow log read and every endpoint of
    the log streaming family answer 403 with "feature not available on current
    billing plan". Answering that with scope advice sends the operator to re-mint
    a credential that is already correct.
    """
    path = "/tailnet/-/logging/network/stream"
    error = _error(
        403, method="GET", path=path, message="feature not available on current billing plan"
    )

    assert "billing state does not allow" in error.message
    assert "feature not available on current billing plan" in error.message
    assert "scope" not in error.message
    assert "`log_streaming:read`" not in error.message


def test_a_403_that_names_no_plan_still_names_the_scope() -> None:
    """The branch is on the upstream wording, not on the status."""
    error = _error(403, method="GET", path="/tailnet/-/logging/network")

    assert isinstance(error, TailscalePermissionError)
    assert "`logs:network:read`" in error.message


def test_a_402_is_still_the_plan_answer_it_always_was() -> None:
    error = _error(402, method="GET", path=POLICY_PATH, message="payment required")

    assert "billing state does not allow" in error.message
