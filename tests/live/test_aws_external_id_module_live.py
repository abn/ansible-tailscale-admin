# SPDX-License-Identifier: BSD-2-Clause
"""The AWS external id module against a real tailnet, through the module.

There is no delete for this family, so the suite leaves exactly what the module
leaves: one reusable external id on a throwaway tailnet. It asserts that the id is
stable across runs, that it is the id the API holds, and that the trust-policy
validator's verdict arrives as a return value rather than a task failure.

The validator's passing branch needs an IAM role that trusts Tailscale's account
with this external id, which cannot exist without an AWS account, so only the
failing branch is exercised here. The passing branch is covered by the unit suite
against a canned 200.
"""

from __future__ import annotations

from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.modules import tailscale_aws_external_id

pytestmark = pytest.mark.live_smoke

#: A role ARN in the required shape that names no role in any account. Tailscale
#: answers 422 for it, which is the verdict branch this suite can reach.
MISSING_ROLE = "arn:aws:iam::000000000000:role/ac-stress-does-not-exist"


def _read(
    module_args: Any,
    module_result: Any,
    credentials: dict[str, str],
    *,
    check_mode: bool = False,
    **options: Any,
) -> dict[str, Any]:
    module_args({**credentials, **options}, check_mode=check_mode)
    with module_result.success() as result:
        tailscale_aws_external_id.main()
    return dict(result)


def _refusal(
    module_args: Any, module_result: Any, credentials: dict[str, str], **options: Any
) -> str:
    module_args({**credentials, **options})
    with module_result.failure() as result:
        tailscale_aws_external_id.main()
    return str(result["msg"])


def test_the_external_id_is_stable_across_runs(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """The property the reusable marker exists for: a second run is quiet."""
    first = _read(module_args, module_result, credentials)
    second = _read(module_args, module_result, credentials)

    assert first["changed"] is False, "the family has no resource to reconcile"
    assert second["changed"] is False
    assert first["external_id"], "a tailnet that can stream has an external id"
    assert first["tailscale_aws_account_id"], "and the account Tailscale presents from"
    assert first["external_id"] == second["external_id"], (
        "the same reusable id comes back, so no run mints a new one"
    )
    assert first["tailscale_aws_account_id"] == second["tailscale_aws_account_id"]


def test_the_module_returns_the_id_the_api_holds(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
) -> None:
    """Read back through the kernel, so a canned id could not pass."""
    result = _read(module_args, module_result, credentials)
    body = api.call("aws_external_id_get", "POST", body={"reusable": True}).body
    devices = api.call("device_list", "GET").body
    listed = devices.get("devices", devices) if isinstance(devices, dict) else []

    print(
        f"\n  tailnet holds: externalId={body.get('externalId')!r} "
        f"tailscaleAwsAccountId={body.get('tailscaleAwsAccountId')!r} "
        f"devices={len(listed or [])}"
    )
    assert body["externalId"] == result["external_id"]
    assert body["tailscaleAwsAccountId"] == result["tailscale_aws_account_id"]


def test_a_run_without_a_role_validates_nothing(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    result = _read(module_args, module_result, credentials)

    assert result["validation"] == {}, "no role was given, so no verdict was asked for"


def test_a_role_tailscale_cannot_assume_is_a_verdict_not_a_failure(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """The validator answers 422, and the module returns it rather than failing."""
    result = _read(module_args, module_result, credentials, role_arn=MISSING_ROLE)

    assert result["changed"] is False
    validation = result["validation"]
    assert validation["role_arn"] == MISSING_ROLE
    assert validation["valid"] is False
    assert validation["message"], "the server names the reason it could not assume the role"
    assert "Tailscale was unable to assume the given role" in validation["message"]
    assert "Traceback" not in validation["message"]
    assert result["external_id"], "the module read an id before validating"
    assert (
        result["external_id"] in validation["message"]
        or result["tailscale_aws_account_id"] in validation["message"]
    ), "the reason names the account or the id it tried to assume with"


def test_check_mode_reads_the_same_id(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    real = _read(module_args, module_result, credentials)
    checked = _read(module_args, module_result, credentials, check_mode=True)

    assert checked["changed"] is False
    assert checked["external_id"] == real["external_id"]


def test_an_empty_role_arn_is_refused_without_a_request(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    message = _refusal(module_args, module_result, credentials, role_arn="   ")

    assert "role_arn" in message
    assert "Traceback" not in message


def test_no_credential_reaches_the_result(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    result = _read(module_args, module_result, credentials, role_arn=MISSING_ROLE)

    assert credentials["oauth_client_secret"] not in str(result)


def test_a_refused_credential_reaches_the_operator_without_echoing_it(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    message = _refusal(
        module_args,
        module_result,
        {**credentials, "oauth_client_secret": "not-the-secret"},
    )

    assert "401" in message
    assert "Traceback" not in message
    assert "not-the-secret" not in message
    assert credentials["oauth_client_id"] not in message
