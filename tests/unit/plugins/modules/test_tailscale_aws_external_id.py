# SPDX-License-Identifier: BSD-2-Clause
"""Tests for the tailscale_aws_external_id module, driven through the harness.

The module is a read over a create-or-get endpoint, so most of what is load
bearing is which request it makes and what it refuses to claim. It must ask for a
reusable id or every run mints a new one, it must never report a change, and a
trust policy the server could not assume must arrive as a verdict rather than a
task failure.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.modules import tailscale_aws_external_id

TOKEN = "tskey-api-abcdefghijklmnopqrstuvwxyz012345"
BASE = "https://api.tailscale.com/api/v2"

EXTERNAL_ID = "60fe9ce7-7791-4ab3-ab34-4294f5972725"
ACCOUNT_ID = "001234567890"
ROLE_ARN = "arn:aws:iam::123456789012:role/tailscale-log-writer"

_DOCUMENT = {"externalId": EXTERNAL_ID, "tailscaleAwsAccountId": ACCOUNT_ID}

_API_URL = "ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api.open_url"


class Body:
    def __init__(self, text: str) -> None:
        self._text = text

    def decode(self, *args: str) -> str:
        return self._text


def _reply(status: int, text: str) -> Any:
    class Response:
        def __init__(self) -> None:
            self.status = status
            self.headers: dict[str, str] = {}

        def read(self) -> Body:
            return Body(text)

    return Response()


def _answer(document: Any) -> Any:
    if isinstance(document, tuple):
        return _reply(document[0], document[1])
    return _reply(200, json.dumps(document))


class Tailnet:
    """A tailnet answering the two operations from canned documents."""

    def __init__(
        self,
        external: Any = None,
        validate: Any = None,
    ) -> None:
        self.external = external if external is not None else _DOCUMENT
        self.validate = validate if validate is not None else {}
        self.requests: list[tuple[str, str, Any]] = []

    def __call__(
        self, url: str, data: Any = None, headers: Any = None, method: str = "GET", **kwargs: Any
    ) -> Any:
        self.requests.append((method, url, data))
        if "validate-aws-trust-policy" in url:
            return _answer(self.validate)
        return _answer(self.external)

    def bodies(self) -> list[Any]:
        return [
            json.loads(request[2]) if isinstance(request[2], str) else None
            for request in self.requests
        ]


@pytest.fixture
def server(mocker: Any) -> Tailnet:
    tailnet = Tailnet()
    mocker.patch(_API_URL, tailnet)
    return tailnet


def _options(**extra: Any) -> dict[str, Any]:
    return {"api_token": TOKEN, **extra}


def test_the_external_id_and_account_are_returned(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options())

    with module_result.success() as result:
        tailscale_aws_external_id.main()

    assert result["external_id"] == EXTERNAL_ID
    assert result["tailscale_aws_account_id"] == ACCOUNT_ID
    assert result["validation"] == {}


def test_the_read_is_the_create_or_get_operation(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options())

    with module_result.success():
        tailscale_aws_external_id.main()

    request = server.requests[0]
    assert request[0] == "POST"
    assert request[1] == f"{BASE}/tailnet/-/aws-external-id"


def test_the_read_asks_for_a_reusable_id(module_args: Any, module_result: Any, server: Any) -> None:
    """Without the marker the API mints a new id on every run, which is not a read."""
    module_args(_options())

    with module_result.success():
        tailscale_aws_external_id.main()

    assert server.bodies() == [{"reusable": True}]


def test_the_same_id_comes_back_and_no_run_reports_a_change(
    module_args: Any, module_result: Any, server: Any
) -> None:
    options = _options()

    module_args(options)
    with module_result.success() as first:
        tailscale_aws_external_id.main()
    module_args(options)
    with module_result.success() as second:
        tailscale_aws_external_id.main()

    assert first["changed"] is False
    assert second["changed"] is False
    assert first["external_id"] == second["external_id"] == EXTERNAL_ID


def test_no_diff_is_returned(module_args: Any, module_result: Any, server: Any) -> None:
    """There is one state to read and nothing to reconcile it against."""
    module_args(_options())

    with module_result.success() as result:
        tailscale_aws_external_id.main()

    assert "diff" not in result


def test_check_mode_reads_and_reports_no_change(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options(), check_mode=True)

    with module_result.success() as result:
        tailscale_aws_external_id.main()

    assert result["changed"] is False
    assert result["external_id"] == EXTERNAL_ID
    assert len(server.requests) == 1, "a read has nothing for check mode to hold back"


def test_the_tailnet_is_addressed_by_name_when_given(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options(tailnet="-1234567890123"))

    with module_result.success():
        tailscale_aws_external_id.main()

    assert server.requests[0][1] == f"{BASE}/tailnet/-1234567890123/aws-external-id"


def test_the_validator_is_not_called_without_a_role(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options())

    with module_result.success():
        tailscale_aws_external_id.main()

    assert len(server.requests) == 1, "no role was given, so nothing was validated"


def test_a_role_is_validated_and_a_pass_is_reported(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options(role_arn=ROLE_ARN))

    with module_result.success() as result:
        tailscale_aws_external_id.main()

    assert result["changed"] is False
    assert result["validation"] == {"role_arn": ROLE_ARN, "valid": True, "message": ""}
    method, url, data = server.requests[1]
    assert method == "POST"
    assert url == f"{BASE}/tailnet/-/aws-external-id/{EXTERNAL_ID}/validate-aws-trust-policy"
    assert json.loads(data) == {"roleArn": ROLE_ARN}


def test_a_trust_policy_that_does_not_allow_tailscale_is_a_verdict(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """A 422 is the server's answer to the question the task asked, not a failure."""
    mocker.patch(
        _API_URL,
        Tailnet(
            validate=(
                422,
                json.dumps(
                    {
                        "message": "Tailscale was unable to assume the given role. "
                        "Please ensure your trust policy allows our account."
                    }
                ),
            )
        ),
    )
    module_args(_options(role_arn=ROLE_ARN))

    with module_result.success() as result:
        tailscale_aws_external_id.main()

    assert result["changed"] is False
    assert result["validation"]["role_arn"] == ROLE_ARN
    assert result["validation"]["valid"] is False
    assert "unable to assume the given role" in result["validation"]["message"]


def test_a_verdict_names_the_server_reason_without_a_traceback(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    mocker.patch(
        _API_URL,
        Tailnet(validate=(422, json.dumps({"message": "trust policy does not require the id"}))),
    )
    module_args(_options(role_arn=ROLE_ARN))

    with module_result.success() as result:
        tailscale_aws_external_id.main()

    assert "trust policy does not require the id" in result["validation"]["message"]
    assert "Traceback" not in result["validation"]["message"]


def test_a_failure_that_is_not_the_verdict_still_fails_the_task(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """Only 422 is the verdict; a server failure is about the request, not the policy."""
    mocker.patch(
        _API_URL,
        Tailnet(validate=(500, json.dumps({"message": "internal error"}))),
    )
    module_args(_options(role_arn=ROLE_ARN))

    with module_result.failure() as result:
        tailscale_aws_external_id.main()

    assert "failed to serve the request" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_an_empty_role_arn_is_refused_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options(role_arn="   "))

    with module_result.failure() as result:
        tailscale_aws_external_id.main()

    assert "role_arn" in result["msg"]
    assert server.requests == [], "and it cost no request"


def test_a_read_without_an_external_id_fails(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    """An empty id would configure an IAM role against nothing."""
    mocker.patch(_API_URL, Tailnet(external={"tailscaleAwsAccountId": ACCOUNT_ID}))
    module_args(_options())

    with module_result.failure() as result:
        tailscale_aws_external_id.main()

    assert "without an external id" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_a_read_that_is_not_a_document_fails(
    module_args: Any, module_result: Any, mocker: Any
) -> None:
    mocker.patch(_API_URL, Tailnet(external=(200, "<html>gateway timeout</html>")))
    module_args(_options())

    with module_result.failure() as result:
        tailscale_aws_external_id.main()

    assert "without an external id" in result["msg"]


def test_a_missing_credential_fails_before_any_request(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args({})

    with module_result.failure() as result:
        tailscale_aws_external_id.main()

    assert "api_token" in result["msg"]
    assert server.requests == []


def test_a_credential_never_reaches_the_result(
    module_args: Any, module_result: Any, server: Any
) -> None:
    module_args(_options(role_arn=ROLE_ARN))

    with module_result.success() as result:
        tailscale_aws_external_id.main()

    assert TOKEN not in json.dumps(result, default=str)
