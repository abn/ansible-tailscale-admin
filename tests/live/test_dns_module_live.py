# SPDX-License-Identifier: BSD-2-Clause
"""`tailscale_dns` against a real tailnet, through the module.

Every assertion drives the module's ``main()``, never the kernel.

The endpoint replaces the whole document, which is the property that makes this
module the dangerous one. A test that changes it must restore it, and the
``preserved`` fixture does that in a ``finally`` so a failed assertion cannot
leave the tailnet without resolvers.
"""

from __future__ import annotations

import json
from typing import Any
from typing import ClassVar

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._api import Api
from ansible_collections.abn.tailscale.plugins.modules import tailscale_dns

pytestmark = pytest.mark.live_smoke

#: A syntactically valid API token, for the one test that must not go through the
#: OAuth exchange because the exchange uses the same patched transport.
_TOKEN = "tskey-api-00000000000000000000000000000000"

#: Two resolvers, so preference order and the exit-node flag are both observable.
#: `1.1.1.1` and `9.9.9.9` are anycast and are what Tailscale's own documentation
#: uses, so nothing here depends on a resolver being reachable.
#:
#: The flag is only ever asked for as `true`: the server drops a `false` on the way
#: in, so a request carrying it comes back without it and every run would report a
#: change. `test_a_false_exit_node_flag_is_dropped_by_the_server` pins that.
TWO_RESOLVERS = [
    {"address": "1.1.1.1", "use_with_exit_node": True},
    {"address": "9.9.9.9", "use_with_exit_node": True},
]

#: The document the server is expected to store for :data:`TWO_RESOLVERS`.
#: Written out rather than derived, because the difference from what was sent is
#: the thing being asserted.
TWO_RESOLVERS_STORED = [
    {"address": "1.1.1.1", "useWithExitNode": True},
    {"address": "9.9.9.9", "useWithExitNode": True},
]

#: A split-DNS map. The domain is one nobody owns, and the resolver is anycast,
#: so the write is accepted whether or not the domain resolves. The exit-node flag
#: is asked for as `true` for the same reason as above.
ONE_SPLIT = {"stress.invalid": [{"address": "1.1.1.1", "useWithExitNode": True}]}
ONE_SPLIT_ASKED = {"stress.invalid": [{"address": "1.1.1.1", "use_with_exit_node": True}]}


def _run(
    module_args: Any, module_result: Any, options: dict[str, Any], **flags: Any
) -> dict[str, Any]:
    module_args(options, **flags)
    with module_result.success() as result:
        tailscale_dns.main()
    return dict(result)


def _current(api: Api) -> dict[str, Any]:
    body = api.call("dns_configuration_get", "GET").body
    return body if isinstance(body, dict) else {}


def test_a_full_configuration_then_read_converges(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """Set every option at once, then set them again and expect no change.

    The property that matters most here, because the endpoint replaces: a module
    that sent a default for an unmentioned field would reset it, and the second
    run would then report a change forever.
    """
    with preserved("dns"):
        options = {
            **credentials,
            "nameservers": TWO_RESOLVERS,
            "split_dns": ONE_SPLIT_ASKED,
            "search_paths": ["stress.invalid"],
            "magic_dns": True,
            "override_local_dns": True,
        }

        first = _run(module_args, module_result, options, diff=True)
        assert first["changed"] is True
        assert first["diff"]["after"], "the diff must carry what it wrote"

        second = _run(module_args, module_result, options)
        assert second["changed"] is False, "the tailnet already holds this"
        assert second["diff"]["before"] == second["diff"]["after"]


def test_every_field_survives_the_round_trip_in_the_api_spelling(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """The module's snake_case options have to arrive as the API's camel case.

    Asserted by reading the document back through the API, because that is where
    a translation bug would show up and nowhere else. A field the module sent
    under the wrong name would be silently ignored by the API, so the test would
    see the old value and no error.
    """
    with preserved("dns"):
        _run(
            module_args,
            module_result,
            {
                **credentials,
                "nameservers": TWO_RESOLVERS,
                "split_dns": ONE_SPLIT_ASKED,
                "search_paths": ["stress.invalid"],
                "magic_dns": True,
                "override_local_dns": True,
            },
        )

        stored = _current(api)
        assert stored["nameservers"] == TWO_RESOLVERS_STORED, "addresses and the flag survive"
        assert stored["splitDNS"] == ONE_SPLIT, "and the split map, in the API's own spelling"
        assert stored["searchPaths"] == ["stress.invalid"]
        assert stored["preferences"]["magicDNS"] is True
        assert stored["preferences"]["overrideLocalDNS"] is True


def test_a_false_exit_node_flag_is_dropped_by_the_server(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """The asymmetry that decides what the rest of this file sends.

    Asked for `false`, the flag is stored as absent. Asked for `true`, it is stored.
    The server does not round-trip a `false`, so a request carrying one leaves a
    document that differs from the tailnet on every run.

    Pinned here so a server that starts round-tripping the flag produces a failure
    rather than a quiet difference. `resolver` is shaped by this: it sends no key
    for the flag when it is off, which is why a task using the option's own default
    converges rather than reporting a change for ever.
    """
    with preserved("dns"):
        _run(
            module_args,
            module_result,
            {**credentials, "nameservers": [{"address": "1.1.1.1", "use_with_exit_node": False}]},
        )
        stored = _current(api)["nameservers"]

        assert stored == [{"address": "1.1.1.1"}], (
            "the server drops a false flag; if this now stores it, the resolvers in "
            "this file can ask for false and a second run will converge again"
        )


def test_a_resolver_keeps_the_flag_the_tailnet_holds(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """A task that does not mention the flag leaves it as the tailnet has it.

    The flag used to default to false, so omitting it cleared the tailnet's own
    value and a task that never mentioned the field reported a change on every run.
    An explicit false is now the only thing that clears it.
    """
    with preserved("dns"):
        flagged = {
            **credentials,
            "nameservers": [{"address": "1.1.1.1", "use_with_exit_node": True}],
        }
        _run(module_args, module_result, flagged)
        assert _current(api)["nameservers"] == [{"address": "1.1.1.1", "useWithExitNode": True}], (
            "the baseline this test keeps"
        )

        omitted = _run(
            module_args, module_result, {**credentials, "nameservers": [{"address": "1.1.1.1"}]}
        )
        assert omitted["changed"] is False, "omitting the flag must not clear it"
        assert _current(api)["nameservers"] == [{"address": "1.1.1.1", "useWithExitNode": True}]

        cleared = _run(
            module_args,
            module_result,
            {**credentials, "nameservers": [{"address": "1.1.1.1", "use_with_exit_node": False}]},
        )
        assert cleared["changed"] is True
        assert _current(api)["nameservers"] == [{"address": "1.1.1.1"}]


def test_a_resolver_may_be_given_as_a_bare_address(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """A string is the same as a mapping that gives only the address, and converges."""
    with preserved("dns"):
        options = {**credentials, "nameservers": ["8.8.4.4", "2001:4860:4860::8844"]}

        first = _run(module_args, module_result, options, diff=True)
        assert first["changed"] is True
        assert _current(api)["nameservers"] == [
            {"address": "8.8.4.4"},
            {"address": "2001:4860:4860::8844"},
        ]

        second = _run(module_args, module_result, options)
        assert second["changed"] is False, "the string form must converge too"


def test_check_mode_reports_the_change_without_writing(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """On a replace endpoint this matters more than anywhere else.

    A check run that wrote would replace the document with a partially specified
    one, and the tailnet would lose every resolver the task did not mention.
    """
    with preserved("dns"):
        before = _current(api)

        result = _run(
            module_args,
            module_result,
            {**credentials, "nameservers": TWO_RESOLVERS, "magic_dns": True},
            check_mode=True,
        )

        assert result["changed"] is True, "check mode still reports what it would do"
        assert result["dns_configuration"], "and the document it would write"
        assert _current(api) == before, "and it wrote nothing"


def test_an_option_left_out_is_not_reset(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """The claim the module's documentation makes, against a real replace endpoint.

    Set everything, then change one thing. Everything else must survive, because
    on this endpoint an omitted field is not "leave it alone" by the server's
    doing, it is "send the previous value" by the module's.
    """
    with preserved("dns"):
        both = {
            **credentials,
            "nameservers": TWO_RESOLVERS,
            "search_paths": ["stress.invalid"],
            "magic_dns": True,
        }
        _run(module_args, module_result, both)
        first = _current(api)

        # One option only, which is how an operator adds a setting.
        result = _run(module_args, module_result, {**credentials, "magic_dns": False})

        assert result["changed"] is True, "magicDNS did change"
        after = _current(api)
        # The server drops a field that becomes its default rather than storing the
        # default, so a `false` arrives as an absent key. That is why the settings
        # above are read with `.get()` throughout: a missing key is the stored form
        # of `false`, not a missing document.
        assert after.get("preferences", {}).get("magicDNS") is not True, "it is off"
        assert after["nameservers"] == first["nameservers"], "the resolvers survived"
        assert after["searchPaths"] == first["searchPaths"], "and the search paths"

        # And the second run over that same task has to be quiet. This is the
        # assertion that catches the non-convergence: the server stores a `false` as
        # an absent key, so a module that sends `magicDNS: false` differs from a
        # tailnet holding no `magicDNS` and reports a change for ever. An earlier
        # version of this file omitted it and the suite passed with the fix removed.
        again = _run(module_args, module_result, {**credentials, "magic_dns": False})
        assert again["changed"] is False, (
            f"stored document is {after!r}, and asking for false must converge on it"
        )


def test_adding_and_removing_a_resolver_is_visible(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """List order is the preference order, so a change in the middle is a change."""
    with preserved("dns"):
        _run(module_args, module_result, {**credentials, "nameservers": TWO_RESOLVERS})
        two = _current(api)["nameservers"]

        # Reverse the preference order, which is a real change the API stores.
        _run(
            module_args,
            module_result,
            {**credentials, "nameservers": list(reversed(TWO_RESOLVERS))},
        )
        assert _current(api)["nameservers"] == list(reversed(two)), (
            "the order is the preference order"
        )

        # A single resolver is a change back down.
        result = _run(
            module_args,
            module_result,
            {**credentials, "nameservers": [TWO_RESOLVERS[0]]},
        )
        assert result["changed"] is True
        assert _current(api)["nameservers"] == TWO_RESOLVERS_STORED[:1]

        # And an empty list clears them, which is a whole-document change too.
        # The key is gone rather than holding an empty list, for the same reason
        # `magicDNS: false` is: the server drops a value that is its default.
        result = _run(module_args, module_result, {**credentials, "nameservers": []})
        assert result["changed"] is True
        assert _current(api).get("nameservers", []) == []


def test_a_split_dns_domain_is_cleared_by_an_empty_list(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """ADR 0004 says an empty list is how a domain goes, and the API must agree.

    Not a `null`, which would send a value the module's own comparison would then
    report as a change on every run.
    """
    with preserved("dns"):
        _run(module_args, module_result, {**credentials, "split_dns": ONE_SPLIT_ASKED})
        assert _current(api)["splitDNS"] == ONE_SPLIT

        result = _run(module_args, module_result, {**credentials, "split_dns": {}})
        assert result["changed"] is True
        assert _current(api).get("splitDNS", {}) == {}, "the domain is gone"

        # A second run over the same task has to be quiet, which is the whole point
        # of clearing something. The server drops an empty map rather than storing
        # it, so the module removes the key instead of sending one, and this is what
        # proves it: a module that sent `{}` would differ from a tailnet holding no
        # `splitDNS` and report a change for ever.
        again = _run(module_args, module_result, {**credentials, "split_dns": {}})
        assert again["changed"] is False, (
            f"stored document is {_current(api)!r}, and clearing a domain must converge"
        )


def test_an_unreadable_current_configuration_fails_rather_than_discarding_it(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """The data-loss guard, against the shape the API answers with.

    The endpoint replaces the whole document, so merging into an empty one would
    send back only the fields the task named and every other resolver would be
    gone. The module refuses instead, and says it wrote nothing.

    The unreadable response is a real HTTP 200 whose body is not JSON, which is
    what a captive portal or a proxy error page looks like from inside a module.
    The transport is patched rather than a second server stood up, because the
    point is the module's handling of an unread body and the tailnet's real
    resolvers are what must be shown intact afterwards.
    """
    with preserved("dns"):
        _run(module_args, module_result, {**credentials, "nameservers": TWO_RESOLVERS})
        before = _current(api)

        from ansible_collections.abn.tailscale.plugins.module_utils._tailscale import (
            _api as api_module,
        )

        class _Html:
            """A 200 whose body is not JSON, as a proxy error page looks like.

            `read` returns a body object rather than a string, because the transport
            decodes it before the module ever sees it, and a plain string here would
            be rejected by the transport itself rather than reaching the guard under
            test.
            """

            status = 200
            headers: ClassVar[dict] = {}

            def read(self) -> Any:
                class _Body:
                    def decode(self, *args: str) -> str:
                        return "<html>captive portal</html>"

                return _Body()

        real_open_url = api_module.open_url

        def html(*args: Any, **kwargs: Any) -> Any:
            return _Html()

        api_module.open_url = html  # ty: ignore[invalid-assignment]
        try:
            # An API token rather than the OAuth client, because the exchange the
            # client performs goes through the same patched transport and would fail
            # there first, which is a different failure from the one under test.
            module_args({"api_token": _TOKEN, "magic_dns": True})
            with module_result.failure() as result:
                tailscale_dns.main()
        finally:
            # Put back before the assertion below reads the tailnet, or the read
            # would be answered by the stub too and the assertion would prove
            # nothing about the tailnet.
            api_module.open_url = real_open_url

        assert "Nothing was written" in result["msg"]
        assert "Traceback" not in result["msg"]
        assert _current(api) == before, "the resolvers are still there"


def test_a_malformed_resolver_is_refused_by_its_own_validation(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
) -> None:
    """`address` is required, so the module's own spec refuses it before a request.

    Checked with a live credential in the payload on purpose: the point is that
    argument validation runs before the credential is used, so a typo costs no
    request and reveals nothing about the credential.
    """
    module_args({**credentials, "nameservers": [{"use_with_exit_node": True}]})
    with module_result.failure() as result:
        tailscale_dns.main()

    assert "address" in result["msg"]
    assert "Traceback" not in result["msg"]
    for secret in credentials.values():
        assert secret not in result["msg"]


def test_no_credential_option_at_all_fails_before_any_request(
    module_args: Any,
    module_result: Any,
    api: Api,
) -> None:
    """A task with no credential fails on the spot."""
    module_args({"magic_dns": True})
    with module_result.failure() as result:
        tailscale_dns.main()

    assert "api_token" in result["msg"] or "oauth_client_id" in result["msg"]
    assert "Traceback" not in result["msg"]


def test_check_mode_over_a_configuration_already_in_place_reports_no_change(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """The first thing an operator does, and it must be quiet when nothing is wrong."""
    with preserved("dns"):
        options = {**credentials, "nameservers": TWO_RESOLVERS, "magic_dns": True}
        _run(module_args, module_result, options)

        result = _run(module_args, module_result, options, check_mode=True)

        assert result["changed"] is False
        assert result["dns_configuration"]["nameservers"] == TWO_RESOLVERS_STORED


def test_the_returned_document_is_the_one_the_tailnet_holds(
    credentials: dict[str, str],
    module_args: Any,
    module_result: Any,
    api: Api,
    preserved: Any,
) -> None:
    """`dns_configuration` must be what is there, not what was asked for.

    On a replace endpoint those differ whenever the server normalises, and a
    module that returned the request would report a document nobody has.
    """
    with preserved("dns"):
        result = _run(
            module_args,
            module_result,
            {**credentials, "nameservers": TWO_RESOLVERS, "magic_dns": True},
        )

        assert result["dns_configuration"] == _current(api)
        assert json.dumps(result["dns_configuration"], sort_keys=True), "and it is a document"
