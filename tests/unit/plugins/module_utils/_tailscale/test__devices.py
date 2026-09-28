# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the device kernel: selection, comparison and the operations.

The module tests drive the same code through ``AnsibleModule``, so what is here is
the part a module cannot reach: the comparisons taken one property at a time, the
timestamp parsing, and the refusals that hold whatever the transport answers.
"""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from datetime import timedelta
from typing import Any

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import DeviceError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import check_name
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import desired
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import expired
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import held
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import identity
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import local_name
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import routes_wanted
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import select

NOW = datetime(2026, 6, 1, tzinfo=UTC)
LATER = NOW + timedelta(days=30)
EARLIER = NOW - timedelta(days=1)

DEVICE: dict[str, Any] = {
    "id": "3133440773018733",
    "nodeId": "nDEVICE000000000CNTRL",
    "name": "build-host.tail1234.ts.net",
    "hostname": "build-host",
    "tags": ["tag:build"],
    "authorized": False,
    "keyExpiryDisabled": False,
    "addresses": ["100.100.100.1", "fd7a:115c:a1e0::1"],
    "expires": LATER.isoformat().replace("+00:00", "Z"),
}

OTHER: dict[str, Any] = dict(
    DEVICE,
    id="4133440773018733",
    nodeId="nOTHER000000000CNTRL",
    name="other.tail1234.ts.net",
    addresses=["100.100.100.2", "fd7a:115c:a1e0::2"],
    tags=["tag:web"],
)


def test_every_selector_has_a_matcher() -> None:
    """A selector added to SELECTORS without one would match nothing, and a task
    would be refused for a reason that names nothing about the selector."""
    from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import _MATCHERS
    from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._devices import SELECTORS

    assert set(_MATCHERS) == set(SELECTORS)


# ------------------------------------------------------------------ identity


def test_a_device_is_written_through_its_preferred_identifier() -> None:
    assert identity(DEVICE) == "nDEVICE000000000CNTRL"


def test_the_legacy_identifier_is_used_when_there_is_no_node_id() -> None:
    """A device the API has not given a nodeId is still addressable, and writes have
    to go through the same identifier the read matched it on."""
    assert identity({"id": "3133440773018733"}) == "3133440773018733"


def test_a_device_with_neither_identifier_yields_an_empty_one() -> None:
    assert identity({}) == ""


def test_a_name_is_read_as_the_label_without_the_tailnet_suffix() -> None:
    assert local_name(DEVICE) == "build-host"


def test_a_name_with_no_dot_is_its_own_label() -> None:
    assert local_name({"name": "build-host"}) == "build-host"


def test_a_device_with_no_name_yields_an_empty_label() -> None:
    assert local_name({}) == ""


# ------------------------------------------------------------------ selection


@pytest.mark.parametrize(
    ("selector", "value"),
    [
        ("device_id", "nDEVICE000000000CNTRL"),
        ("device_id", "3133440773018733"),
        ("device_name", "build-host"),
        ("device_name", "build-host.tail1234.ts.net"),
        ("address", "100.100.100.1"),
        ("address", "fd7a:115c:a1e0::1"),
        ("tag", "tag:build"),
    ],
)
def test_every_selector_finds_the_same_device(selector: str, value: str) -> None:
    selection = select([DEVICE, OTHER], {selector: value})
    assert [device["nodeId"] for device in selection.devices] == ["nDEVICE000000000CNTRL"]
    assert (selection.selector, selection.value) == (selector, value)


def test_a_selector_naming_nothing_matches_no_device() -> None:
    assert select([DEVICE], {"address": "100.1.1.1"}).devices == []


def test_selecting_needs_a_selector() -> None:
    with pytest.raises(DeviceError, match="every device in the tailnet"):
        select([DEVICE], {"authorized": True})


def test_a_selector_the_collection_does_not_know_is_not_one() -> None:
    """A caller that passed something else has named no device at all, which is the
    same situation as passing nothing and is refused the same way."""
    with pytest.raises(DeviceError, match="every device in the tailnet"):
        select([DEVICE], {"user": "someone@example.com"})


# ------------------------------------------------------------------ the name


@pytest.mark.parametrize("name", ["build-host", "b", "9lives", "a-b-c", "0"])
def test_a_name_in_the_stored_form_is_accepted(name: str) -> None:
    check_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "Build-Host",
        "under_score",
        "dotted.name",
        "trailing-",
        "-leading",
        "double--dash",
        "with space",
        "",
        "a" * 64,
    ],
)
def test_a_name_the_server_would_rewrite_is_refused(name: str) -> None:
    with pytest.raises(DeviceError):
        check_name(name)


def test_the_refusal_for_a_rewritten_name_says_why_it_refuses() -> None:
    with pytest.raises(DeviceError, match="change on every run"):
        check_name("Build-Host")


# ------------------------------------------------------------------ expiry


def test_a_key_expiring_later_has_not_expired() -> None:
    assert expired(DEVICE, NOW) is False


def test_a_key_that_has_passed_has_expired() -> None:
    assert expired(dict(DEVICE, expires="2020-01-01T00:00:00Z"), NOW) is True


def test_a_key_expiring_at_this_moment_has_expired() -> None:
    assert expired(dict(DEVICE, expires=NOW.isoformat().replace("+00:00", "Z")), NOW) is True


def test_an_absent_expiry_counts_as_not_expired() -> None:
    """Guessing the other way would leave a device whose key state nobody can observe
    looking reconciled for good."""
    assert expired({"nodeId": "n1"}, NOW) is False
    assert expired({"nodeId": "n1", "expires": ""}, NOW) is False
    assert expired({"nodeId": "n1", "expires": "whenever"}, NOW) is False


def test_a_timestamp_without_an_offset_is_read_as_utc() -> None:
    assert expired(dict(DEVICE, expires="2020-01-01T00:00:00"), NOW) is True


def test_a_lowercase_suffix_is_read_too() -> None:
    assert expired(dict(DEVICE, expires="2020-01-01T00:00:00z"), NOW) is True


# ------------------------------------------------------------------ comparison


def test_nothing_asked_for_asks_for_nothing() -> None:
    assert desired(DEVICE, {"device_name": "build-host"}, NOW) == {}


def test_a_property_already_held_is_not_wanted() -> None:
    assert (
        desired(
            DEVICE,
            {
                "name": "build-host",
                "tags": ["tag:build"],
                "authorized": False,
                "key_expiry_disabled": False,
                "tailscale_ip": "100.100.100.1",
            },
            NOW,
        )
        == {}
    )


def test_a_differing_property_is_wanted() -> None:
    assert desired(DEVICE, {"authorized": True}, NOW) == {"authorized": True}


def test_an_absent_boolean_is_read_as_false() -> None:
    """The API omits a boolean that is off rather than storing the default, so an
    absent key and a stored false are the same state."""
    bare = {key: value for key, value in DEVICE.items() if key != "authorized"}
    assert desired(bare, {"authorized": False}, NOW) == {}
    assert desired(bare, {"authorized": True}, NOW) == {"authorized": True}


def test_an_absent_tag_list_is_read_as_no_tags() -> None:
    bare = {key: value for key, value in DEVICE.items() if key != "tags"}
    assert desired(bare, {"tags": []}, NOW) == {}
    assert desired(bare, {"tags": ["tag:build"]}, NOW) == {"tags": ["tag:build"]}


def test_tags_are_wanted_sorted() -> None:
    assert desired(DEVICE, {"tags": ["tag:z", "tag:a"]}, NOW) == {"tags": ["tag:a", "tag:z"]}


def test_a_name_is_wanted_only_when_the_label_differs() -> None:
    """The label is what moves. A task asking for the label the device already holds
    has nothing to do, and the tailnet's suffix is not something it can ask for."""
    assert desired(DEVICE, {"name": "build-host"}, NOW) == {}
    assert desired(DEVICE, {"name": "renamed"}, NOW) == {"name": "renamed"}


def test_an_address_the_device_holds_in_either_family_is_not_wanted() -> None:
    assert desired(DEVICE, {"tailscale_ip": "fd7a:115c:a1e0::1"}, NOW) == {}


def test_expiring_is_wanted_only_for_a_key_that_has_not_passed() -> None:
    assert desired(DEVICE, {"expire_key": True}, NOW) == {"expire_key": True}
    assert desired(dict(DEVICE, expires="2020-01-01T00:00:00Z"), {"expire_key": True}, NOW) == {}


def test_expiring_false_asks_for_nothing() -> None:
    assert desired(DEVICE, {"expire_key": False}, NOW) == {}


def test_what_a_property_holds_now_is_reported_in_the_module_s_spelling() -> None:
    assert held(DEVICE, ["name", "tags", "authorized", "key_expiry_disabled"], NOW) == {
        "name": "build-host",
        "tags": ["tag:build"],
        "authorized": False,
        "key_expiry_disabled": False,
    }


def test_the_current_address_is_the_first_the_api_lists() -> None:
    assert held(DEVICE, ["tailscale_ip"], NOW) == {"tailscale_ip": "100.100.100.1"}


def test_a_device_holding_no_address_reports_none_rather_than_a_value() -> None:
    assert held({"nodeId": "n1"}, ["tailscale_ip"], NOW) == {"tailscale_ip": None}


def test_an_expired_key_is_reported_as_expired_rather_than_as_a_timestamp() -> None:
    assert held(dict(DEVICE, expires="2020-01-01T00:00:00Z"), ["expire_key"], NOW) == {
        "expire_key": True
    }


# ------------------------------------------------------------------ routes


def test_routes_already_enabled_are_not_wanted_again() -> None:
    current = {"enabledRoutes": ["10.20.0.0/16"]}
    assert routes_wanted(current, ["10.20.0.0/16"]) is None


def test_routes_in_another_order_are_the_same_set() -> None:
    current = {"enabledRoutes": ["10.21.0.0/16", "10.20.0.0/16"]}
    assert routes_wanted(current, ["10.20.0.0/16", "10.21.0.0/16"]) is None


def test_routes_to_enable_are_wanted_sorted() -> None:
    assert routes_wanted({"enabledRoutes": []}, ["10.21.0.0/16", "10.20.0.0/16"]) == [
        "10.20.0.0/16",
        "10.21.0.0/16",
    ]


def test_asking_for_no_routes_is_a_real_answer_and_not_an_absence() -> None:
    """It is how a device is stripped of the routes an admin enabled for it, and
    reporting it as `None` would leave the routes on."""
    assert routes_wanted({"enabledRoutes": ["10.20.0.0/16"]}, []) == []


def test_an_absent_route_list_is_read_as_no_routes() -> None:
    assert routes_wanted({}, []) is None
    assert routes_wanted("not a document", []) is None
    assert routes_wanted({"enabledRoutes": None}, []) is None
