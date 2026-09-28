# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for folding a task's declarations into a policy document.

The document is what gets written, so what these tests pin is what the module
would send. The preset app table is the exception: a wrong identifier is a
connector that fetches nothing, and the server's own refusal of one is the only
place a mistake shows up, so every row is checked.
"""

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import diff
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._vocabulary import (
    PARAMETRISED_PRESETS,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._vocabulary import (
    PRESET_APPS,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._vocabulary import (
    PRESET_NAMES,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._vocabulary import (
    VocabularyError,
)
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._vocabulary import compose

# The document every case starts from: deny-all, and the two tagOwners the
# connectors need so the prerequisite check is not what is under test.
BASE = {
    "acls": [],
    "tagOwners": {"tag:connector": ["autogroup:admin"], "tag:other": ["autogroup:admin"]},
}


def connector(**overrides):
    entry = {"name": "example", "connectors": ["tag:connector"], "domains": ["example.com"]}
    entry.update(overrides)
    return entry


def only(document, *path):
    """The node at `path`, for an assertion that does not restate the whole tree."""
    for step in path:
        document = document[step]
    return document


def fold(document, **declarations):
    """The document alone, for the case where the findings are not what is under test."""
    return compose(document, **declarations)[0]


def reported(document, **declarations):
    """The findings alone, for the case where the document is not what is under test."""
    return compose(document, **declarations)[1]


# The preset app table
# --------------------


def test_every_fixed_preset_app_maps_to_the_identifier_tailscale_writes():
    # The published table, one row at a time. A slug that differs from its display
    # name is the whole reason this table is in the module.
    expected = {
        "AWS CloudFront (global)": "aws-cloudfront-global",
        "Confluence": "confluence",
        "GitHub": "github",
        "Google Workspace": "google-workspace",
        "Jira": "jira",
        "Microsoft 365": "microsoft-365",
        "Okta": "okta",
        "Oracle Services Network (global)": "oracle-osn-global",
        "Salesforce (Hyperforce environment)": "salesforce-hyperforce",
        "Salesforce (Salesforce-hosted)": "salesforce",
        "Stripe": "stripe",
    }

    assert expected == PRESET_APPS


def test_the_four_parametrised_apps_carry_the_published_pattern():
    # Measured against the real API: `oracle-oci-<region>` and
    # `oracle-object-storage-<region>` are accepted, and every
    # `aws-ec2-<region>-<availability-zone>-<local-zone>` shape tried was refused
    # with `preset app ID (...) is not valid`, so neither list is composed here.
    expected = {
        "AWS EC2/ELB": "aws-ec2-<region>-<availability-zone>-<local-zone>",
        "AWS S3": "aws-s3-<region>-<availability-zone>-<local-zone>",
        "Oracle Cloud Infrastructure (OCI)": "oracle-oci-<region>",
        "Oracle Object Storage": "oracle-object-storage-<region>",
    }

    assert expected == PARAMETRISED_PRESETS


def test_the_table_names_fifteen_apps_and_no_duplicate():
    # Fourteen names and one identifier each, from the published table. A count is
    # the cheapest thing to assert and the one that fails when a row is dropped.
    assert len(PRESET_NAMES) == 15
    assert len(set(PRESET_NAMES)) == 15
    assert len(set(PRESET_APPS.values()) | set(PARAMETRISED_PRESETS.values())) == 15


@pytest.mark.parametrize("name, identifier", sorted(PRESET_APPS.items()))
def test_a_fixed_preset_app_is_written_as_its_identifier(name, identifier):
    composed = fold(BASE, app_connectors=[connector(preset=name, domains=None)])

    written = only(composed, "nodeAttrs", 0, "app", "tailscale.com/app-connectors", 0)
    assert written == {
        "name": "example",
        "connectors": ["tag:connector"],
        "presetAppID": identifier,
    }


@pytest.mark.parametrize("name, pattern", sorted(PARAMETRISED_PRESETS.items()))
def test_a_parametrised_preset_app_is_refused_with_its_pattern(name, pattern):
    with pytest.raises(VocabularyError) as caught:
        compose(BASE, app_connectors=[connector(preset=name)])

    assert pattern in str(caught.value)
    assert "preset_id" in str(caught.value)


def test_a_declared_preset_id_is_written_as_given():
    composed = fold(
        BASE, app_connectors=[connector(preset_id="oracle-oci-us-ashburn-1", domains=None)]
    )

    written = only(composed, "nodeAttrs", 0, "app", "tailscale.com/app-connectors", 0)
    assert written["presetAppID"] == "oracle-oci-us-ashburn-1"


def test_a_preset_app_carries_no_domains_key():
    # The server refuses domains that are not empty alongside a preset, and
    # stores an empty list as an empty list, so the only convergent choice is to
    # send no key at all.
    composed = fold(BASE, app_connectors=[connector(preset="GitHub", domains=None)])

    written = only(composed, "nodeAttrs", 0, "app", "tailscale.com/app-connectors", 0)
    assert "domains" not in written


def test_preset_and_preset_id_together_are_refused():
    with pytest.raises(VocabularyError, match="both 'preset' and 'preset_id'"):
        compose(BASE, app_connectors=[connector(preset="GitHub", preset_id="github")])


# The node attribute entry
# ------------------------


def test_a_connector_is_written_under_a_node_attribute_targeting_every_node():
    composed = fold(BASE, app_connectors=[connector()])

    assert composed["nodeAttrs"] == [
        {"target": ["*"], "app": {"tailscale.com/app-connectors": [connector()]}}
    ]


def test_a_connector_is_added_to_the_entry_the_file_already_has():
    document = {
        **BASE,
        "nodeAttrs": [
            {
                "target": ["*"],
                "attr": ["funnel"],
                "app": {
                    "tailscale.com/app-connectors": [
                        {"name": "other", "connectors": ["tag:other"], "domains": ["a.example.com"]}
                    ]
                },
            }
        ],
    }

    composed = fold(document, app_connectors=[connector()])

    assert composed["nodeAttrs"][0]["attr"] == ["funnel"], "the entry keeps what it carried"
    assert only(composed, "nodeAttrs", 0, "app", "tailscale.com/app-connectors", 1) == connector()


def test_an_app_map_under_a_narrower_target_is_refused():
    document = {
        **BASE,
        "nodeAttrs": [
            {
                "target": ["tag:connector"],
                "app": {
                    "tailscale.com/app-connectors": [
                        {
                            "name": "other",
                            "connectors": ["tag:connector"],
                            "domains": ["a.example.com"],
                        }
                    ]
                },
            }
        ],
    }

    with pytest.raises(VocabularyError, match='target "\\*"'):
        compose(document, app_connectors=[connector()])


def test_a_connector_whose_tag_has_no_owner_is_refused():
    with pytest.raises(VocabularyError) as caught:
        compose(BASE, app_connectors=[connector(connectors=["tag:unowned"])])

    assert "tag:unowned" in str(caught.value)
    assert "tagOwners" in str(caught.value)


def test_a_connector_naming_a_group_as_a_connector_is_refused():
    with pytest.raises(VocabularyError, match="must be a tag"):
        compose(BASE, app_connectors=[connector(connectors=["group:engineering"])])


def test_a_connector_repeating_a_tag_is_refused():
    with pytest.raises(VocabularyError, match="twice"):
        compose(BASE, app_connectors=[connector(connectors=["tag:connector", "tag:connector"])])


def test_a_custom_connector_with_no_domains_is_refused():
    with pytest.raises(VocabularyError, match="needs 'domains'"):
        compose(BASE, app_connectors=[{"name": "example", "connectors": ["tag:connector"]}])


def test_a_custom_connector_with_an_empty_domain_list_is_refused():
    with pytest.raises(VocabularyError, match="empty 'domains'"):
        compose(BASE, app_connectors=[connector(domains=[])])


def test_a_connector_repeating_a_domain_is_refused():
    with pytest.raises(VocabularyError, match="lists a domain twice"):
        compose(
            BASE,
            app_connectors=[connector(domains=["a.example.com", "a.example.com"])],
        )


def test_a_connector_with_no_name_is_refused():
    with pytest.raises(VocabularyError, match="needs a 'name'"):
        compose(BASE, app_connectors=[connector(name="")])


def test_the_same_connector_declared_twice_is_a_conflict():
    document = {
        **BASE,
        "nodeAttrs": [
            {
                "target": ["*"],
                "app": {"tailscale.com/app-connectors": [connector(domains=["other.example.com"])]},
            }
        ],
    }

    with pytest.raises(VocabularyError, match="declared twice"):
        compose(document, app_connectors=[connector()])


def test_the_same_connector_declared_identically_is_not_a_conflict():
    document = {
        **BASE,
        "nodeAttrs": [{"target": ["*"], "app": {"tailscale.com/app-connectors": [connector()]}}],
    }

    composed = fold(document, app_connectors=[connector()])

    assert only(composed, "nodeAttrs", 0, "app", "tailscale.com/app-connectors") == [connector()]


def test_routes_are_written_under_the_connector():
    composed = fold(BASE, app_connectors=[connector(routes=["100.64.0.0/10"])])

    assert only(composed, "nodeAttrs", 0, "app", "tailscale.com/app-connectors", 0)["routes"] == [
        "100.64.0.0/10"
    ]


# Findings
# --------


def test_a_connector_no_rule_can_reach_is_reported():
    findings = reported(BASE, app_connectors=[connector()])

    assert any("reachable by no access rule" in finding for finding in findings)
    assert any("auto-approver" in finding for finding in findings)


def test_a_reachable_and_approved_connector_is_not_reported():
    document = {
        **BASE,
        "grants": [{"src": ["autogroup:member"], "dst": ["tag:connector"], "ip": ["*"]}],
        "autoApprovers": {"routes": {"100.64.0.0/10": ["tag:connector"]}},
    }

    findings = reported(document, app_connectors=[connector()])

    assert findings == []


def test_a_preset_app_is_not_asked_for_a_route_approver():
    document = {
        **BASE,
        "grants": [{"src": ["autogroup:member"], "dst": ["tag:connector"], "ip": ["*"]}],
    }

    findings = reported(document, app_connectors=[connector(preset="GitHub", domains=None)])

    assert findings == []


def test_an_acl_destination_counts_as_reaching_the_tag():
    document = {
        **BASE,
        "acls": [{"action": "accept", "src": ["*"], "dst": ["tag:connector:53"]}],
        "autoApprovers": {"routes": {"100.64.0.0/10": ["tag:connector"]}},
    }

    findings = reported(document, app_connectors=[connector()])

    assert findings == []


def test_a_group_nobody_declares_is_reported_with_the_node_naming_it():
    document = {**BASE, "acls": [{"action": "accept", "src": ["group:eng"], "dst": ["*:*"]}]}

    findings = reported(document)

    assert len(findings) == 1
    assert "group:eng" in findings[0]
    assert "/acls/0/src" in findings[0]


def test_a_declared_group_is_not_reported():
    document = {
        **BASE,
        "acls": [{"action": "accept", "src": ["group:eng"], "dst": ["*:*"]}],
        "groups": {"group:eng": ["alice@example.com"]},
    }

    findings = reported(document)

    assert findings == []


def test_a_group_named_by_a_tag_owner_is_reported():
    document = {**BASE, "tagOwners": {"tag:web": ["group:platform"]}}

    findings = reported(document)

    assert any("group:platform" in finding for finding in findings)


def test_a_group_named_by_a_node_attribute_target_is_reported():
    document = {**BASE, "nodeAttrs": [{"target": ["group:platform"], "attr": ["funnel"]}]}

    findings = reported(document)

    assert any("group:platform" in finding for finding in findings)


def test_a_legacy_users_spelling_still_names_a_group():
    document = {**BASE, "acls": [{"action": "accept", "users": ["group:eng"], "ports": ["*:*"]}]}

    findings = reported(document)

    assert any("group:eng" in finding for finding in findings)


def test_an_acl_destination_port_is_not_part_of_the_group_name():
    document = {**BASE, "acls": [{"action": "accept", "src": ["*"], "dst": ["group:eng:22"]}]}

    findings = reported(document)

    assert any("group:eng" in finding for finding in findings)
    assert not any("eng:22" in finding for finding in findings)


def test_a_selector_that_is_not_a_group_is_not_read_as_one():
    document = {
        **BASE,
        "acls": [
            {
                "action": "accept",
                "src": ["autogroup:member", "user:*@example.com"],
                "dst": ["*:*"],
            }
        ],
    }

    findings = reported(document)

    assert findings == []


def test_the_number_of_reported_groups_is_capped():
    document = {
        **BASE,
        "acls": [
            {
                "action": "accept",
                "src": [f"group:g{index}" for index in range(9)],
                "dst": ["*:*"],
            }
        ],
    }

    findings = reported(document)

    assert len(findings) == 6, "five groups and a line saying how many were left out"


# Groups
# ------


def test_a_declared_group_is_merged_into_the_document():
    composed = fold(BASE, groups={"group:eng": ["alice@example.com"]})

    assert composed["groups"] == {"group:eng": ["alice@example.com"]}


def test_a_group_without_its_prefix_is_refused():
    with pytest.raises(VocabularyError, match="does not start with 'group:'"):
        compose(BASE, groups={"engineering": ["alice@example.com"]})


def test_a_group_declared_differently_by_the_file_is_refused():
    document = {**BASE, "groups": {"group:eng": ["alice@example.com"]}}

    with pytest.raises(VocabularyError, match="declared twice"):
        compose(document, groups={"group:eng": ["bob@example.com"]})


def test_a_group_declared_with_its_members_reordered_is_not_a_conflict():
    # The server sorts group members, so the canonical form does too, and a
    # difference in order is not a difference in the document.
    document = {**BASE, "groups": {"group:eng": ["alice@example.com", "bob@example.com"]}}

    composed = fold(document, groups={"group:eng": ["bob@example.com", "alice@example.com"]})

    assert not diff(composed, document)


def test_declaring_nothing_leaves_the_document_alone():
    document = {**BASE, "groups": {"group:eng": ["alice@example.com"]}}

    composed = fold(document)

    assert composed == document


# Access tests
# ------------


def test_a_declared_test_is_appended_to_the_document():
    composed = fold(BASE, tests=[{"src": "alice@example.com", "deny": ["1.2.3.4:22"]}])

    assert composed["tests"] == [{"src": "alice@example.com", "deny": ["1.2.3.4:22"]}]


def test_a_declared_test_is_written_in_the_casing_the_api_uses():
    composed = fold(
        BASE,
        tests=[
            {
                "src": "alice@example.com",
                "accept": ["1.2.3.4:443"],
                "proto": "tcp",
                "src_posture_attrs": {"node:os": "linux"},
            }
        ],
    )

    assert composed["tests"] == [
        {
            "src": "alice@example.com",
            "accept": ["1.2.3.4:443"],
            "proto": "tcp",
            "srcPostureAttrs": {"node:os": "linux"},
        }
    ]


def test_a_test_the_file_declares_keeps_its_place():
    document = {**BASE, "tests": [{"src": "bob@example.com", "accept": ["1.2.3.4:22"]}]}

    composed = fold(document, tests=[{"src": "alice@example.com", "accept": ["1.2.3.4:443"]}])

    assert [test["src"] for test in composed["tests"]] == [
        "bob@example.com",
        "alice@example.com",
    ]


def test_a_test_with_no_src_is_refused():
    with pytest.raises(VocabularyError, match="needs a 'src'"):
        compose(BASE, tests=[{"accept": ["1.2.3.4:443"]}])


def test_a_test_that_asserts_nothing_is_refused():
    with pytest.raises(VocabularyError, match="asserts nothing"):
        compose(BASE, tests=[{"src": "alice@example.com"}])


def test_a_test_with_a_wildcard_destination_is_refused_by_the_server_not_here():
    # The server refuses a test naming `*` as a source or a destination. The
    # module does not repeat that check, because the message it answers with
    # already names the test that failed.
    composed = fold(BASE, tests=[{"src": "*", "accept": ["1.2.3.4:443"]}])

    assert composed["tests"] == [{"src": "*", "accept": ["1.2.3.4:443"]}]


# The document itself
# -------------------


def test_the_document_the_caller_passed_in_is_not_modified():
    document = {**BASE}

    compose(
        document,
        groups={"group:eng": ["alice@example.com"]},
        tests=[{"src": "a@b.com", "accept": ["1.2.3.4:22"]}],
    )

    assert document == BASE


def test_a_document_that_is_not_an_object_is_left_for_the_module_to_refuse():
    composed, findings = compose([])

    assert composed == []
    assert findings == []


def test_declaring_against_a_document_that_is_not_an_object_is_refused():
    with pytest.raises(VocabularyError, match="not a JSON object"):
        compose("not a policy", groups={"group:eng": ["alice@example.com"]})
