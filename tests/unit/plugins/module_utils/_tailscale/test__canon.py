# SPDX-License-Identifier: GPL-3.0-or-later
"""Canonicalisation decides what a run reports as `changed`, so the equivalence
classes below are the whole contract. Two documents must canonicalise alike when
they mean the same thing, and differently when they do not.
"""

import pytest
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import CanonError
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import canonicalise
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import diff
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import load_file
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import loads
from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import render

# One policy in three spellings. Only the syntax differs between them.
_PLAIN = """{
  "acls": [
    {
      "action": "accept",
      "src": ["autogroup:member"],
      "dst": ["tag:web:443"]
    }
  ],
  "groups": {
    "group:web": ["alice@example.com", "bob@example.com"]
  },
  "hosts": {
    "printer": "100.64.0.9"
  },
  "tagOwners": {
    "tag:web": ["group:web"]
  }
}"""

_ANNOTATED = """{
  // Access for the web tier. Comments and trailing commas are the only
  // differences from the strict JSON spelling above.
  "acls": [
    {
      "action": "accept",
      "src": ["autogroup:member"],
      "dst": ["tag:web:443"],
    },
  ],
  "groups": {
    "group:web": [
      "alice@example.com", /* ops */
      "bob@example.com",
    ],
  },
  "hosts": {
    "printer": "100.64.0.9",
  },
  "tagOwners": {
    "tag:web": ["group:web"],
  },
}"""

_REORDERED = """{
  "tagOwners": {
    "tag:web": ["group:web"]
  },
  "hosts": {
    "printer": "100.64.0.9"
  },
  "groups": {
    "group:web": ["alice@example.com", "bob@example.com"]
  },
  "acls": [
    {
      "dst": ["tag:web:443"],
      "action": "accept",
      "src": ["autogroup:member"]
    }
  ]
}"""

_LEGACY_ACL = {"acls": [{"action": "accept", "users": ["*"], "ports": ["*:*"]}]}
_MODERN_ACL = {"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}


# HuJSON is JSON plus comments, and only the scanner can tell the two apart.
def test_line_comments_are_not_data():
    assert loads('{"a": 1} // trailing\n') == {"a": 1}
    assert loads('// leading\n{"a": 1}') == {"a": 1}
    assert loads('{"a": /* inline */ 1}') == {"a": 1}


def test_block_comments_spanning_lines_are_not_data():
    text = '{"a": 1, /* one\ntwo\nthree */ "b": 2}'

    assert loads(text) == {"a": 1, "b": 2}


def test_comment_markers_inside_a_string_survive():
    text = '{"endpoint": "https://tailscale.com", "pattern": "/* not a comment */"}'

    assert loads(text) == {
        "endpoint": "https://tailscale.com",
        "pattern": "/* not a comment */",
    }


def test_escaped_solidus_survives():
    # A backslash takes the solidus with it, so the following slash cannot open
    # a comment and the escaped form cannot end the string.
    assert loads(r'{"a": "x\/\/\/y"}') == {"a": "x///y"}


def test_escaped_backslash_does_not_close_the_string():
    assert loads(r'{"a": "ends in a backslash \\", "b": 2}') == {
        "a": "ends in a backslash \\",
        "b": 2,
    }


def test_unescaped_control_character_in_a_string_is_rejected():
    with pytest.raises(CanonError, match=r"unescaped tab in a string at line 1 column 9"):
        loads('{"a": "x\ty"}')


def test_unterminated_block_comment_is_rejected():
    with pytest.raises(CanonError, match="unterminated block comment at line 1 column 10"):
        loads('{"a": 1} /* never closed')


def test_unterminated_string_is_rejected():
    with pytest.raises(CanonError, match="unterminated string starting at line 1 column 7"):
        loads('{"a": "no closing quote}')


def test_syntax_error_reports_the_line_it_is_on():
    # Line 3 of the source, not of the comment-stripped copy.
    with pytest.raises(CanonError, match=r"invalid HuJSON at line 3 column 8"):
        loads('{\n  "a": 1,\n  "a" 2,\n}')


def test_non_json_constants_are_rejected():
    for text in ('{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}'):
        with pytest.raises(CanonError, match="is not valid JSON"):
            loads(text)


def test_file_is_parsed_from_disk(tmp_path):
    path = tmp_path / "policy.hujson"
    path.write_text(_ANNOTATED, encoding="utf-8-sig")

    assert load_file(str(path)) == loads(_PLAIN)


# The admin API accepts two spellings of the same ACL entry.
def test_legacy_users_and_ports_canonicalise_like_src_and_dst():
    assert canonicalise(_LEGACY_ACL) == canonicalise(_MODERN_ACL)


def test_legacy_acl_spelling_renders_the_same_text():
    assert render(_LEGACY_ACL).body == render(_MODERN_ACL).body


def test_ssh_users_are_not_renamed_to_src():
    # An ssh rule's `users` names local unix accounts, so the rename that unifies
    # an ACL entry would quietly rewrite who may log in.
    policy = {
        "ssh": [
            {
                "action": "check",
                "src": ["autogroup:member"],
                "dst": ["autogroup:self"],
                "users": ["root", "ubuntu"],
            }
        ]
    }

    assert canonicalise(policy)["ssh"][0]["users"] == ["root", "ubuntu"]


def test_acl_entry_carrying_both_spellings_keeps_both():
    # The server's own handling of the pair is undocumented, so neither principal
    # is dropped to guess at it.
    policy = {
        "acls": [
            {
                "action": "accept",
                "users": ["autogroup:member"],
                "src": ["group:web"],
                "ports": ["tag:web:443"],
            }
        ]
    }

    entry = canonicalise(policy)["acls"][0]
    assert entry["src"] == ["group:web"]
    assert entry["users"] == ["autogroup:member"]
    assert entry["dst"] == ["tag:web:443"]


def test_acl_action_is_preserved():
    policy = {"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"], "via": ["x"]}]}

    assert canonicalise(policy)["acls"][0]["action"] == "accept"


def test_unknown_acl_keys_are_preserved():
    policy = {"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"], "futureField": 1}]}

    assert canonicalise(policy)["acls"][0]["futureField"] == 1


def test_unknown_top_level_keys_are_preserved():
    policy = {"futureSection": {"enabled": True}}

    assert canonicalise(policy)["futureSection"] == {"enabled": True}


# Syntax, key order and list order all separate text from meaning.
def test_comments_and_trailing_commas_do_not_change_the_canonical_form():
    assert canonicalise(loads(_ANNOTATED)) == canonicalise(loads(_PLAIN))


def test_source_key_order_does_not_change_the_canonical_form():
    assert canonicalise(loads(_REORDERED)) == canonicalise(loads(_PLAIN))


def test_annotated_and_reordered_spellings_canonicalise_alike():
    assert canonicalise(loads(_ANNOTATED)) == canonicalise(loads(_REORDERED))


def test_member_list_order_is_not_significant():
    desired = {"groups": {"group:web": ["alice@example.com", "bob@example.com"]}}
    actual = {"groups": {"group:web": ["bob@example.com", "alice@example.com"]}}

    assert canonicalise(desired) == canonicalise(actual)


def test_member_list_below_a_named_section_is_not_significant():
    # The approvers of a route sit two levels below the section that names them,
    # which is why a member set is identified by its whole path.
    desired = {"autoApprovers": {"routes": {"100.64.0.0/10": ["group:a", "group:b"]}}}
    actual = {"autoApprovers": {"routes": {"100.64.0.0/10": ["group:b", "group:a"]}}}

    assert canonicalise(desired) == canonicalise(actual)


def test_list_directly_under_a_member_section_keeps_its_order():
    # Only a list that is the value of a mapping holds members, so a shape no
    # section of the policy file produces falls back to the default.
    policy = {"groups": ["bob@example.com", "alice@example.com"]}

    assert canonicalise(policy) == policy


def test_acl_rule_order_is_significant():
    # Two documents holding the same two rules in opposite order are different
    # documents, so a reordering is a change the run has to report.
    rule = {"action": "accept", "src": ["group:a"], "dst": ["*:*"]}
    other = {"action": "accept", "src": ["group:b"], "dst": ["*:*"]}
    first = {"acls": [rule, other]}
    second = {"acls": [other, rule]}

    assert canonicalise(first) != canonicalise(second)
    assert diff(first, second) == [
        {
            "path": "/acls/0/src/0",
            "change": "modified",
            "desired": "group:a",
            "actual": "group:b",
        },
        {
            "path": "/acls/1/src/0",
            "change": "modified",
            "desired": "group:b",
            "actual": "group:a",
        },
    ]


# A member set has to be added to `_MEMBER_SET_MAPS` when the server stops
# preserving an order, and never otherwise. These pin the orders the server was
# measured to keep: it returned each of them exactly as it was sent, so sorting
# any of them would fold an unrelated edit into a rewrite of the section. The
# measurement is recorded in the module_utils docstring of `_vocabulary`.
_APP_CONNECTORS = "tailscale.com/app-connectors"


def _with_connectors(entries):
    return {"acls": [], "nodeAttrs": [{"target": ["*"], "app": {_APP_CONNECTORS: entries}}]}


def test_app_connector_list_order_is_significant():
    first = {"name": "a", "connectors": ["tag:a"], "domains": ["a.example.com"]}
    second = {"name": "b", "connectors": ["tag:b"], "domains": ["b.example.com"]}

    assert canonicalise(_with_connectors([first, second])) != canonicalise(
        _with_connectors([second, first])
    )
    assert diff(_with_connectors([first, second]), _with_connectors([second, first])), (
        "reported element by element, because the index is what a connector is addressed by"
    )


def test_the_lists_inside_a_connector_keep_their_order():
    entry = {
        "name": "a",
        "connectors": ["tag:z", "tag:a"],
        "domains": ["z.example.com", "a.example.com"],
        "routes": ["0.0.0.0/0", "::/0"],
    }

    assert canonicalise(_with_connectors([entry])) == _with_connectors([entry])


def test_the_node_attribute_list_keeps_its_order():
    attributes = [
        {"target": ["*"], "app": {_APP_CONNECTORS: [{"name": "a", "connectors": ["tag:a"]}]}},
        {"target": ["tag:a"], "attr": ["funnel"]},
    ]
    other = [attributes[1], attributes[0]]

    assert canonicalise({"nodeAttrs": attributes}) != canonicalise({"nodeAttrs": other})


def test_the_tests_list_keeps_its_order():
    first = {"src": "alice@example.com", "deny": ["1.2.3.4:22"]}
    second = {"src": "bob@example.com", "accept": ["1.2.3.4:443"]}

    assert canonicalise({"tests": [first, second]}) != canonicalise({"tests": [second, first]})


def test_render_pairs_the_body_with_the_hujson_content_type():
    rendered = render({"acls": []})

    assert rendered.content_type == "application/hujson"
    assert rendered.body == '{\n  "acls": []\n}\n'
    assert loads(rendered.body) == {"acls": []}


def test_rendered_body_parses_back_to_the_same_canonical_form():
    rendered = render(loads(_ANNOTATED))

    assert canonicalise(loads(rendered.body)) == canonicalise(loads(_ANNOTATED))


# The comparison is the only source of `changed`, so its shape carries the
# contract: an empty list means the run has nothing to write. Every difference
# says what writing the desired document does to the actual one, so a key only
# the desired document has is added and carries its desired value, and a key
# only the actual document has is removed and carries its actual value.
def test_reports_no_difference_for_equivalent_policies():
    assert diff(loads(_ANNOTATED), loads(_REORDERED)) == []


def test_diff_compares_a_raw_document_against_a_canonical_one():
    # A raw API response against an already canonicalised desired document is
    # the shape the reconciliation kernel hands over most often.
    assert diff(loads(_ANNOTATED), canonicalise(loads(_REORDERED))) == []


def test_reports_a_changed_acl_destination():
    desired = {"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:web:443"]}]}
    actual = {"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:web:80"]}]}

    assert diff(desired, actual) == [
        {
            "path": "/acls/0/dst/0",
            "change": "modified",
            "desired": "tag:web:443",
            "actual": "tag:web:80",
        }
    ]


def test_reports_added_and_removed_keys():
    desired = {"acls": [], "hosts": {"printer": "100.64.0.9"}}
    actual = {"acls": [], "ssh": []}

    assert diff(desired, actual) == [
        {"path": "/hosts", "change": "added", "desired": {"printer": "100.64.0.9"}},
        {"path": "/ssh", "change": "removed", "actual": []},
    ]


def test_reports_a_key_added_to_an_acl_rule():
    desired = {"acls": [{"action": "accept", "src": ["group:a"], "dst": ["*:*"]}]}
    actual = {"acls": [{"action": "accept", "src": ["group:a"]}]}

    assert diff(desired, actual) == [{"path": "/acls/0/dst", "change": "added", "desired": ["*:*"]}]


def test_reports_a_key_removed_from_an_acl_rule():
    desired = {"acls": [{"action": "accept", "src": ["group:a"]}]}
    actual = {"acls": [{"action": "accept", "src": ["group:a"], "dst": ["*:*"]}]}

    assert diff(desired, actual) == [
        {"path": "/acls/0/dst", "change": "removed", "actual": ["*:*"]}
    ]


def test_reports_added_and_removed_ordered_entries_by_index():
    # `nodeAttrs` is order-significant, so a length change is reported position
    # by position rather than as a single replaced value, and a difference
    # inside an entry is reported at the node that differs.
    desired = {"nodeAttrs": [{"attr": ["funnel"], "value": ["true"]}, {"attr": ["ssh"]}]}
    actual = {"nodeAttrs": [{"attr": ["ssh"]}]}

    assert diff(desired, actual) == [
        {
            "path": "/nodeAttrs/0/attr/0",
            "change": "modified",
            "desired": "funnel",
            "actual": "ssh",
        },
        {"path": "/nodeAttrs/0/value", "change": "added", "desired": ["true"]},
        {"path": "/nodeAttrs/1", "change": "added", "desired": {"attr": ["ssh"]}},
    ]
    assert diff(desired=actual, actual=desired) == [
        {
            "path": "/nodeAttrs/0/attr/0",
            "change": "modified",
            "desired": "ssh",
            "actual": "funnel",
        },
        {"path": "/nodeAttrs/0/value", "change": "removed", "actual": ["true"]},
        {"path": "/nodeAttrs/1", "change": "removed", "actual": {"attr": ["ssh"]}},
    ]


def test_reports_a_member_set_change_as_one_difference():
    desired = {"groups": {"group:web": ["alice@example.com", "bob@example.com"]}}
    actual = {"groups": {"group:web": ["alice@example.com", "carol@example.com"]}}

    # One value, not two indices, because a member set is a set.
    assert diff(desired, actual) == [
        {
            "path": "/groups/group:web",
            "change": "modified",
            "desired": ["alice@example.com", "bob@example.com"],
            "actual": ["alice@example.com", "carol@example.com"],
        }
    ]


def test_escapes_reserved_characters_in_a_path():
    desired = {"groups": {"group:a/b~c": ["alice@example.com"]}}
    actual = {"groups": {"group:a/b~c": []}}

    assert [change["path"] for change in diff(desired, actual)] == ["/groups/group:a~1b~0c"]


def test_keeps_a_boolean_distinct_from_a_number():
    # Python would call `True == 1`, JSON would not.
    assert diff({"futureFlag": True}, {"futureFlag": 1}) == [
        {"path": "/futureFlag", "change": "modified", "desired": True, "actual": 1}
    ]
