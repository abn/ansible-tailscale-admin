# SPDX-License-Identifier: BSD-2-Clause
"""The parts of a policy document a task can declare, rather than only write.

Internal to this collection. The path carries a leading underscore, which
declares the kernel private: it can be refactored in any release without a major
version bump. See ``.agents/rules/ansible.md``.

:mod:`._policy` reconciles a whole document, and a document is HuJSON an operator
writes. Three sections of that language are regular enough to be worth naming on
a task, and each of them nests in a way the file format makes awkward: ``groups``
is a map of member lists, an app connector is a list of entries inside a map
inside a list of node attributes, and ``tests`` is a list of assertions. This
file folds a task's declaration of those three into a document and reports what
the document still lacks.

Two rules decide the shape of the result.

**A declared section is merged, and a conflict is refused.** A task names what it
wants; the file says what the tailnet should otherwise hold. Where the two
disagree about the same group, the same connector name or the same target, the
module picks neither, because a silent precedence would let a playbook overwrite
its own file without saying so. Refusing costs nothing: the conflict is visible
in the file and in the task, and no request is spent.

**A prerequisite the server enforces is refused before the request; one it
tolerates is a warning.** Measured against the real API, an app connector naming
a tag that ``tagOwners`` does not declare is refused with a 400 and the write
never lands, so refusing it here turns a rejected write into a message that names
the missing line. The same connector missing its route approvers, or any access
rule permitting discovery of its tag, is accepted and quietly routes nothing.
Those are warnings, because the document is still what the operator asked for and
the server has no opinion about it.

What the server does to a document on the way in and out
--------------------------------------------------------

Measured by writing each shape to a throwaway tailnet and reading it back, since
a second run reporting a change for ever is the failure this collection cannot
ship and no mock can predict it.

* It sorts the members of a group, which the canonical form already treats as a
  set, so a declared group's members converge whichever order they were written.
* It preserves the order of the app connector list, of the ``targets``, the
  ``domains`` and the ``routes`` inside one entry, of the ``nodeAttrs`` list and
  of the ``tests`` list. None of them is a member set, so none is sorted here.
* It accepts an app map only on a node attribute entry whose target is exactly
  ``["*"]``, and answers anything else with
  ``tailscale.com/app-connectors: can only be specified with target "*"``.
* It refuses a custom app with no ``domains``, or with an empty one, and refuses
  ``domains`` that are not empty when a ``presetAppID`` is set, because the
  domains of a preset app are fetched by Tailscale rather than written here. A
  declared preset app therefore carries no ``domains`` key at all rather than an
  empty one, and the server stores what it was sent: an empty list sent with a
  preset comes back as an empty list, and an absent one comes back absent.
* It validates ``presetAppID`` and answers an identifier it does not recognise
  with ``preset app ID (...) is not valid``, and a connector that is not a
  declared tag with ``connector (...) must be a tag``.
* It refuses duplicate ``connectors``, duplicate ``domains``, an empty ``name``
  and a wildcard over a top-level domain. The public suffix list needed to judge
  the last one locally is not something this collection carries, so that one is
  left to the server, whose message names the domain.

None of the checks here replace the server's. They exist to spend no request on
a document the server will refuse, and to name the line to fix.
"""

from __future__ import annotations

from collections.abc import Iterable
from collections.abc import Mapping
from copy import deepcopy
from typing import Any
from typing import Final

from ansible_collections.abn.tailscale.plugins.module_utils._tailscale._canon import canonicalise

__all__ = [
    "PARAMETRISED_PRESETS",
    "PRESET_APPS",
    "PRESET_NAMES",
    "VocabularyError",
    "compose",
]


class VocabularyError(Exception):
    """A declaration on the task cannot be folded into the document.

    A :class:`._policy.PolicyError` sibling rather than an alias of it, because
    nothing was sent either way but the remedy differs: a ``PolicyError`` names
    the API's objection, and this one names the option in the playbook.
    """


#: The capability an app connector is declared under. The name is the capability
#: provider's domain, so a document can carry capabilities this collection knows
#: nothing about under other keys, and it leaves them alone.
APP_CONNECTORS: Final = "tailscale.com/app-connectors"

#: The preset apps Tailscale publishes, under the name it publishes them, mapped
#: to the ``presetAppID`` each one carries. The two are not interchangeable:
#: ``Google Workspace`` is ``google-workspace``, and ``Salesforce
#: (Salesforce-hosted)`` is ``salesforce`` while the Hyperforce environment is
#: ``salesforce-hyperforce``. A wrong identifier is a connector that fetches
#: nothing, so the mapping is the module's job rather than the operator's.
#: https://tailscale.com/docs/features/app-connectors/how-to/setup#edit-preset-apps
PRESET_APPS: Final[dict[str, str]] = {
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

#: The preset apps whose identifier carries the region they apply to, mapped to
#: the pattern Tailscale publishes. Those trailing segments are AWS availability
#: zones and local zones, and Oracle regions, and Tailscale owns both lists, so a
#: declared identifier is passed through rather than composed from a task's guess
#: at a region name. A shape the server does not recognise is refused with
#: ``preset app ID (...) is not valid`` rather than accepted as a connector that
#: fetches nothing.
PARAMETRISED_PRESETS: Final[dict[str, str]] = {
    "AWS EC2/ELB": "aws-ec2-<region>-<availability-zone>-<local-zone>",
    "AWS S3": "aws-s3-<region>-<availability-zone>-<local-zone>",
    "Oracle Cloud Infrastructure (OCI)": "oracle-oci-<region>",
    "Oracle Object Storage": "oracle-object-storage-<region>",
}

#: Every preset app name a task may use, the fixed ones first so the
#: documentation's list and the argument spec's ``choices`` read the same way.
PRESET_NAMES: Final[tuple[str, ...]] = (*PRESET_APPS, *PARAMETRISED_PRESETS)

#: The node attribute target an app map is only accepted under.
_WILDCARD: Final[list[str]] = ["*"]

#: How many findings of one kind to name. A policy with a hundred undeclared
#: groups produces a hundred lines, which is a wall rather than a report.
MAX_REPORTED: Final = 5

_GROUP: Final = "group:"
_TAG: Final = "tag:"

#: Distinguishes a key the document does not hold from one it holds as null,
#: which a policy file can express and which means nothing.
_ABSENT: Final = object()

#: Where each mergeable section is read in a document. A member set is identified
#: by its whole path, so a comparison has to canonicalise through the path the
#: value is actually read at rather than through its own.
_GROUPS_PATH: Final = ("groups",)
_CONNECTORS_PATH: Final = ("nodeAttrs", "*", "app", APP_CONNECTORS, "*")


#: The rule fields that name a target, and the sections they sit in. An
#: `acls` destination carries a port after the host, so the host is read through
#: :func:`_host_of`; the rest name a host or a user outright. An `acls` entry
#: still spells them `users` and `ports` in the legacy form the API accepts, and
#: the node a group was named at is reported as it was written.
_SOURCES: Final = (
    ("acls", "src"),
    ("acls", "users"),
    ("grants", "src"),
    ("ssh", "src"),
    ("ssh", "dst"),
)
_DESTINATIONS: Final = (("acls", "dst"), ("acls", "ports"), ("grants", "dst"))


def compose(
    document: Any,
    *,
    groups: Mapping[str, list[str]] | None = None,
    app_connectors: list[Mapping[str, Any]] | None = None,
    tests: list[Mapping[str, Any]] | None = None,
) -> tuple[Any, list[str]]:
    """Fold a task's declarations into a document, and report what it still lacks.

    The document is copied, so the file the caller read is not modified. Raises
    :class:`VocabularyError` for anything the server would refuse, and for a
    conflict between the file and the task. The findings are the rest: the
    document is writable, and something in it will not do what it looks like it
    does.
    """
    composed = deepcopy(document)
    declared = bool(groups or app_connectors or tests)
    if not isinstance(composed, dict):
        if not declared:
            return composed, []
        raise VocabularyError(
            "This task declares part of the policy, and the policy file is not a JSON "
            "object, so there is nothing to declare it into."
        )

    findings: list[str] = []
    if groups:
        _merge_groups(composed, groups)
    if app_connectors:
        _merge_connectors(composed, app_connectors, findings)
    if tests:
        _merge_tests(composed, tests)
    findings.extend(_undeclared_groups(composed))
    return composed, findings


# Groups
# ------


def _merge_groups(document: dict[str, Any], declared: Mapping[str, list[str]]) -> None:
    existing = document.get("groups", {})
    if not isinstance(existing, dict):
        raise VocabularyError(
            "The 'groups' key in the policy file is not a mapping of group name to "
            "members, so a group declared on the task cannot be added to it."
        )
    for name, members in declared.items():
        _check_group(name, members)
        present = existing.get(name, _ABSENT)
        if present is not _ABSENT and _at((*_GROUPS_PATH, name), present) != _at(
            (*_GROUPS_PATH, name), list(members)
        ):
            raise VocabularyError(
                f"Group {name!r} is declared twice with different members: the policy "
                f"file says {present!r} and the task says {list(members)!r}. Change one "
                "of them; the module will not pick a winner, because a silent precedence "
                "would let a task overwrite its own policy file."
            )
        existing[name] = list(members)
    document["groups"] = existing


def _at(path: tuple[str, ...], value: Any) -> Any:
    """`value` in canonical form, as though it sat at `path` in a document.

    A member set is identified by its whole path, so a group read on its own has
    no members to sort and comparing two spellings of it that way would report a
    difference the server does not have. A `*` is a placeholder for whatever
    index or name the value carries at that point.
    """
    document: Any = value
    for step in reversed(path):
        document = {step: document}
    return canonicalise(document)


def _check_group(name: str, members: Any) -> None:
    if not name.startswith(_GROUP):
        raise VocabularyError(
            f"Group {name!r} does not start with {_GROUP!r}. Tailscale identifies a "
            f"group by that prefix, and a rule naming it without the prefix is read as "
            "a user login."
        )
    if not isinstance(members, list) or not all(
        isinstance(member, str) and member for member in members
    ):
        raise VocabularyError(
            f"Group {name!r} must be a list of member logins, each a non-empty string, "
            "such as ['alice@example.com']."
        )


# App connectors
# --------------


def _merge_connectors(
    document: dict[str, Any], declared: list[Mapping[str, Any]], findings: list[str]
) -> None:
    entries = [_connector(declaration) for declaration in declared]
    for entry in entries:
        _check_tag_owner(document, entry)
    _check_discovery(document, entries, findings)

    holder = _app_map_holder(document)
    existing = holder["app"].get(APP_CONNECTORS, [])
    if not isinstance(existing, list):
        raise VocabularyError(
            f"The {APP_CONNECTORS!r} list in the policy file is not a list, so an app "
            "connector declared on the task cannot be added to it."
        )
    for entry in entries:
        present = _named_entry(existing, entry["name"])
        if present is None:
            existing.append(entry)
        elif _at(_CONNECTORS_PATH, present) != _at(_CONNECTORS_PATH, entry):
            raise VocabularyError(
                f"App connector {entry['name']!r} is declared twice with different "
                f"settings: the policy file says {present!r} and the task says "
                f"{entry!r}. An app connector is identified by its name, so these would "
                "be one connector written two ways."
            )
    holder["app"][APP_CONNECTORS] = existing


def _named_entry(entries: list[Any], name: str) -> dict[str, Any] | None:
    for entry in entries:
        if isinstance(entry, dict) and entry.get("name") == name:
            return entry
    return None


def _app_map_holder(document: dict[str, Any]) -> dict[str, Any]:
    """The node attribute entry an app connector is written under, created if absent.

    The map goes on an entry targeting every node, because that is the only
    target the server accepts it under. An entry already carrying a map under a
    narrower target is refused rather than left to fail the write with a message
    about a line the operator did not write on the task.
    """
    attributes = document.get("nodeAttrs", [])
    if not isinstance(attributes, list):
        raise VocabularyError(
            "The 'nodeAttrs' key in the policy file is not a list, so an app connector "
            "declared on the task cannot be added to it."
        )
    for entry in attributes:
        if not isinstance(entry, dict) or not isinstance(entry.get("app"), dict):
            continue
        if entry.get("target") != _WILDCARD:
            raise VocabularyError(
                f"The policy file puts an app map on a node attribute entry targeting "
                f"{entry.get('target')!r}. The server accepts an app map only on an "
                f"entry targeting every node, and answers anything else with "
                f'{APP_CONNECTORS!r}: can only be specified with target "*".'
            )
        return entry
    holder: dict[str, Any] = {"target": list(_WILDCARD), "app": {}}
    attributes.append(holder)
    document["nodeAttrs"] = attributes
    return holder


def _connector(declaration: Mapping[str, Any]) -> dict[str, Any]:
    """One app connector as the document carries it, or an error naming the option."""
    name = declaration.get("name")
    if not isinstance(name, str) or not name:
        raise VocabularyError(
            "An app connector declared on the task needs a 'name', which is how the "
            "console and the policy file identify one. The server refuses an empty "
            "name with 'name must not be empty'."
        )
    preset = declaration.get("preset")
    preset_id = declaration.get("preset_id")
    if preset and preset_id:
        raise VocabularyError(
            f"App connector {name!r} sets both 'preset' and 'preset_id'. 'preset' names "
            "an integration this module holds the identifier for, and 'preset_id' gives "
            "the identifier itself."
        )

    entry: dict[str, Any] = {"name": name, "connectors": _connectors(declaration)}
    if preset:
        entry["presetAppID"] = _preset_id(preset, name)
    elif preset_id:
        if not isinstance(preset_id, str) or not preset_id.strip():
            raise VocabularyError(
                f"App connector {name!r} sets 'preset_id' to an empty value. It is the "
                "identifier Tailscale's Apps page shows, such as 'github'."
            )
        entry["presetAppID"] = preset_id
    else:
        entry["domains"] = _domains(declaration)
    routes = declaration.get("routes")
    if routes:
        entry["routes"] = _strings(routes, "routes", name)
    return entry


def _connectors(declaration: Mapping[str, Any]) -> list[str]:
    name = declaration.get("name")
    connectors = declaration.get("connectors")
    if not isinstance(connectors, list) or not connectors:
        raise VocabularyError(
            f"App connector {name!r} needs 'connectors', the tags of the devices that "
            "route its traffic. The server refuses an empty list with 'connectors must "
            "not be empty'."
        )
    tags = _strings(connectors, "connectors", name)
    for tag in tags:
        if not tag.startswith(_TAG):
            raise VocabularyError(
                f"App connector {name!r} lists {tag!r} as a connector. A connector is a "
                f"device, so it is named by a tag beginning {_TAG!r}; the server answers "
                "anything else with 'must be a tag'."
            )
    if len(set(tags)) != len(tags):
        raise VocabularyError(
            f"App connector {name!r} lists a connector tag twice. The server refuses the "
            "duplicate with 'connectors must not contain duplicates'."
        )
    return tags


def _domains(declaration: Mapping[str, Any]) -> list[str]:
    name = declaration.get("name")
    domains = declaration.get("domains")
    if domains is None:
        raise VocabularyError(
            f"App connector {name!r} names no preset app, so it needs 'domains': the "
            "applications it routes are named, not fetched by Tailscale. The server "
            "refuses a custom app with no domains."
        )
    listed = _strings(domains, "domains", name)
    if not listed:
        raise VocabularyError(
            f"App connector {name!r} has an empty 'domains' list. A custom app has to "
            "name the domains it routes, and the server refuses an empty one."
        )
    if len(set(listed)) != len(listed):
        raise VocabularyError(
            f"App connector {name!r} lists a domain twice. The server refuses the "
            "duplicate with 'domains must not contain duplicates'."
        )
    return listed


def _preset_id(preset: Any, name: Any) -> str:
    if preset in PRESET_APPS:
        return PRESET_APPS[preset]
    if preset in PARAMETRISED_PRESETS:
        raise VocabularyError(
            f"App connector {name!r} asks for the preset app {preset!r}, whose "
            "identifier carries the region it applies to: "
            f"{PARAMETRISED_PRESETS[preset]}. Give that identifier as 'preset_id' "
            "instead, and set no 'domains': Tailscale fetches the domains of a preset "
            "app itself."
        )
    raise VocabularyError(
        f"App connector {name!r} asks for a preset app this module does not know, "
        f"{preset!r}. The published ones are {', '.join(PRESET_NAMES)}."
    )


def _strings(values: Any, option: str, name: Any) -> list[str]:
    if not isinstance(values, list) or not all(
        isinstance(value, str) and value for value in values
    ):
        raise VocabularyError(
            f"App connector {name!r} needs {option!r} to be a list of non-empty strings."
        )
    return list(values)


def _check_tag_owner(document: Mapping[str, Any], entry: Mapping[str, Any]) -> None:
    owners = document.get("tagOwners", {})
    if not isinstance(owners, dict):
        raise VocabularyError(
            "The 'tagOwners' key in the policy file is not a mapping, so the tag an app "
            "connector needs cannot be checked against it."
        )
    missing = [tag for tag in entry["connectors"] if tag not in owners]
    if not missing:
        return
    raise VocabularyError(
        f"App connector {entry['name']!r} routes through "
        f"{', '.join(repr(tag) for tag in missing)}, which 'tagOwners' does not declare. "
        f"A tag exists only where the policy grants it, and the server refuses the whole "
        f"write with 'connector ({missing[0]}) must be a tag' otherwise. Add a 'tagOwners' "
        f"entry naming who may assign {missing[0]}."
    )


def _check_discovery(
    document: Mapping[str, Any], entries: Iterable[Mapping[str, Any]], findings: list[str]
) -> None:
    """Name the connector prerequisites the server accepts a document without.

    An app connector resolves its domains over the PeerAPI, so a device has to
    reach the connector's tag before it discovers anything. A connector that is
    neither reachable nor approved routes no traffic, and the document declaring
    it is accepted all the same.
    """
    reachable = _reachable_tags(document)
    approved = _approved_tags(document)
    declared = list(entries)
    for tag in sorted({tag for entry in declared for tag in entry["connectors"]}):
        if tag not in reachable:
            findings.append(
                f"App connector {tag!r} is reachable by no access rule. A client "
                "discovers an app's addresses by querying the connector, so it needs "
                f"access to {tag} on port 53 before anything routes, for example a grant "
                f"of src ['autogroup:member'] to dst ['{tag}'] on ip ['tcp:53', "
                "'udp:53']."
            )
        if tag in approved:
            continue
        if any("presetAppID" in entry for entry in declared if tag in entry["connectors"]):
            # A preset app's own routes are fetched and approved by Tailscale. Only
            # routes it discovers afterwards need an approver, and that difference is
            # not visible from the document, so the case is left to the operator.
            continue
        findings.append(
            f"App connector {tag!r} has no auto-approver for its routes. A custom app "
            "has to have its routes approved, so add the tag to the approvers in "
            "'autoApprovers'."
        )


def _reachable_tags(document: Mapping[str, Any]) -> set[str]:
    """The tags some access rule sends traffic to."""
    found = {
        _host_of(selector)
        for section, field in _DESTINATIONS
        for rule in _entries(document, section)
        for selector in _selectors(rule, field)
    }
    return {selector for selector in found if selector.startswith(_TAG)}


def _approved_tags(document: Mapping[str, Any]) -> set[str]:
    """The principals named as the approvers of a route or of an exit node."""
    approvers = document.get("autoApprovers", {})
    if not isinstance(approvers, dict):
        return set()
    found: set[str] = set()
    sections: list[Any] = [approvers.get("exitNode")]
    routes = approvers.get("routes")
    if isinstance(routes, dict):
        sections.extend(routes.values())
    for section in sections:
        if isinstance(section, list):
            found.update(item for item in section if isinstance(item, str))
    return found


# Access tests
# ------------


def _merge_tests(document: dict[str, Any], declared: list[Mapping[str, Any]]) -> None:
    existing = document.get("tests", [])
    if not isinstance(existing, list):
        raise VocabularyError(
            "The 'tests' key in the policy file is not a list, so an access test "
            "declared on the task cannot be added to it."
        )
    document["tests"] = [*existing, *(_test(test) for test in declared)]


def _test(declaration: Mapping[str, Any]) -> dict[str, Any]:
    src = declaration.get("src")
    if not isinstance(src, str) or not src:
        raise VocabularyError(
            "An access test declared on the task needs a 'src', the identity the test "
            "runs from: a user login, a group, a tag or a Tailscale IP."
        )
    test: dict[str, Any] = {"src": src}
    asserted = False
    for field in ("accept", "deny"):
        destinations = declaration.get(field)
        if not destinations:
            continue
        test[field] = _destinations(destinations, field, src)
        asserted = True
    if not asserted:
        raise VocabularyError(
            f"Access test {src!r} asserts nothing. Give it an 'accept' list of the "
            "destinations it must reach, a 'deny' list of the ones it must not, or both."
        )
    proto = declaration.get("proto")
    if proto:
        test["proto"] = proto
    posture = declaration.get("src_posture_attrs")
    if posture:
        if not isinstance(posture, dict) or not all(
            isinstance(key, str) and key and isinstance(value, (str, int, float, bool))
            for key, value in posture.items()
        ):
            raise VocabularyError(
                f"Access test {src!r} needs 'src_posture_attrs' to map a posture "
                "attribute to a string, a number or a boolean, such as "
                "{'node:os': 'linux'}."
            )
        test["srcPostureAttrs"] = dict(posture)
    return test


def _destinations(values: Any, field: str, src: str) -> list[str]:
    if not isinstance(values, list) or not all(
        isinstance(value, str) and value for value in values
    ):
        raise VocabularyError(
            f"Access test {src!r} needs {field!r} to be a list of non-empty 'host:port' "
            "strings, such as ['example-host-1:22']."
        )
    return list(values)


# Groups a rule names and the document does not declare
# ------------------------------------------------------


def _undeclared_groups(document: Mapping[str, Any]) -> list[str]:
    """Name the groups the rules use and the document does not declare.

    The server refuses such a document with ``group not found`` unless the group
    is synced from an identity provider, and a policy file cannot show that, so
    this is a warning rather than a refusal: a synced group is a group the file
    is right not to declare.
    """
    declared = document.get("groups", {})
    known = set(declared) if isinstance(declared, dict) else set()
    first_seen: dict[str, str] = {}
    for node, name in _group_references(document):
        if name not in known and name not in first_seen:
            first_seen[name] = node
    if not first_seen:
        return []

    findings = [
        f"The policy names {name} at {node} and does not declare it. The server refuses "
        "the whole write with 'group not found' unless the group is synced from an "
        "identity provider, which a policy file cannot show. Declare the group on the "
        "task or in the file, or expect it to be synced."
        for name, node in sorted(first_seen.items())[:MAX_REPORTED]
    ]
    if len(first_seen) > MAX_REPORTED:
        findings.append(
            f"{len(first_seen) - MAX_REPORTED} more group(s) are named and not declared."
        )
    return findings


def _group_references(document: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Every group the document names, with the node it was named at."""
    found: list[tuple[str, str]] = []
    fields = (*_SOURCES, *_DESTINATIONS, ("tests", "src"), ("nodeAttrs", "target"))
    for section, field in fields:
        for index, entry in enumerate(_entries(document, section)):
            for selector in _selectors(entry, field):
                for name in _group_names(selector):
                    found.append((f"/{section}/{index}/{field}", name))
    for name, values in _owner_approvers(document):
        for selector in values:
            for group in _group_names(selector):
                found.append((name, group))
    return found


def _owner_approvers(document: Mapping[str, Any]) -> list[tuple[str, list[str]]]:
    """The tag owners, the route approvers and the exit node approvers, as nodes."""
    found: list[tuple[str, list[str]]] = []
    owners = document.get("tagOwners")
    if isinstance(owners, dict):
        for tag, values in owners.items():
            if isinstance(values, list):
                found.append((f"/tagOwners/{tag}", list(values)))
    approvers = document.get("autoApprovers")
    if isinstance(approvers, dict):
        exit_node = approvers.get("exitNode")
        if isinstance(exit_node, list):
            found.append(("/autoApprovers/exitNode", list(exit_node)))
        routes = approvers.get("routes")
        if isinstance(routes, dict):
            for route, values in routes.items():
                if isinstance(values, list):
                    found.append((f"/autoApprovers/routes/{route}", list(values)))
    return found


def _group_names(selector: str) -> list[str]:
    """The group a selector names, if it names one, as the document spells it.

    A group is identified by its prefix and can carry a port after it in an
    `acls` destination, so what follows the prefix is the name up to a port.
    """
    if not selector.startswith(_GROUP):
        return []
    rest = selector[len(_GROUP) :]
    name, separator, ports = rest.partition(":")
    if separator and not _is_ports(ports):
        return []
    return [f"{_GROUP}{name}"] if name else []


def _entries(document: Mapping[str, Any], section: str) -> list[dict[str, Any]]:
    entries = document.get(section)
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def _selectors(entry: Mapping[str, Any], field: str) -> list[str]:
    value = entry.get(field)
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _host_of(selector: str) -> str:
    """The host part of a destination, which carries the port after a colon.

    Whether the tail is a port is read rather than assumed, because a group name
    is a prefix and a colon inside one belongs to the name: `group:engineering`
    has no port, and cutting one off the end would name `group:engine`.
    """
    head, separator, tail = selector.rpartition(":")
    if not separator or not head or not _is_ports(tail):
        return selector
    return head


def _is_ports(tail: str) -> bool:
    """Whether the tail of a destination is a port, or several of them."""
    return bool(tail) and all(part == "*" or part.isdigit() for part in tail.split(","))
