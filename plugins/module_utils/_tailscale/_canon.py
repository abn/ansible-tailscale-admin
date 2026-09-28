# SPDX-License-Identifier: BSD-2-Clause
"""Canonical form of a Tailscale policy file.

Internal to this collection. The path carries a leading underscore, which
declares the kernel private: it can be refactored in any release without a major
version bump. See ``.agents/rules/ansible.md``.

Why a canonical form exists
---------------------------

The same policy serialises differently depending on who wrote it and when. It
can be HuJSON or strict JSON, the admin API accepts both a legacy and a modern
spelling of an ACL entry, key order and list order are free, and the server
materialises defaults and echoes back its own normalisation of whatever was
sent. Textual equality therefore never holds, and comparing a desired document
against what the server returned by string is the largest single source of
perpetual ``changed`` in a naive implementation.

The canonical form
------------------

A canonical document is plain Python built from ``dict``, ``list``, ``str``,
``bool``, ``int``, ``float`` and ``None``, under three rules:

1. **Mapping keys are sorted.** Any fixed order we picked would still differ
   from the order the server chooses, so an order chosen here buys nothing over
   sorting except the need to keep it in step with the API.
2. **A named few lists are order-insensitive.** A list of members under one of
   the mappings in ``_MEMBER_SET_MAPS`` is a set, so it is sorted: ``groups``
   and ``tagOwners`` members, ``postures`` conditions, and the approvers of a
   route or of an exit node. Every other list keeps the order it was written
   in, and that includes every list of access rules: ``acls``, ``grants`` and
   ``ssh``. Their order carries no access meaning, because the only ``acls``
   action is ``accept`` and evaluation is additive, and an ``ssh`` rule in
   ``check`` mode applies ahead of any rule in ``accept`` mode however the two
   are written. The order is kept anyway, because the file is what an operator
   authors and reviews, and a canonicaliser that sorted the rules would fold an
   unrelated edit into a reshuffle of the whole policy. A new member set has to
   be added to ``_MEMBER_SET_MAPS``, and the default stays "keep the order"
   because a visible difference is recoverable while a hidden one is not.
3. **An ACL entry has one spelling.** ``users`` and ``ports`` are renamed to
   ``src`` and ``dst`` inside ``acls`` only, because an ``ssh`` rule's ``users``
   names local unix accounts and means something unrelated.

``render`` produces the same form ``diff`` compares, so the text a user reads in
a diff is the text that gets written.

Out of scope here
-----------------

* Comments and trailing commas are consumed on the way in and not reproduced on
  the way out. Preserving an operator's comments means sending their file
  rather than our rendering of it, which is a choice for the policy module.
* Defaults the server materialises are not injected, so a document that omits a
  field the server returns reports a difference. Filling defaults in belongs
  with the policy model, and a wrong guess rewrites access rules.
"""

from __future__ import annotations

import json
from typing import Any
from typing import NamedTuple
from typing import NoReturn

HUJSON_CONTENT_TYPE = "application/hujson"

INDENT = 2

# Paths of the mappings whose values are member sets rather than sequences, and
# are therefore sorted. `hosts` is absent because it maps a name to one value,
# so it never holds a member list. A mapping here has to name its members, which
# leaves a list sitting directly under one of these keys in the default.
_MEMBER_SET_MAPS = (
    ("autoApprovers",),
    ("autoApprovers", "routes"),
    ("groups",),
    ("postures",),
    ("tagOwners",),
)

# Legacy spellings of an ACL entry. Scoped to `acls`, because an `ssh` rule's
# `users` names local unix accounts and means something else entirely.
_ACL_KEY = "acls"
_ACL_RENAMES = {"users": "src", "ports": "dst"}

_STRING_FORBIDDEN = {
    0x08: "backspace",
    0x09: "tab",
    0x0A: "line feed",
    0x0C: "form feed",
    0x0D: "carriage return",
}


class CanonError(Exception):
    """A policy document could not be read as HuJSON."""


class Rendered(NamedTuple):
    """A document rendered for the API, paired with the content type to send it under.

    Labelling HuJSON as `application/json` makes the server parse it strictly and
    fail on the first comment, so the two travel together by construction.
    """

    body: str
    content_type: str


def load_file(path: str) -> Any:
    """Parse the HuJSON policy file at `path`.

    A path that does not exist, is a directory, or cannot be decoded is reported
    as a CanonError. It is the most likely first mistake, since the module runs
    under AnsiballZ with its working directory set to a temporary path, so a
    relative one never resolves; a traceback for a mistyped option is a poor
    answer to that.
    """
    # utf-8-sig consumes a byte order mark and is otherwise utf-8. A mark from a
    # Windows editor would otherwise reach the parser and fail there.
    try:
        with open(path, encoding="utf-8-sig") as handle:
            return loads(handle.read())
    except OSError as error:
        raise CanonError(f"cannot read the policy file at {path}: {error.strerror}") from None
    except UnicodeDecodeError:
        raise CanonError(f"the policy file at {path} is not valid UTF-8") from None


def loads(text: str) -> Any:
    """Parse HuJSON text into plain Python structures."""
    try:
        return json.loads(_without_extraneous_syntax(text), parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise CanonError(
            f"invalid HuJSON at line {exc.lineno} column {exc.colno}: {exc.msg}"
        ) from exc


def canonicalise(policy: Any) -> Any:
    """Return the canonical form of a policy document."""
    return _canonical(policy, ())


def render(policy: Any) -> Rendered:
    """Render a policy document as HuJSON, paired with the content type to send it under."""
    body = json.dumps(canonicalise(policy), indent=INDENT)
    # The trailing newline keeps a unified diff of two renderings from carrying a
    # "no newline at end of file" marker on every hunk.
    return Rendered(body=body + "\n", content_type=HUJSON_CONTENT_TYPE)


def diff(desired: Any, actual: Any) -> list[dict[str, Any]]:
    """Return the differences between a desired and an actual policy, empty if equivalent.

    Both sides are canonicalised first, so a caller cannot compare a raw API
    response against a canonicalised desired document and read the difference as
    a real change.

    A difference names the narrowest node that differs, by JSON Pointer, and
    says what writing `desired` does to `actual`: `added` carries the desired
    value, `removed` the actual one, `modified` both. A member set is the one
    node reported whole rather than element by element, because sorting has left
    its elements without a stable address.
    """
    return _diff(canonicalise(desired), canonicalise(actual), ())


def _canonical(value: Any, path: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        return {
            key: _canonical(value[key], (*path, str(key))) for key in sorted(value, key=_order_key)
        }
    if isinstance(value, list):
        if path and path[-1] == _ACL_KEY:
            return [_canonical_acl(item) for item in value]
        items = [_canonical(item, (*path, "*")) for item in value]
        if _is_member_set(path):
            items.sort(key=_order_key)
        return items
    return value


def _canonical_acl(entry: Any) -> Any:
    """Canonicalise one `acls` entry, renaming the legacy field spellings."""
    if not isinstance(entry, dict):
        return entry
    renamed = {}
    for key, value in entry.items():
        canonical_key = key
        replacement = _ACL_RENAMES.get(key)
        # An entry carrying both spellings keeps both. Renaming either one away
        # would drop a principal, and the server's own handling of the pair is
        # undocumented, so the ambiguity is left visible instead of resolved.
        if replacement is not None and replacement not in entry:
            canonical_key = replacement
        renamed[canonical_key] = value
    return _canonical(renamed, (_ACL_KEY, "*"))


def _is_member_set(path: tuple[str, ...]) -> bool:
    """True when the list at `path` holds the members of a set rather than a sequence."""
    return path[:-1] in _MEMBER_SET_MAPS


def _order_key(value: Any) -> tuple:
    """A total order over JSON values, so a sort cannot fail on mixed types.

    Comparing JSON values directly would raise on a document mixing strings and
    numbers, and Python's equality would rank `True` equal to `1`.
    """
    if value is None:
        return (0,)
    if isinstance(value, bool):
        return (1, value)
    if isinstance(value, (int, float)):
        return (2, value)
    if isinstance(value, str):
        return (3, value)
    if isinstance(value, list):
        return (4, tuple(_order_key(item) for item in value))
    if isinstance(value, dict):
        keys = sorted(value, key=_order_key)
        return (5, tuple((_order_key(key), _order_key(value[key])) for key in keys))
    raise CanonError(f"cannot canonicalise a value of type {type(value).__name__}")


def _diff(desired: Any, actual: Any, path: tuple[str, ...]) -> list[dict[str, Any]]:
    if isinstance(desired, dict) and isinstance(actual, dict):
        differences: list[dict[str, Any]] = []
        for key in sorted(set(desired) | set(actual), key=_order_key):
            child = (*path, str(key))
            if key not in actual:
                differences.append(_added(child, desired[key]))
            elif key not in desired:
                differences.append(_removed(child, actual[key]))
            else:
                differences.extend(_diff(desired[key], actual[key], child))
        return differences
    if isinstance(desired, list) and isinstance(actual, list):
        return _diff_list(desired, actual, path)
    if _same_scalar(desired, actual):
        return []
    return [_modified(path, desired, actual)]


def _diff_list(desired: list, actual: list, path: tuple[str, ...]) -> list[dict[str, Any]]:
    if _is_member_set(path):
        # A member set is one value, not a sequence. Reporting it element by
        # element would blame whichever index a sort happened to move.
        return [] if _same_list(desired, actual) else [_modified(path, desired, actual)]
    differences: list[dict[str, Any]] = []
    for index in range(max(len(desired), len(actual))):
        child = (*path, str(index))
        if index >= len(actual):
            differences.append(_added(child, desired[index]))
        elif index >= len(desired):
            differences.append(_removed(child, actual[index]))
        else:
            differences.extend(_diff(desired[index], actual[index], child))
    return differences


def _same_list(desired: list, actual: list) -> bool:
    return len(desired) == len(actual) and all(
        _same_scalar(want, have) for want, have in zip(desired, actual, strict=False)
    )


def _same_scalar(desired: Any, actual: Any) -> bool:
    """Equality that keeps a boolean distinct from a number, as JSON does."""
    if isinstance(desired, bool) is not isinstance(actual, bool):
        return False
    return desired == actual


def _added(path: tuple[str, ...], value: Any) -> dict[str, Any]:
    return {"path": _pointer(path), "change": "added", "desired": value}


def _removed(path: tuple[str, ...], value: Any) -> dict[str, Any]:
    return {"path": _pointer(path), "change": "removed", "actual": value}


def _modified(path: tuple[str, ...], desired: Any, actual: Any) -> dict[str, Any]:
    return {
        "path": _pointer(path),
        "change": "modified",
        "desired": desired,
        "actual": actual,
    }


def _pointer(path: tuple[str, ...]) -> str:
    """A JSON Pointer (RFC 6901) naming `path`. The empty string is the whole document."""
    return "".join("/" + part.replace("~", "~0").replace("/", "~1") for part in path)


def _without_extraneous_syntax(text: str) -> str:
    """Blank out HuJSON comments and trailing commas, leaving valid JSON behind.

    A comment becomes spaces rather than nothing, so the line numbers a parse
    error reports still point at the lines the operator wrote.
    """
    out: list[str] = []
    index = 0
    length = len(text)
    comma_pending = False

    while index < length:
        char = text[index]

        if char == '"':
            if comma_pending:
                out.append(",")
                comma_pending = False
            index = _copy_string(text, index, out)
            continue

        if char.isspace() or (char == "/" and text[index : index + 2] in ("//", "/*")):
            # Neither whitespace nor a comment says anything about whether the
            # comma before it is trailing, so both pass through with the
            # question still open.
            if char == "/":
                index = _skip_comment(text, index, out)
            else:
                out.append(char)
                index += 1
            continue

        if char == ",":
            comma_pending = True
            index += 1
            continue

        if char in "}]":
            comma_pending = False
            out.append(char)
            index += 1
            continue

        if comma_pending:
            out.append(",")
            comma_pending = False
        out.append(char)
        index += 1

    # A comma still pending here was trailing: `[1,` and `[1,]` are one document.
    return "".join(out)


def _skip_comment(text: str, index: int, out: list[str]) -> int:
    if text[index + 1] == "/":
        end = text.find("\n", index)
        end = len(text) if end == -1 else end
    else:
        end = text.find("*/", index + 2)
        if end == -1:
            raise CanonError(f"unterminated block comment at {_position(text, index)}")
        end += 2
    out.append(_blank(text[index:end]))
    return end


def _copy_string(text: str, index: int, out: list[str]) -> int:
    """Copy one string literal from its opening quote, escapes included.

    A backslash takes the character after it with it, so neither an escaped
    quote nor an escaped solidus ends the literal early, and a `//` or `/*`
    inside the literal is data rather than the start of a comment. A raw control
    character is refused here because the JSON parser reports it without a
    position.
    """
    start = index
    length = len(text)
    index += 1
    while index < length:
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            out.append(text[start : index + 1])
            return index + 1
        code = ord(char)
        if code < 0x20:
            raise CanonError(
                f"unescaped {_STRING_FORBIDDEN.get(code, f'U+{code:04X}')} in a string "
                f"at {_position(text, index)}"
            )
        index += 1
    raise CanonError(f"unterminated string starting at {_position(text, start)}")


def _blank(fragment: str) -> str:
    return "".join(char if char in "\r\n" else " " for char in fragment)


def _position(text: str, index: int) -> str:
    line = text.count("\n", 0, index) + 1
    column = index - (text.rfind("\n", 0, index) + 1) + 1
    return f"line {line} column {column}"


def _reject_constant(name: str) -> NoReturn:
    """Refuse `NaN`, `Infinity` and `-Infinity`, which JSON does not have."""
    raise CanonError(f"{name} is not valid JSON")
