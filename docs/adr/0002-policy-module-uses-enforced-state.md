---
type: ADR
title: 'The policy module reconciles with state=enforced, not present'
description: Why a whole-document replace is named enforced rather than present, why the
  conventional present/absent vocabulary is a deliberate departure, and that the interface was
  not built.
status: deprecated
tags:
  - ansible
  - tailscale
  - api
---

# The policy module reconciles with `state=enforced`

**Deprecated.** The interface this ADR chose was not built. `tailscale_policy`
has no `state` parameter and always reconciles. What follows is kept because the
measurement behind it still holds, and because it explains why the module looks
unlike its neighbours in an Ansible collection.

## Context

`POST /api/v2/tailnet/{tailnet}/acl` **fully replaces** the policy file. There is
no partial update, no JSON Patch, and no way to address a single rule. A write
that omits a top-level section deletes it.

Ansible's convention is therefore awkward here. `present`/`absent` is what
essentially every collection uses, measured across `community.general`,
`community.aws`, `community.dns` and `ansible.netcommon`: 128 modules use exactly
`[absent, present]`, and the words `enforced` and `reconciled` appear in **zero**
`state` choices anywhere in those trees. There is no precedent to follow.

## Options considered

- **`present`/`absent`.** Rejected. A user who writes `present` reasonably
  believes unmentioned sections are untouched. Here they are deleted. The name
  would misdescribe the operation at exactly the moment it matters.
- **`enforced`/`present`.** Chosen. `enforced` says the supplied document is the
  whole truth. `present` remains available for a read-modify-write merge of
  top-level sections, still `If-Match` guarded, and never the default.
- **No `state` parameter**, reconcile always. Rejected: a reader should not have
  to know which of two behaviours a module has before running it.
- **A separate merge module.** Rejected as surface for its own sake. The
  distinction is one boolean, not a separate resource.

## Decision

`tailscale_policy` takes `state` with `enforced` as the default and `present` as
the opt-in merge mode.

## What was built instead

The third option, rejected here, is what shipped. `tailscale_policy` reconciles
unconditionally: it takes no `state`, and the merge mode was not implemented. The
replace-only behaviour the module has is therefore the only behaviour, stated in
the module `description` rather than in an option name, and the `ETag` guard
applies to the one write it can make.

The option names this ADR weighed are gone with it. So is the reasoning for
excluding `get`, `list`, `query` and `info`: a read-only policy task is a
`tailscale_policy` run in check mode, which makes one request and writes nothing.

## Consequences

- The collection departs from Ansible convention, and the departure is visible in
  the argument list rather than in a note. A user reaching for `present` gets an
  unsupported-parameter error instead of a merge, which is the safe direction.
- There is no merge mode, so there is no read-modify-write path and no second
  concurrency surface to guard.
