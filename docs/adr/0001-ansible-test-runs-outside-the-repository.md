---
type: ADR
title: Run ansible-test from a copy outside the repository
description: Why the collection is staged into the system temp directory rather than symlinked or
  copied inside the tree, including the silent-pass failure mode that motivates it.
status: stable
tags:
  - ansible
  - tooling
  - build
---

# Run ansible-test from a copy outside the repository

## Context

`ansible-test` refuses to run unless the collection sits at
`ansible_collections/<namespace>/<name>/`. This repository's root **is** the
collection root, so the two requirements are in direct conflict: the tree that
`ansible-galaxy build` packages is the one that is in the wrong place for
`ansible-test`.

Three placements are conceivable. All three were tried.

## Decision

`make collection/link` stages a copy at
`$TMPDIR/ansible-tailscale/<worktree>/ansible_collections/abn/tailscale`, and the
`sanity`, `test` and `integration` targets run from there. The farm path is keyed
on the worktree directory name.

## Why

**Inside the repository, `ansible-test` silently checks nothing.** It enumerates
content through git, so a tree nested anywhere inside a checkout, git-ignored or
not, reports `All targets skipped` and **exits 0**. There is no red to notice. A
green sanity run that linted zero files is worse than a red one, because it is
believed.

**Symlinks do not work either.** `ansible-test` does not traverse symlinked
content directories. A symlink to the repository root resolves to the root, which
is not under `ansible_collections/`, and the run aborts.

**A copy is the only thing that works**, and it is disposable by construction, so
the cost of regenerating it per invocation is the right trade against the risk of
a silent pass.

**Keying on the worktree name is not optional.** Several checkouts of this
repository can exist at once, and a shared destination would have them linting
each other's half-finished code, which produces failures that belong to nobody
and successes that mean nothing.

## Consequences

- `ansible-test` invocations are not run from the repository root. Every target
  that needs it depends on `collection/link`.
- The farm is a copy, so it can hold stale files. `collection/link` clears the
  destination before copying, and copies an explicit list of paths rather than
  the whole tree.
- Nothing about this is discoverable from the recipe, so the comment above
  `collection/link` has to stay with it.

## Verification

Two worktrees, a deliberate `E225` violation in one: that worktree's sanity run
exits 1 naming the file, the other exits 0 with no errors. Repeat with the farm
inside the repository and the failing run reports `All targets skipped` with
exit 0.
