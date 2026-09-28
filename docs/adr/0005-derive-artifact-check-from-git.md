---
type: ADR
title: Derive the artifact check from what git ignores
description: Why the Galaxy build assertion compares the artifact against git's own ignore list rather
  than a hand-maintained list of development paths.
status: stable
tags:
  - tooling
  - build
---

# Derive the artifact check from what git ignores

## Context

`ansible-galaxy build` reads `build_ignore` in `galaxy.yml` and nothing else. A
development path missing from that list ships silently, in a published artifact,
to every consumer of the collection.

The obvious defence is a second list in the `build` target naming the paths that
must not appear. That is what this repository had, and it did not work. The
listing was piped through `sed` to strip a leading collection directory that
`ansible-galaxy` does not in fact emit, so every path lost its first component:
`plugins/modules/x.py` became `modules/x.py`. No pattern could ever match, and
the assertion had never once fired.

It then fired for the first time and immediately found two leaks that had been
shipping all along, a nested copy of the collection and a pytest cache.

A list that must be updated by hand is a list that will be wrong, and a check that
is wrong in the permissive direction is worse than no check, because it is
mistaken for evidence.

## Decision

The assertion has two independent parts.

The first needs no list. `git ls-files --others --ignored --exclude-standard`
reports every path the repository ignores, and the check fails if the artifact
contains any of them or anything beneath one. A tool that writes into the tree
produces a git-ignored path, so it is caught the first time it runs, with nothing
to remember.

The second part covers what git cannot see: a tracked path that is declared in
`build_ignore`, which git would otherwise be right to track. That list is read
out of `galaxy.yml` rather than restated, so a new excluded path needs no change
here, and so the check cannot drift from the thing it is asserting.

This began as a small regex naming one tracked development-only file, the
`tailscale_scaffold` fixture that held the documentation fragments to validate.
That file is gone, because the three real modules include the same fragments and
`validate-modules` cross-checks them against real modules now. Keeping a
hand-written regex for a file that no longer existed would have left a gate
matching nothing, which is the failure this ADR was written about.

The size ceiling stays as a backstop for anything that slips both.

## Consequences

Adding a tool that writes into the tree requires no change here. A path that must
not ship requires a `build_ignore` entry and nothing else, and the failure message
names the entry that was supposed to cover it.

The comparison walks each artifact path's ancestors rather than its top-level
component. Matching only the first component produces false positives, because
`tests/output` is ignored while `tests` is a legitimate part of the artifact. It
also has to be an ancestor walk rather than a substring match over the entry, since
`dist` is an excluded path and a legitimate `plugins/lookup/dist_cache.py` contains
it as a substring. `.contrib/scripts/assert-excluded.py` does the walk.

Deriving the list from `build_ignore` also found that the entries are not all
honoured. An entry written with a trailing slash is accepted by
`ansible-galaxy build`, which then ships the directory anyway, so the assertion
catches a leak the build reported as a success. That is the whole reason the second
part asserts rather than trusting the manifest.
