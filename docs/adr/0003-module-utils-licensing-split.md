---
type: ADR
title: module_utils is BSD-2-Clause while the rest of the collection is GPL-3.0-or-later
description: The per-file licensing split, why it follows ansible-core, and the two
  implementation details it forces.
status: stable
tags:
  - licensing
  - ansible
  - reuse
---

# `module_utils` is BSD-2-Clause while the rest is GPL-3.0-or-later

## Context

Collections intended for the `ansible` package must be GPL-3.0-or-later
compatible on both the GNU and DFSG lists, covering `plugins/modules/`,
`plugins/module_utils/`, controller-side plugin code, non-code content, and
anything outside `plugins/` that imports the above.

That is workable for modules, which are executed rather than imported. It is a
problem for `module_utils`, which other projects import and link against.

ansible-core resolves this by relicensing its own `module_utils` as BSD-2-Clause,
specifically so that third-party modules under GPL-incompatible licences can
reuse them. `community.general` does the same for its private module utils.

## Decision

| Path | License |
|---|---|
| `plugins/modules/**`, and everything else | `GPL-3.0-or-later` |
| `plugins/module_utils/**` | `BSD-2-Clause` |
| `tests/fixtures/openapi/**` | `BSD-3-Clause`, Tailscale's own |

Per-file licensing follows REUSE: each file declares its licence through an
`SPDX-License-Identifier` comment, and every declaration resolves to a text under
`LICENSES/`. `galaxy.yml` lists all three SPDX identifiers, and `LICENSE` states
the split and its reason.

## Consequences

- `plugins/module_utils/**` must not import from the GPL-licensed part of the
  collection, or the split is meaningless. The kernel is self-contained by
  construction, which is also why it is a single package.
- **Zero-byte `__init__.py` files cannot carry an SPDX header.** The `empty-init`
  sanity test requires them to be completely empty. The per-file scheme and that
  test are in direct conflict, and the test wins, so the licensing of those files
  is stated in `LICENSE` rather than in the files. This is the one place the REUSE
  scheme is knowingly incomplete.
- A future module util promoted from private to public becomes a breaking change
  and needs a rename without the underscore prefix.
- No CLA other than the DCO is permitted, and no binary may be committed.
