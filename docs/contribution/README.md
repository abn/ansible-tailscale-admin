---
type: Guide
title: Contributing
description: How to set up a development environment, run the checks, and submit a change.
status: draft
tags:
  - contributing
  - workflow
---

# Contributing

## Setup

```sh
git clone https://github.com/abn/ansible-tailscale-admin
cd ansible-tailscale-admin
make init
```

`make init` installs the Go-based `okf` validator, syncs the locked Python
tooling environment, installs the pre-commit hook, and materialises the
`ansible_collections/abn/tailscale` symlink that `ansible-test` requires.

You will need `go` available; `GOTOOLCHAIN=auto` handles the version that `okf`
requires, which is newer than the host default.

## Checks

```sh
make check          # fast and hermetic: hooks, ansible-lint, okf, changelog, docs
make check/full     # adds ansible-test sanity, units and integration
make fmt            # apply formatting and safe fixes
```

`make check` runs on every commit through the pre-commit hook. It never starts a
container, which is why `check/full` exists as a separate target.

`tests/integration/targets/loopback` drives `tailscale_policy`, `tailscale_dns`
and `tailscale_settings` through a real `ansible-playbook` against a loopback stub
of the API. It needs no credential, no
tailnet and no network, so it runs in every CI matrix cell. Reach for it when the
question is whether the module behaves the same way once a real `AnsibleModule`, a
real transport and a real callback are involved. That is how `diff_mode: support:
full` was found to render nothing: the unit tests passed, because they asserted
only that the keys existed.

The Ansible matrix, across ansible-core versions and Python versions, runs in CI
via `ansible-test-gh-action`. It is deliberately not reproduced locally: a
hand-rolled local matrix is a bespoke script pretending to be a test suite. The
module Python floor is declared once, in `tests/config.yml`; the sanity and units
jobs test that floor rather than the oldest target each ansible-core lists, and
the integration matrix covers it and one version above.

## Live verification

The live suites reach a real tailnet and never the host's own Tailscale
configuration. Two things are required, and the target refuses without both:

- An admin API key in a file only you can read, `./.tskey` by default. Put one
  there, or point `TS_KEY_FILE` at one elsewhere. `.tskey` is git-ignored.
- The acknowledgement, because a credential merely being present must not be
  enough:

```sh
TS_LIVE_SMOKE=I_HAVE_A_THROWAWAY_TAILNET make live-smoke
```

The tailnet is expected to be a development tailnet you are willing to discard:
the suites create and remove devices, keys, Services and the policy. `make
live-smoke` prefers the test OAuth client in `./.tskey-oauth` when it exists,
which `make oauth/client` provisions; `make live-stress` needs the admin key.
Neither reads anything from the machine's own `tailscale` CLI.

## Making a change

1. State the scope in one sentence: unit of work, target, acceptance condition.
2. Work on a conventional branch in its own worktree, rebased on `main`.
3. Add a changelog fragment. The directory does not exist in a fresh checkout;
   create `changelogs/fragments/` and add `<issue-or-pr-number>-<slug>.yml`.
   Nothing else may live in that directory: the `changelog` sanity test parses
   every file in it as YAML, so a README there fails the build.

   ```yaml
   ---
   minor_changes:
     - tailscale_dns - add O(split_dns) for per-domain resolvers
       (https://github.com/abn/ansible-tailscale-admin/pull/42).
   ```

   Valid sections are `release_summary`, `major_changes`, `minor_changes`,
   `breaking_changes`, `deprecated_features`, `removed_features`,
   `security_fixes`, `bugfixes` and `known_issues`. The first line of an entry is
   `<module_name> - <description>`, and it carries the issue and pull request
   URLs. `major_changes`, `breaking_changes`, `removed_features`,
   `minor_changes` and `deprecated_features` do not belong in a patch release.

   **Do not write a fragment for a new module.** `antsibull` derives those from
   `version_added`, and the `changelog` sanity test fails if you add one.

4. Update `docs/` if behaviour changed. A page that describes what the modules
   do is reference material, and `docs/log.md` records the change to the bundle
   itself, so a new or rewritten page gets a dated entry there.
5. Run `make check/full`.
6. Get the change reviewed, then push.

Stage explicit paths. Never `git add -A`.

## Adding a module

The collection's own conventions are in `.agents/rules/ansible.md`. The short
version:

- Flat file under `plugins/modules/`, `AnsibleModule`, no third-party imports.
- Keep HTTP, retries, error mapping and canonicalisation in
  `plugins/module_utils/_tailscale/`. A module contains none of it. That split is
  what makes the hard parts unit-testable without Ansible.
- Add API operations to the operation table rather than building a path at the
  call site. The table is asserted against Tailscale's published description, so
  a path cannot drift from the API without a failing test.
- `attributes:` for check mode and diff mode, never `notes:`.
- Proof of idempotency is a test that applies twice and asserts `changed == 0` on
  the second run.

## Where documentation goes

Two surfaces, and they do not overlap. A module's `DOCUMENTATION` block is the
authority for its options, defaults and return values, and `docs/` is for the
design decisions and the operational knowledge around them: what a run costs, what
the safety model covers, which failure means what. An option table in `docs/` will
drift from the argument spec silently, whereas a change to an option that misses
the module documentation is a build failure.

## Reporting a bug

Open an issue with the collection version, the `ansible-core` version, the
playbook task, and the module's failure message including the
`x-tailscale-request-id` if one is present.
