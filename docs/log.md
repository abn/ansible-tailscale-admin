---
type: Log
title: Knowledge base log
description: Evolution of this documentation bundle, kept separate from software release notes.
status: draft
tags:
  - changelog
---

# Knowledge base log

This file records how the **documentation bundle** changes: pages added, pages
deprecated, structural refactors. It is deliberately not a changelog. Software
release notes live in `CHANGELOG.md`, generated from `changelogs/fragments/`.

## 2026-09-28

- Added a live-verification section to the contributing guide, saying that a live
  run takes an explicitly set key (`.tskey`, or `TS_KEY_FILE`) and a development
  tailnet, and that nothing is read from the host's own `tailscale` CLI. The guide
  is the page a contributor meets before running anything.
- Moved the contributor scripts from `scripts/` to `.contrib/scripts/`, and took
  the drift check and the three tailnet-provisioning flows out of the `Makefile`
  into `spec-drift.sh` and `provision.sh` there, so the `Makefile` holds Make and
  the flows hold shell. The paths in `capabilities`, ADR 0005 and the contributing
  guide follow the move.
- Swept the bundle for staleness after the fact-module and DNS work. The `README`
  module list and table now name the two fact modules and the two lookups, a
  duplicated paragraph is gone, and its policy row says the document comes from a
  file or from text. The Tailscale SSH caveat moved out of the README's first
  section, where it framed the collection as SSH-related, into the policy section
  of `usage`, where the `ssh` section it concerns is discussed. `examples` and the
  contributing guide no longer describe the DNS resolver flag as defaulted, and the
  contributing guide no longer says the loopback target drives "all three modules".
- Added a `usage` section for the two lookups, including the variable names they
  read a credential from, because `module_defaults` and the action group do not
  reach a lookup and that is the one place a reader meets that difference.
- Added [ADR 0008](adr/0008-read-only-fact-modules.md) and carried the two fact
  modules into the pages that enumerate what the collection manages: the module
  table and the ADR list in `overview`, the cost and return tables and a section
  each in `usage`, and the scope table in `authentication`. The ADR narrows ADR
  0002's read-only rule rather than replacing it, so that page keeps its record of
  why a single resource is still read in check mode.
- Recorded the module Python floor in the contributing guide, next to the CI
  matrix it constrains, so the declaration in `tests/config.yml` is discoverable
  from the page that tells a contributor what the gates run.

## 2026-09-27

- Carried `tailscale_service` into the pages that enumerate what the collection
  manages: the module table and the module count in `README.md`, the request
  cost and return value tables and a section of its own in `usage`, the scope
  table in `authentication`, the guarantees and the unprotected failure modes in
  `safety-model`, and four new entries in `troubleshooting` for the refusals the
  Service endpoints produce. The measurements behind them are in the usage
  section rather than here, because a log records the bundle's evolution and not
  the code's behaviour.
- Added `tailscale_auth_key` to `overview`, `authentication` and `usage`, and the
  credential failures it produces to `troubleshooting`: a tailnet-owned auth key
  with no tags, an auth key the API will not update, a description with a character
  the API refuses, an OAuth client with no scopes, and a run that correctly reports
  no secret. The scope table gained a row per credential kind, because the keys
  endpoint authorises each kind separately rather than the module.
- Established the bundle: `overview`, `contribution`, and the docsite
  configuration.
- Added five ADRs: `0001` for staging the collection outside the repository before
  running `ansible-test`, `0002` for the policy module's shape, `0003` for the
  `module_utils` licensing split, `0004` for reconciling DNS as one document, and
  `0005` for deriving the artifact check from git's ignore list.
- Added `usage`, `authentication`, `safety-model` and `troubleshooting`, so the
  bundle carries the material the collection owes its users: a first run, a scope
  to module table, what the modules guarantee, and the failures the API actually
  produces.
- Rewrote `overview` against the code. It described a set of planned modules,
  three of which do not exist, and a state of the project in which no module had
  been written.
- Marked ADR `0002` deprecated. The `enforced`/`present` interface it chose was
  never built: `tailscale_policy` has no `state` parameter and always reconciles.
  The ADR keeps the measurement that motivated the decision, and now records what
  was built instead.
- Corrected ADR `0004`'s account of a null `split_dns` value, and removed a
  reference to a parallel review process from ADR `0001`.
- Brought `README.md` up to date. It claimed no module existed, described a
  scope-to-module table that was never written, and described safety rules and
  options belonging to modules that do not exist.
- Reduced this log to the bundle's own evolution. It had accumulated the history
  of the code and of the work around it, which is what the commit history and the
  release notes are for.
- Corrected two claims in the new pages before they settled. The policy validator
  answers a failed validation with a success status, so an invalid policy is
  refused by the write rather than by the validation request before it. And
  validating a proposal needs `policy_file:read` while writing it needs
  `policy_file`, which the first draft of the scope table merged into one row.
- Extended the scope and module tables in `authentication` and `usage` to cover
  the logging modules, and gave them their own sections. The two have opposite
  shapes, one declares a destination and the other reads a window, and a reader
  needs that difference stated rather than inferred from the option names.
- Added the plan refusal that arrives as a 403 to `troubleshooting`, keyed to the
  server's own wording. The log streaming endpoints and the network flow log read
  answer that way on a plan without them, and the status alone would send an
  operator to widen a credential that already holds every scope.
- Added the two device modules to `usage`, `authentication`, `overview` and
  `troubleshooting`, and to the module table in `README.md`. The new material is
  what a device task needs and cannot be inferred from the API's schema: a name is
  rewritten rather than stored, tags and routes are returned in the server's order,
  the last tag cannot be taken off a device, and a device is selected by the label
  it holds now, which is the label a rename moves.
- Added `tailscale_user`, and with it a third module shape. A user is discovered
  rather than declared: it appears when somebody authenticates or is invited, so
  the module selects one from the user list and reconciles the properties the API
  lets it change. Updated `overview`, `usage`, `authentication` and
  `troubleshooting` for it, and corrected the claim that the collection exposes no
  module for users.
- Recorded three failures of the users API that a mock cannot produce, all
  measured against a real tailnet. A role change for the user the calling
  credential belongs to is answered 200 and changes nothing, the same request for
  the role already held is answered 500, and an invite is refused to an OAuth
  client and never appears in the user list. The first is why `tailscale_user`
  reads the user back after writing it and refuses to report a change it cannot
  see.
- Added `examples`, a page walking through a runnable play in `examples/`. It is the
  first statement of intended use rather than of one module, and it exists because
  the per-module reference said what each module does without ever saying what a
  playbook that uses them looks like. The play is run twice and the second run is
  quiet, so the page's central claim is one that can be checked.
- Extended the module tables in `overview` and `README.md` to all ten modules. The
  logging rows were missing from both, and the enumerated lists had been rewritten
  independently by six parallel changes, so they were consolidated into one list
  each rather than merged.
- Corrected the safety model's account of a concurrent console edit. It said the
  collection guards only the policy file and offered no option for the rest, which
  remains true, but the sentence counted modules rather than naming the resources
  the claim covers.
- Added the resolver asymmetry to `troubleshooting`. A nameserver written without
  `use_with_exit_node` is stored without the key, which is the same rule the
  preferences and split DNS already followed and which `resolver` did not, so a
  task using the option's own default reported a change on every run.
- Added ADR `0007`, which records why a precondition failure re-reads and re-applies
  rather than ending the task. It narrows invariant 2 and says what it keeps: the
  guard stays, and nothing another writer did is discarded.
- Extended the module, scope and troubleshooting tables to the three wave-seven
  modules: contacts, device attributes and the AWS external id. The device
  attributes write path is plan-gated the same way log streaming is, so the plan
  refusal section now names it alongside the streaming family.
- Gave the three wave-seven modules their own sections in `usage`, and added them
  to the cost and return tables, which had listed ten of thirteen.
- Corrected the "what the collection does not do" list in `overview`. It claimed
  the operation table covered webhooks, and it does not; it now names webhooks,
  posture integrations, the legacy DNS endpoints, `oauth-apps`, organizations and
  deleting a tailnet, each with the reason it is out.
- Rewrote the first-run section of `usage` as three steps, because it assumed a
  play and a credential already existed and named `site.yml` rather than the
  example's real path.
- Corrected the pages that still described a policy write refused with a 412 as
  final. `examples`, `troubleshooting` and `safety-model` now say the run reads
  again and retries, which is what ADR 0007 decided and what the code does.
- Corrected the `tailscale_logs` endpoint in `README` and `overview`, which showed
  a `{logType}` template for two paths the description writes out separately.
- `usage` now says which one thing about `tailscale_log_streaming` is unmeasured:
  the server's habit of storing an unstorable value as an absent key, which every
  other module here has had to account for and which cannot be measured for a log
  destination on a plan without streaming.
- Added `capabilities`, a generated page listing every endpoint in the API
  description, whether a module calls it, and the reason for each one that none
  does. It is derived from the operation table and a new coverage classification,
  and `make check` regenerates it and fails on a difference, because a hand-kept
  list of what is covered goes stale the first time a module is added and nothing
  catches it. That is how this bundle came to claim the operation table covered
  webhooks when it did not.
- Added two coverage categories the first pass had no name for, and used them on
  three rows that were in the operation table and named by nothing: a policy
  preview that is a second way to check a policy, a Service list the module does
  not need because it selects by name, and a resend whose result nothing can
  observe. A test now fails if an operation is in the table and nothing names it.
- Added `tailscale_webhook`, the fourteenth module, to the module tables in
  `README.md` and `overview`, to the cost and return tables and a section of its
  own in `usage`, and to the scope table in `authentication`. The `overview`
  exclusion list no longer names webhooks and now says why the test and rotate
  actions are not exposed; `README` loses a "does not do" entry that named
  devices, keys, users and webhooks, all four of which now have modules. The
  generated capabilities page follows the operation table and the classification.
