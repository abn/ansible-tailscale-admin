---
type: Guide
title: A runnable example
description: One play that declares a tailnet, the state it declares, what a second run
  does, and what happens when the tailnet is edited by hand in between.
status: draft
tags:
  - example
  - usage
  - idempotency
---

# A runnable example

`examples/site.yml` is one play that declares a tailnet and leaves it. It is the
shape this collection is meant to be used in: a resource declared once, applied,
and quiet on every run after the first. The play is also the contract the rest of
the documentation is measured against, so it runs as written rather than being a
sketch.

## Running it

The credential comes from the environment, so no secret is stored in the
repository:

```sh
export ANSIBLE_COLLECTIONS_PATH=/path/to/collections  # holds ansible_collections/abn/tailscale
export TS_OAUTH_CLIENT_ID=...
export TS_OAUTH_CLIENT_SECRET=...

ansible-playbook examples/site.yml --check
ansible-playbook examples/site.yml
```

The credential is an OAuth client, which the modules exchange for a short-lived
access token on the first request of each task. It is read with `lookup('env',
...)` in the play's `module_defaults`, because the modules themselves never read
the environment. [Authentication](authentication.md) explains the two
credentials, the scopes each task needs, and why a client is the better one for
automation.

The play runs on `localhost` with `gather_facts: false`. These modules reach the
Tailscale Admin API themselves, so nothing about the target host matters.

`--check` first is worth the habit here: the policy task prints which nodes it
would change, so a wrong path or a truncated policy file shows up as a change
you did not intend rather than as a silent no-op.

## What it declares

The play owns four resources and, when told to, touches a fifth and a sixth that
something else created.

| Task | Module | Declared state |
|---|---|---|
| Apply the access control policy | `tailscale_policy` | The whole policy in `examples/policies/tailnet.hujson` |
| Turn on MagicDNS behind a public resolver | `tailscale_dns` | `magic_dns: true` and one resolver, `1.1.1.1` |
| Keep authorisation keys valid for ninety days | `tailscale_settings` | `devices_key_duration_days: 90` |
| Publish the web Service | `tailscale_service` | `svc:example-web` on `tcp:443`, carrying `tag:example` |
| Tag an existing device | `tailscale_device` | `tag:example` on the device named in `tailnet_device_name` |
| Reconcile an existing user | `tailscale_user` | The role in `tailnet_user_role` for `tailnet_user_login` |

The two trailing tasks are skipped unless their variable is set, because neither
resource can be made by a playbook. That is the honesty the example is trying to
carry: a device appears when something authenticates, and a user appears when
somebody joins or is invited. The play selects an existing object or steps past
the task.

The policy file replaces the whole access control document, because that is the
only shape the endpoint has. It grants `tag:example` to `autogroup:admin` and
allows every member to reach every destination. A Service tag exists only where
`tagOwners` grants it, which is why the policy is applied before the Service: the
Service would be refused otherwise, and the refusal names the tag rather than the
ordering.

Each option is on the task for a reason rather than by default. The resolver is
written with its address and no flag, so the run keeps whatever the tailnet holds
for that address rather than clearing it, and the task converges.

[Usage](usage.md) has the per-module detail behind each of these shapes, and
[overview](overview.md) explains why a replaced document carries forward what the
task did not name.

## What it needs to already exist

The credential has to reach every scope the modules use; the client this
collection is tested with is granted all of them, which is why the example does
not narrow it. The tailnet has to be one the operator may have its policy
replaced on, because the policy task owns the whole document.

Beyond that, the play needs nothing. It creates the Service and the access
control it declares, and it does not depend on a device or a user existing. Where
one is wanted, set `tailnet_device_name` or `tailnet_user_login` and the matching
task reconciles the object that already exists. A name that matches no device or
no user is a failure from the module, not a quiet skip, because reporting success
for an object that is not there would be a lie.

## What the second run does

Nothing. Every task reports `ok` and the recap reads `changed=0`:

```text
PLAY RECAP *********************************************************************
localhost                  : ok=4    changed=0    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0
```

That is the first invariant of the collection, and it is the property the
comparison logic exists for. A replaced document is compared in a canonical form,
so the same policy written in a different order or with comments does not report
a difference. A merging document, such as the settings endpoint, compares only
the options the task named, so a field nobody asked about cannot make a run
report a change. And on the DNS endpoint, whose task does not name
`search_paths`, the existing search paths are carried into the write rather than
reset, which is why the task is quiet over a field it never mentions.

## What a hand edit does

The interesting case is the tailnet changed between two runs, through the console
or an API call. The module re-reads the resource at the start of the run, so the
edit is just a difference to reconcile, and the next run puts the declared state
back.

Measured: after a clean run, `tag:drift` was added to the policy's `tagOwners` by
a direct API call. The next run of the play reported the policy task changed and
its diff showed the tag being removed, with every other task quiet:

```text
TASK [Apply the access control policy] *****************************************
--- before
+++ after
@@ -11,9 +11,6 @@
     "tagOwners": {
-        "tag:drift": [
-            "autogroup:admin"
-        ],
         "tag:example": [
```

The write is guarded by the fingerprint the run read, so a change that lands
*during* that read and write is not silently written over: the API answers `412`,
the module reads the document again, recomputes the diff against what it now holds
and writes again, up to three attempts. A document that keeps changing fails and
says it is contended. Each attempt applies the declared document, so a section the
file does not declare is removed, and the diff reports what was replaced. The guard
is exercised at the seam in `tests/live/test_policy_module_live.py`.

## What it leaves behind

The play creates the policy, enables MagicDNS, sets the key duration, and
publishes `svc:example-web`. Every one of those is still there after the run,
which is what "declares a state and leaves it" means. It removes nothing: no user
is deleted, no device is removed, and no key is revoked. Running it against a
tailnet that already holds these resources reconciles them instead of duplicating
them.

Two consequences are worth stating plainly. The policy is replaced whole, so a
document someone else wrote is gone after the run unless the file reproduces it.
And the play does not set device approval, which would change whether every new
device on the tailnet can join; that is left to the operator's own playbook.

## What running the example found

Writing the play as a user would rather than as a test would surfaced two
mismatches between the modules and an idempotent play. Both are fixed, and both
were invisible to the live suites because those were written around them.

- **The action group was incomplete.** The play declares the connection options
  once under `group/abn.tailscale.tailscale`, which `docs/authentication.md` and
  [usage](usage.md) present as covering every task. `meta/runtime.yml` omitted
  `tailscale_user` and `tailscale_auth_key` from that group, so a task using the
  group alone failed before making a request, with `No credential. Set api_token,
  or set oauth_client_id and oauth_client_secret together.` The group now names
  every module, and a test fails if one is added or removed without it.
- **A DNS resolver's exit-node flag did not survive an unrelated change.** The
  server drops `useWithExitNode` when it is `false` and stores it when it is
  `true`. The option defaulted to false, so a resolver the tailnet had flagged as
  reachable through an exit node was cleared by the next run that did not mention
  the field, and that run reported a change against the tailnet it had just
  altered. The flag now has no default: an entry that omits it keeps the tailnet's
  own value, and `use_with_exit_node: false` is the explicit way to clear it.
