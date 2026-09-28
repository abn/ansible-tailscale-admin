---
type: Overview
title: Overview
description: What this collection manages, how the modules differ in shape, and the design
  decisions behind them.
status: draft
tags:
  - tailscale
  - ansible
  - collection
---

# Overview

`abn.tailscale` manages a Tailscale **tailnet** declaratively, through the
Tailscale Admin API v2. A playbook declares the state it wants and the modules
bring the tailnet to it, writing only what differs.

There is no Ansible module for the Tailscale control plane. The collections named
after Tailscale are node-side: they install `tailscaled` on a host and run
`tailscale up`. None of them manage a tailnet, which is a different object with
different failure modes. This collection does.

## The modules

| Module | Reconciles | Endpoint | Shape |
|---|---|---|---|
| `tailscale_policy` | The whole access control policy, from a HuJSON file or HuJSON text | `GET`/`POST /tailnet/{tailnet}/acl` | Replaced whole, guarded by `ETag` |
| `tailscale_dns` | Nameservers, split DNS, search paths, and the MagicDNS and override preferences | `GET`/`POST /tailnet/{tailnet}/dns/configuration` | Replaced whole, merged from current |
| `tailscale_settings` | Individual settings, such as device approval and authorisation key duration | `GET`/`PATCH /tailnet/{tailnet}/settings` | Merged, only the options given |
| `tailscale_service` | A Service published into the tailnet, and whether a device may host it | `GET`/`PUT`/`DELETE /tailnet/{tailnet}/services/{serviceName}` | Replaced whole, merged from current |
| `tailscale_service_info` | Every Service the tailnet holds | `GET /tailnet/{tailnet}/services` | Read only, never writes |
| `tailscale_device` | One device's name, tags, approval, key expiry and address, or its removal | `GET /tailnet/{tailnet}/devices`, `POST`/`DELETE /device/{deviceId}/...` | One endpoint per property, selected from the device list |
| `tailscale_device_info` | Every device the tailnet holds, as the API returns them | `GET /tailnet/{tailnet}/devices` | Read only, never writes |
| `tailscale_device_routes` | The subnet routes an admin has enabled for one device | `GET`/`POST /device/{deviceId}/routes` | Replaced whole, on one device |
| `tailscale_auth_key` | Auth keys, OAuth clients and federated identities | `/tailnet/{tailnet}/keys` and `/tailnet/{tailnet}/keys/{keyId}` | Replaced whole on update, merged from current |
| `tailscale_user` | The role, suspension, approval and membership of a user | `GET /tailnet/{tailnet}/users`, `POST /users/{userId}/...` | Properties of a discovered resource |
| `tailscale_logs` | The audit log, or the network flow log, over a window the task gives | `GET /tailnet/{tailnet}/logging/configuration`, `.../logging/network` | Read only, never writes |
| `tailscale_log_streaming` | The destination logs are published to, and its publishing status | `GET`/`PUT`/`DELETE /tailnet/{tailnet}/logging/{logType}/stream` | Replaced whole, merged from current |
| `tailscale_contacts` | The address Tailscale writes to for each contact type | `GET /tailnet/{tailnet}/contacts`, `PATCH .../contacts/{contactType}` | One document, compared per type |
| `tailscale_device_attributes` | One device's custom posture attributes | `GET /device/{deviceId}/attributes`, `PATCH /tailnet/{tailnet}/device-attributes` | Merge patch, a set and a delete in one request |
| `tailscale_aws_external_id` | The reusable external id this tailnet presents to AWS | `POST /tailnet/{tailnet}/aws-external-id` | Read, changes nothing |
| `tailscale_webhook` | The events a tailnet posts to an endpoint URL, and the destination format | `GET`/`POST /tailnet/{tailnet}/webhooks`, `GET`/`PATCH`/`DELETE /webhooks/{endpointId}` | Found by URL, one field updatable, the rest fixed at creation |

The shape column is the API's, not a choice, and it decides what a module has to
do with an option it was not given.

- A replaced document has no partial update, so an option the task left out has to
  be sent back as the value the tailnet already holds. Sending a default instead
  would reset a field nobody mentioned, which on a replace endpoint is
  indistinguishable from asking for it.
- A merged document treats an absent field as a field to leave alone, so the
  module drops the option from the request entirely.
- A device has no document to replace. Each property has an endpoint of its own,
  so an option left out is never sent and a property is written only when the one
  the task named differs from the one the device holds.
- A user is not a document and is not created by a playbook. One appears when
  somebody authenticates or is invited, so the module reads the user list, selects
  one user from it, and refuses a selector that matches nobody or more than one.
  A user awaiting approval cannot be put back into that state, because the API can
  approve a user but cannot withdraw an approval, so a task asking for that is
  refused rather than reported as a change that cannot happen.
- A webhook endpoint has no id a task can name before it exists, so its URL is the
  key: the module lists the tailnet's endpoints, matches by URL, and creates only
  when none matches. Only the subscription list can change afterwards, because the
  API has no update for the URL or the provider type; a task declaring a different
  provider is refused rather than quietly ignored.

Either way, comparison covers only the options the task set, so a second run over
unchanged input reports `changed: 0` rather than a difference nobody asked about.
A replaced document also has fields the server will not store, such as an empty
string or an empty list, which come back as an absent key, and sending one is a
difference that never goes away.

All of them reach the API over HTTPS themselves from the host that runs the task,
and the one that reads a file reads it there, so `hosts: localhost` with the local
connection is enough. They use none of the target's connection settings, and a
delegated task works because what they manage is not on the target.

## The decisions behind that shape

Each of these has an ADR with the reasoning, the options rejected, and the
consequences accepted.

- [ADR 0001](adr/0001-ansible-test-runs-outside-the-repository.md): the
  collection is staged into a copy outside the repository for `ansible-test`,
  because a tree nested anywhere inside a checkout reports a silent pass.
- [ADR 0002](adr/0002-policy-module-uses-enforced-state.md): why the policy
  module has no `state` parameter, and why the `enforced`/`present` interface
  proposed here was not built.
- [ADR 0003](adr/0003-module-utils-licensing-split.md): `module_utils` is
  BSD-2-Clause while the rest of the collection is GPL-3.0-or-later, following
  ansible-core.
- [ADR 0004](adr/0004-atomic-dns-configuration.md): DNS is one module over the
  atomic configuration endpoint, not four modules over the legacy ones.
- [ADR 0005](adr/0005-derive-artifact-check-from-git.md): the Galaxy artifact
  check is derived from git's own ignore list and from `build_ignore`, because
  neither `ansible-galaxy build` nor a hand-maintained list reports a leak.
- [ADR 0006](adr/0006-headscale-waits-for-an-admin-api.md): Headscale is out of
  scope until it publishes an Admin API, and no seam is built in anticipation of
  one.
- [ADR 0007](adr/0007-a-concurrent-policy-edit-converges.md): a policy write the
  API refuses with a 412 re-reads and re-applies rather than ending the task, which
  narrows the fail-closed reading of concurrency without discarding another
  writer's edit.
- [ADR 0008](adr/0008-read-only-fact-modules.md): why reading a whole inventory
  gets modules of its own, and how that narrows ADR 0002's rule that a read-only
  task is a check-mode run.

## What the collection does not do

- Node-side operations. Installing `tailscaled`, running `tailscale up`,
  configuring Serve or Funnel: those belong on the host.
- Invites. Tailscale permits them only to user-owned keys, because an invite needs
  an inviting user, and an invited user does not appear in the user list until it
  accepts. `tailscale_user` manages users that exist; it does not create them. The
  eight user-invite and device-invite endpoints mostly carry no OAuth scope
  upstream at all, so a scoped credential could not be granted them.
- Webhook test and rotate. `tailscale_webhook` reconciles the endpoints
  themselves; sending a test event and rotating the signing secret are actions
  with no observable end state, so no task could reach `changed: 0` on a second
  run and neither is exposed.
- Posture integrations. Reachable, and not implemented for a different reason: the
  server validates a provider's credentials against the vendor, so an integration
  cannot be created without a real CrowdStrike, Intune, Jamf, Kandji, Kolide or
  SentinelOne account, and the write path could not be verified against the API.
- The legacy DNS endpoints. `dns/nameservers`, `dns/preferences`, `dns/searchpaths`
  and `dns/split-dns` are replaced by the atomic `dns/configuration` endpoint,
  which is the only one that can express a resolver's `useWithExitNode`.
  [ADR 0004](adr/0004-atomic-dns-configuration.md) has the reasoning.
- OAuth applications under `oauth-apps`. OAuth clients are managed through the
  keys API that `tailscale_auth_key` already covers.
- Organizations, and deleting a tailnet. Both act above or outside a single
  tailnet, which is the unit this collection manages.
- Headscale or any other self-hosted control plane. It does not implement the
  Tailscale Admin API, and [ADR 0006](adr/0006-headscale-waits-for-an-admin-api.md)
  says why no seam is built for one.
- Anything requiring third-party Python. A module runs where a dependency cannot
  be installed, so the collection carries none.

## Where to read next

- [Usage](usage.md): what one run of each module does, and what it returns.
- [Authentication](authentication.md): credentials, token lifetime, and the
  scopes each module needs.
- [Safety model](safety-model.md): what the modules guarantee, and what they
  cannot.
- [Troubleshooting](troubleshooting.md): the failures the API actually produces,
  and what each one means.
- The module reference, which is the authority for options:
  `ansible-doc abn.tailscale.tailscale_policy` and its siblings.

## Where the facts come from

The operation table, the request paths and the scopes for every call are
hand-written Python in the collection, asserted against a vendored copy of
Tailscale's published OpenAPI description at
`tests/fixtures/openapi/tailscale.yaml`. `make spec/drift` re-reads the upstream
description, so an API change surfaces as a failing check rather than as a 404 in
production.
