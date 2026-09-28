---
type: ADR
title: Tailnet DNS is one module over the atomic configuration endpoint
description: Why DNS is reconciled as a single document rather than through the four
  per-feature endpoints, and the conflict that creates with any alternative.
status: stable
tags:
  - tailscale
  - api
  - dns
---

# Tailnet DNS is one module over the atomic configuration endpoint

## Context

The Tailscale API exposes DNS two ways.

The legacy per-feature endpoints, each read-modify-write on its own:
`/dns/nameservers`, `/dns/preferences`, `/dns/searchpaths` and
`/dns/split-dns`.

And `/dns/configuration`, which takes and returns one document covering
nameservers, split DNS, search paths and preferences together.

The legacy set is not merely more verbose. It is **lossy**: it cannot express
`useWithExitNode` on a resolver, which the configuration endpoint can and which
matters for exit-node users. It is also non-atomic, so a partial failure leaves
split DNS set and search paths not.

## Options considered

- **One module per feature**, matching the legacy endpoints one for one.
  Rejected: four round trips per run, no atomicity, and no way to express
  per-resolver exit-node behaviour.
- **One module over `/dns/configuration`.** Chosen.
- **One module over `/dns/configuration` plus thin per-feature modules.**
  Rejected. The two cannot be combined, so offering both invites a playbook that
  fights itself.

## Decision

A single `tailscale_dns` module reconciling one `DnsConfiguration` document:
`nameservers` as `{address, use_with_exit_node}` objects, `split_dns`,
`search_paths`, and the `magic_dns` and `override_local_dns` preferences.

## Consequences

- **The choice is not compatible with the other shape.** The Terraform provider
  exposes both `dns_configuration` and the individual `dns_*` resources, and
  Pulumi's bridge over it documents the conflict explicitly. Users arriving from
  one of those will have a resource that either does not exist here or behaves
  differently, and the documentation must say so rather than leave it to be
  discovered.
- Comparison is over one document, which is what makes the second run report no
  change. Reconciling four resources separately would report drift against
  server-side defaults on any of them.
- An option the task does not give is taken from the current configuration, not
  from a default, because the endpoint replaces the document. Sending a default
  would reset a field the operator never mentioned.
- A `split_dns` value is a list of resolvers, and an empty list is how a domain is
  cleared. The API also accepts a null value for that key, but the module sends an
  empty list, so a playbook that wants a domain cleared should write one.
- Changing nameservers has a side effect the user should be told about: removing
  all of them turns MagicDNS off, so the two settings are not independent.
