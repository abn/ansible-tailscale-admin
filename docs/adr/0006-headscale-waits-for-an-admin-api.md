---
type: ADR
title: Headscale support waits for a Headscale Admin API
description: Why this collection targets the Tailscale Admin API alone, and what would have to
  change before a self-hosted control plane is in scope.
status: stable
tags:
  - scope
  - api
---

# Headscale support waits for a Headscale Admin API

## Context

Headscale is the common self-hosted alternative to Tailscale's own control plane,
and a collection named for Tailscale that could not manage one would have an obvious
gap in it. The question is whether to plan for it now.

Headscale does not implement the Tailscale Admin API. What it exposes is a gRPC
service with its own schema, its own authentication model, and a resource set that
differs from Tailscale's in kind and not only in detail. There is no v2 surface to
build against.

The two are not reachable by configuration. `base_url` is the one genuinely
portable piece of this collection, and it points at a different protocol behind it.

## Decision

`abn.tailscale` targets the Tailscale Admin API only. No Headscale support is
planned, no abstraction is built in anticipation of one, and no issue is held open
for it.

The reason is that the work would not be a small adapter. The operation table in
`plugins/module_utils/_tailscale/_spec.py` is written against the vendored Tailscale
description and cross-checked against it by a test, which is what keeps paths,
verbs and scope names honest. A second backend means a second operation table, a
second spec to vendor and drift-check, and a credential model for gRPC that shares
nothing with the OAuth exchange here. Every safety property in
`docs/safety-model.md` is stated against a Tailscale behaviour, including the
`ETag` guard, which exists because Tailscale's policy endpoint is the only
concurrency-controlled resource in the set.

Building that seam for a backend that does not exist yet would be speculative in
the expensive direction: it would put an untested abstraction between the modules
and the one API that works, and the abstraction would be shaped by an assumption
about Headscale rather than by evidence.

## Consequences

A user running Headscale has no module here, and the honest answer to them is that
this collection does not manage a self-hosted control plane.

This is revisited if and when Headscale publishes an Admin API v2 with a stable
schema. At that point the question worth asking is not whether to add it but
whether one collection should carry both, since a shared abstraction over two
control planes with different resource models is thinner than two collections that
share a vendoring and a safety-model discipline.

The operation table is the place any such work would start, and the spec-drift
test is the pattern that would carry over: a hand-written table cross-checked
against a vendored description, so an upstream addition becomes a failure to
reconcile rather than a comment that quietly goes stale.
