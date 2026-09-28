---
type: ADR
title: 'Read-only fact modules are part of managing a tailnet'
description: Why the collection returns the devices and Services a tailnet holds, and how that
  narrows ADR 0002's rule that a read-only task is a reconciling module in check mode.
status: stable
tags:
  - ansible
  - tailscale
  - api
---

# Read-only fact modules are part of managing a tailnet

## Context

The collection reconciles a tailnet: a task declares the state it wants and the
module writes only what differs. ADR 0002 recorded the consequence for reading: a
read-only task is a reconciling module run in check mode, which makes one request
and writes nothing, so no `get`, `list`, `query` or `info` module was added.

That rule reaches one resource. A check-mode run of `tailscale_device` reads the
one device its task named, and a check-mode run of `tailscale_service` reads the
one Service. Neither answers "what does this tailnet hold", because naming no
device is not a task either module accepts. The list endpoints the collection
already calls in order to find the one resource are, by construction, not
reachable from a task.

A consumer drove a DNS control plane from the tailnet's own inventory: every
device's MagicDNS name and IPv4, and every Service's addresses. The only way to
build that was a script outside Ansible calling the Admin API directly, with its
own credential handling and its own error paths.

## Decision

Reading a whole inventory is management, and it gets modules.
`tailscale_device_info` returns the devices the tailnet holds and
`tailscale_service_info` returns its Services. Both return the API's own
documents unaltered, always report `changed=False`, and expose no `state`.

ADR 0002's rule is narrowed rather than discarded. A single resource is still read
by running its module in check mode, and no module grew a second way to read one
resource. The facts modules exist for the question check mode cannot answer:
enumerating a resource family, which is different from "is this one resource as I
declared it".

`GET /tailnet/{tailnet}/services`, previously excluded as a second way to reach a
Service, is now called by `tailscale_service_info`. `GET /users/{userId}` is
reclassified as that second way in its place, since `tailscale_user` already reads
the list and selects from it.

## Consequences

- The two facts modules join the action group, so a playbook that sets the
  connection options once sets them for the reads as well.
- They return the API's documents rather than a projected shape, because Tailscale
  adds fields and a fixed shape would drop information a task needs. A field the
  API renames reaches a task unchanged, which is the point.
- An inventory is read whole. A large tailnet returns every device, so filtering
  is a task's business in Jinja rather than a server-side query.
- The scopes a facts module needs are read scopes, and neither module can widen
  access, because neither writes anything.
