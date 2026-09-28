---
type: ADR
title: A concurrent policy edit converges instead of failing the run
description: Why a precondition failure re-reads and re-applies rather than ending
  the task, and what that keeps of the guard it replaces.
status: stable
tags:
  - tailscale
  - api
  - policy
  - concurrency
---

# A concurrent policy edit converges instead of failing the run

## Context

The policy file is the only resource the Tailscale API offers concurrency control
for. A read returns an `ETag`, and a write carrying `If-Match` is refused with a
412 when the document changed in between. Every other document this collection
manages, DNS and settings, has no such guard.

The collection guards the write and treats a 412 as fatal. That was written for one
reader: another task in the same play, where two writers racing is a mistake in the
playbook and stopping is the right answer.

The common case is a different reader. A tailnet is edited by hand, in the console
or through the API, by people and by other tools. A run that finds the document
changed under it is not looking at a playbook mistake, it is looking at a normal
tailnet, and failing the task means the operator runs it again by hand until the
window happens to be clear. That is not convergence, it is a loop with extra steps.

## Options considered

- **Keep failing on a 412.** Rejected. It is correct for a rival task and wrong for
  the tailnet everyone actually has, and it makes the collection unusable in the
  case it was most likely to meet.
- **Drop the guard and write unconditionally.** Rejected. It silently discards
  whatever the other writer did, which is the harm the guard exists to prevent.
- **Wait and retry the same write.** Rejected. The API has no cross-process lock,
  so waiting does not remove the race; it only moves it. The `If-Match` value is
  stale by definition, so retrying it unchanged can only fail again.
- **Re-read and re-apply, bounded.** Chosen.

## Decision

A 412 is not terminal. On one, the module reads the document again, recomputes the
diff against what is now there, re-validates, and writes again, at most three
attempts in total. If the attempts run out, the task fails and the message says the
document is contended.

The guard itself is unchanged: every write still carries `If-Match`, and a read
that returns no `ETag` still aborts rather than proceeding unguarded.

## Consequences

- **Nothing is written from a stale read.** Each attempt compares and writes against
  the document it has just read, so the diff it reports and the write it makes are
  about the tailnet as it is. That is the property the guard was protecting, and it
  survives.
- **The declared document stays authoritative.** A section another writer adds
  while the run is in flight is removed, because the file does not declare it. That
  is what a whole-document reconcile does on any run, and it is not a consequence
  of the race. What the retry changes is that the removal is reported: the diff's
  `before` is the document the retry read, so the operator sees what was replaced.
- **The change is reported.** When an attempt writes, the task reports
  `changed: true` and the diff's `before` is the document the attempt read, not the
  one the first read saw.
- **Two concurrent runs remain unsupported.** The API has no lock that spans
  processes, so two playbooks writing one policy file at the same moment cannot
  both be guaranteed. Each converges on the fields it declares; where both declare
  one field, the later write wins. That is a property of the API and is documented
  rather than papered over.
- **The attempt count is small and fixed.** A document that is genuinely contended
  fails after three attempts rather than retrying until something else gives. A
  bounded number is what keeps a race from becoming a hang.
- **DNS and settings are unaffected.** They carry no `ETag`, so there is no
  precondition to fail and no seam to retry on. An edit made between two runs is
  re-read and applied; an edit landing inside the write window is overwritten, and
  the safety model says so.
- **This narrows invariant 2.** The invariant reads "fail closed on concurrency".
  Its purpose is that a concurrent edit is never silently discarded, and that
  survives: the retry re-reads and re-applies rather than writing over a document
  it has not seen. Failing was one way to honour the purpose, not the purpose.
