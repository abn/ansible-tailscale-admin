---
type: Reference
title: Safety model
description: What the modules guarantee before they write, and the failure modes nothing in the
  collection protects you from.
status: draft
tags:
  - safety
  - tailscale
  - policy
---

# Safety model

The policy file is replaced whole, it governs what can reach what, and there is no
partial success: one wrong document affects every device in the tailnet at once.
That is what the guarantees below are about.

## What the policy module does

**A document that opens the tailnet is refused.** A policy with neither an `acls`
nor a `grants` key means every device can reach every other, and the two failure
modes are asymmetric. An empty list, in either spelling, denies everything, which
is the safe direction, so it needs no confirmation. An absent key needs
`allow_all_traffic: true`, set on the task, because an allow-all policy is
indistinguishable from one whose rules were lost. The refusal happens before any
request, so a check run reports it too.

That distinction is measured rather than assumed. Asked of the server's own
evaluator, on a tailnet with a real device in it: a wide-open ACL allows traffic,
`"acls": []` denies it, `"grants": []` denies it, and `{}` allows it. The stored
document cannot answer the question, because the server accepts all four verbatim
and normalises none of them, so they come back looking equally rule-free.

**The proposal is offered to the server's validator before it is written.** On a
change, the module posts the document to the validator and then writes it. A
failed validation is caught by the validator call, not by the write, which
matters because the endpoint answers a failure with a 200 and a body rather than
with a status: a module that only read the status would prove nothing and would
leave the refusal to the write. The failures are reported with the test that
failed and why, bounded to five and scrubbed, because the response shape is the
one place the API returns user identities.

What the validator does not do is judge reachability. It runs the `tests` your
document declares, and nothing else. A document that denies the operator applying
it all access passes if its own tests pass, so the case the validator cannot
catch is the case a `tests` block has to cover.

**The write is guarded, and a lost race is retried.** The module keeps the `ETag`
the read returned and writes with `If-Match`. If anyone edited the policy in the
console in between, the write is refused with a 412 rather than discarding their
work, and the module reads again, recomputes against what the document now holds
and writes again, up to three attempts. A single console edit is therefore
converged instead of reported. A document that changes on every attempt fails and
says it is contended, and nothing from that run is applied. A read that returned
no `ETag` aborts the write outright: there is no way to tell "did not happen" from
"happened, and the answer was lost", and that is a property of the API rather than
a transient failure, so nothing is sent and a retry cannot help.

**Comparison is canonical.** Both documents are normalised before they are
compared, so key order, member order inside a set, and the legacy `users`/`ports`
spelling of an ACL entry do not produce a difference. Without that, every run would
report a change and the task would stop meaning anything. What it does not do is
inject the defaults the server materialises, so a field the server returns and
your file omits is a real difference and is reported as one.

**Check mode is one read.** It compares and reports, and it writes nothing.

## What the DNS, settings and service modules do

Neither replaces the whole tailnet, and both need the same discipline about an
option the task did not give.

`tailscale_dns` sits on a replace endpoint, so an option the task did not give is
sent back as the value the tailnet already holds. Sending a default instead would
reset a field nobody mentioned, which on that endpoint is indistinguishable from
asking for it. Comparison is still over the whole merged document, so a second run
reports no change.

The server does not store a value that is already the default. A `false` comes back
as an absent key, and so does an empty list or map, so the module removes a value
that is off rather than sending it as `false`, and an empty collection clears its
key rather than emptying it. Without that, a task saying `magic_dns: false` sends a
document the tailnet will not hold, and reports a change on every run for ever. This
is measured, not assumed: each of those six shapes was written to the real endpoint
and read back.

`tailscale_settings` sits on a merging endpoint, so an option the task did not give
is dropped from the request. No option carries a default, so an option left out
stays distinct from one set to false. Only the options given are compared.

`tailscale_service` sits on a replace endpoint as well, so an option the task did
not give is sent back as the value the Service holds. Two of its fields are
mandatory on the wire whatever the task says, the addresses and the ports, and
carrying them forward is what makes an update naming one field possible at all.
The addresses are the server's to assign, so an address the task never declared
is not compared, and a value the server will not store, which is any empty
string or empty list, is dropped from the request rather than sent. A Service
that has to expose nothing is not expressible: `ports` must name one port, or
`do-not-validate` to stop the API validating the list.

Removing a Service is the most destructive thing outside the policy file. It
takes the MagicDNS name with it, and the addresses go with the name, so a
Service recreated under the same name answers on a different address. The module
refuses a task that combines removing a Service with naming a device to approve,
because the two are different resources and only one of them is reversible.

A DNS change reaches every device in the tailnet, including devices this playbook
knows nothing about.

## Transport and failure

Only `GET` and `HEAD` are ever retried, and only once. A retried write cannot be
taken back: the API may have applied the change and still answered with a 5xx or a
dropped connection, so a second attempt would turn a visible failure into a
divergence between what you asked for and what the tailnet holds. One retry covers
a burst caused by a concurrent run. Anything beyond that is a tailnet under real
pressure, which you need to see rather than have hidden. Each request is bounded by
`timeout`, which is 30 seconds by default.

A rate-limited read waits for the server's own `Retry-After`, capped so a mistaken
value cannot park the run. A read that fails below that, at the socket rather than
at a status, waits the short default and tries once more. That covers a refused
connection, a reset after the connection was accepted, a body that stopped early
and a timeout, which are the four ways a network blip arrives. A write failing that
way is not retried, and its message says the request may already have been applied
rather than telling you nothing changed, because for a policy write that would be
the dangerous direction to be wrong in.

Failures are written to be acted on rather than to be re-read. A 403 names the
scope the operation needs and the scopes that one depends on. A 404 does not guess
between the three ordinary causes. A 412 says the policy changed under the run.
Every message carries the `x-tailscale-request-id` when the response had one, which
is the only handle Tailscale support has.

Nothing sensitive is put in a failure message in the first place. The `data` shape
on a validator response, which carries user addresses, is read in exactly one place:
turning a failed validation into a message about your own policy. It is not read on
the way to constructing an error from any other response, so a 4xx or 5xx still
carries only the `message` field. What is read is scrubbed of credential-shaped
text, collapsed onto one line, and capped, so an echoed token cannot reach a log
and an embedded newline cannot forge a line in a transcript.

## What none of this protects you from

A wrong policy that is valid. The server's access tests check syntax and whether
the principals a rule names exist. They do not check whether the rules are what
you meant, so a policy that denies the laptop you are connected from is written
happily.

An over-privileged credential. An API access token carries every permission of the
user who created it, and the collection asks the token endpoint for no scope at
all, so an OAuth client is only as narrow as the scopes it was created with. A
leaked secret is a leaked tailnet, and the `no_log` on the option stops it reaching
a log rather than stops it leaking.

A concurrent console edit to DNS, settings or a Service. The policy file is the
only resource the API offers concurrency control for, so it is the only one this
collection guards. A nameserver, a setting or a Service changed in the console
between a run's read and its write is overwritten, and the run reports success.
There is no option to override that with, on any of those modules.

Rollback. A run that fails part way leaves the tailnet as the last successful
write left it. Reconciling is the recovery: fix the file or the task and run
again, and the modules converge.

A check run proving the write will work. Check mode compares, and for the policy
that comparison is one read, which means the server's validator does not run. A
document that reports differences in `--check` can still be refused on the real
run, and the reasons it is refused are the reasons the API gave.

A device behaving. Nothing here configures `tailscaled`. A device can be pointed at
a different tailnet, unenrolled, or running an old client, and access control only
binds the devices that are in the tailnet at all.

An ambiguous write failure being resolved for you. Not retrying writes means a
failure is reported rather than hidden, which is the right side of that trade, but
it also means a run that dies mid-write leaves you to establish whether the change
landed. Read the policy before running again, and the next run will tell you.
