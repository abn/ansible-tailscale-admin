---
type: Guide
title: Troubleshooting
description: The failures the Tailscale API actually produces, what each one means, and what to do
  about it.
status: draft
tags:
  - troubleshooting
  - errors
  - tailscale
---

# Troubleshooting

Every failure that came from an API call names the request it made and carries the
`x-tailscale-request-id` when the response had one. That request id is the only
handle Tailscale support has, so quote it. The upstream message is quoted in the
failure text where the API gave one, scrubbed of credential-shaped text and capped,
so what you read is what the server said rather than a paraphrase of it. A refusal
the collection made itself, such as a policy that opens the tailnet, names the
option to change instead, because nothing was sent.

The sections below are keyed to the status or the message you actually got.

## 401: the credential was not accepted

Tailscale answers a missing, a malformed and an expired credential identically,
with `API token invalid`, so the message cannot tell them apart. Check all three:
the credential reached the request, it is spelled correctly, and it has not
expired. A variable that resolved to nothing, or to whitespace, is treated as no
credential at all, and a task with no credential fails before sending anything.

If you are using an OAuth client, the secret is exchanged for an access token at
the start of the run. A client that has been revoked, or a token endpoint answering
an error document with a success status, is reported as such rather than as a
permissions problem.

## 403: the credential is valid and not authorised

The failure names the scope the operation needs, and the scopes that one depends
on. The commonest case is a policy task: `policy_file` and `policy_file:read`
additionally require `devices:posture_attributes:read` and `devices:core:read`,
because a policy can name a device by its attributes and Tailscale grants reading
those separately. The API's own refusal does not name the extra two; the
collection's does.

Granting a scope does not rescue a token that already exists, because scopes are
fixed when a token is issued. Mint a new one from the OAuth client or trust
credential. A personal API access token has no scopes to widen: it carries its
owner's permissions, so the only lever is that user's role in the admin console.

A `tailscale_settings` task can fail here per field. The settings endpoint
authorises each setting separately, so writing `network_flow_logging_on` needs
`logs:network`, `https_enabled` needs `networking_settings`, the two `acls_*`
options need `policy_file`, and the rest need `feature_settings`. The read is not
per option: give the credential all four read scopes as well, because the module
compares against the document the API returned and a credential that cannot see a
field cannot tell it unchanged from hidden.

## A policy write that keeps losing the race

The write was refused because the `If-Match` fingerprint no longer matched, which
means something else edited the policy between the read and the write, usually a
person in the console. The module reads the document again, recomputes the diff
against what it now holds, and writes again, up to three attempts, so a single
concurrent edit is converged rather than reported.

A run that reaches this message saw the document change on every one of its three
attempts, so it gave up. Nothing from the run was applied. Re-run once the other
writer is quiet, or let it finish first.

## The policy is refused because one of its own tests failed

A policy document can carry its own `tests`, and Tailscale refuses a document whose
tests do not hold. The module runs them before the write and reports the failures,
naming the test that failed and why, with up to five shown and the rest counted.

The refusal arrives from the validation request, not from the write, and that
distinction is worth knowing when you are reading a request log: a 200 from
`/acl/validate` is not a pass. The endpoint reports a failed validation with a
success status and the failures in the body.

That same status also carries warnings, and a warning is not a failure. You will
see one as a `WARNING` line in the output and the policy will still be written. A
common one names a group that is not syncing from SCIM and will therefore be
ignored by the rules referring to it, which is worth acting on even though the
write went through.

What the validator will not tell you is whether the document denies you access. It
runs the tests you wrote, so a document that grants the operator applying it nothing
passes if its own tests pass. Cover that case with a `tests` block that expects you
to have access, and the validator will refuse the document that would lock you out.

## 400: `requested tags ... are invalid or not permitted`

A tag exists only where the policy's `tagOwners` grants it, and a tag with no
owner cannot be applied to a device. Add the tag to `tagOwners` in the policy this
collection manages, then re-run.

The same refusal reaches `tailscale_service`, where a tag is access control
rather than metadata: a device can host a Service only if it carries one of the
Service's tags, so a Service carrying a tag nothing owns is refused the same way.

## 400: `when updating a service, addrs must contain 2 elements`

An update to a Service has to carry both its addresses, the IPv4 it holds and the
IPv6 the server assigned, and the API refuses one that carries neither or only
one. `tailscale_service` sends the pair the Service holds, so this reaches a task
written against something other than this module. Give `addrs` as the pair, or
leave it out to keep what is there.

## 400: `ports are empty, use "do-not-validate" to opt out of port validation`

A Service has to expose at least one port, on a create as much as on an update,
so a Service with nothing to expose is not expressible. Declare a `protocol:port`
pair, or `ports: [do-not-validate]` to stop the API validating the list.

## 400: `when creating a new service, addrs must be empty or contain 1 IPv4 address`

A Service that does not exist yet takes either no addresses, to let the server
choose, or a single IPv4. The IPv6 is always the server's to assign, so there is
nothing to declare. An existing Service takes the pair, which is the case above.

## 400: `bad IPv4 address: address is reserved for use by Tailscale`

The TailVIP range is `100.64.0.0/10`, and much of it is reserved for Tailscale's
own use and refused on a create. The message does not say which addresses are
free, so pick another. An address outside the range is refused by the same
endpoint with a message naming the range it requires.
## 400: `tagged nodes cannot be untagged without reauth`

A tagged device cannot shed its last tag through the API. The tag is the device's
owner, and a device with no owner has no identity in the policy, so Tailscale
requires it to authenticate again before it stops being that tag. Set the tags the
device should have rather than an empty list, or have the device re-authenticate
from the Tailscale app or the login screen, which is what makes the tag go. Giving
a device the tags it already has is not this failure.

## 400: `name "..." is already taken`

Device names are unique across a tailnet, and a name is held for a while after the
device that had it is gone, so a name that looks free in the machines page can still
be refused. Give the device a different name.
## 400: `tailscale.com/app-connectors: ...`

Four refusals come out of the app connector section, and each names the field:

- `connector (...) must be a tag` means a connector names a tag `tagOwners` does
  not grant. The whole write is refused, so nothing else in the document is
  applied either. An `app_connectors` entry on the task is checked for this before
  any request, and names the tag to add.
- `can only be specified with target "*"` means the document puts an `app` map on
  a node attribute entry targeting something narrower. An app map belongs on an
  entry targeting every node, which is what `app_connectors` creates.
- `preset app ID (...) is not valid` means the identifier is not one Tailscale
  recognises. Name the application with `preset` and let the module write the
  identifier, or give the identifier `preset_id` gives as the Apps page shows it.
- `domains must be empty when an preset app ID is defined` means the entry carries
  domains as well as a preset. Tailscale fetches the domains of a preset app
  itself, so drop `domains` from that entry.

## 400: `need at least one nameserver to enable MagicDNS`
## 400: `tailnet-owned auth key must have tags set`

A key minted with an OAuth client or a federated identity belongs to the tailnet
rather than to a user, and the API requires a tailnet-owned auth key to carry tags.
Add one under `capabilities.devices.create.tags`. A key minted with a user's API
access token belongs to that user and may omit them, so the same task can be
accepted with `api_token` and refused with `oauth_client_id`.

## 400: `keys of type "auth" can not be updated`

The API cannot change an auth key after it is minted, so a task that describes an
existing auth key differently has nothing to reconcile. `tailscale_auth_key`
refuses before sending, naming the fields that differ. Remove the key with
`state: absent` and let the next run mint another. Remember what that costs: the
devices which registered with the old key keep a key that no longer works, and a
device that has not yet re-registered has to be given the new one.

## 400: `keys: description had invalid characters`

A description accepts alphanumerics, hyphens and spaces, and nothing else, so a
value with a dot or a colon in it is refused. The limit is 50 characters.

## 400: `scopes cannot be empty`

An OAuth client needs at least one scope, on creation and on every update, because
the update replaces the whole credential rather than merging into it.

## The auth key task succeeds twice and the second result has no secret

That is the endpoint, not a defect. The API returns key material once, in the
response that creates the credential, and never again, so a run that finds the
credential already in place has nothing to hand over and cannot compare one. Take
the secret from a `register` on the run that reported a change, and store it: a
second run cannot recover it, and neither can this collection.

MagicDNS resolves names through a resolver, so `magic_dns: true` with an empty
`nameservers` list is refused. Add a resolver to the same task, or turn MagicDNS
off.

## 400: `exactly one capability scope must be populated`

The wording names a permissions problem and almost always is not one. Tailscale
emits it when content-type handling broke and the server could not parse the body.
HuJSON has to be sent as `application/hujson` and JSON as `application/json`; a
policy sent under the wrong one fails at the first comment and surfaces here. The
collection pairs the rendered document with its content type, so if you are hitting
this on a task you did not write, the body came from something else.

## 402: the plan or billing state forbids it

Nothing in the request changes this. It takes a billing change in the console. A
`tailscale_user` task that sets `role: auditor` on a free tailnet is refused here:
`auditor` is a paid role.

## 403 whose message names the billing plan

The plan or billing state also arrives as a 403 on some endpoints, where the status
is the one used for a missing scope, and the two need opposite advice. The API's own
message says which it is: `feature not available on current billing plan` is a
billing answer, and the collection reports it as one rather than naming a scope.
Widening a credential does not help.

The whole log streaming family answers this way, along with the network flow log
read, on a plan that does not include them. `tailscale_log_streaming` and
`tailscale_logs` with `log_type: network` are therefore only usable on a plan that
offers log streaming and network flow logging. `tailscale_logs` with
`log_type: configuration` works on any plan, because the configuration audit log is
not a paid feature.

Writing a custom posture attribute answers this way too. `tailscale_device_attributes`
reads a device's attributes on any plan, and every write is refused on a plan that
does not offer custom device posture attributes, whether it is the per-device pair
or the tailnet-level batch.

## 404: the resource was not found

The response does not distinguish three ordinary causes: it does not exist, it
exists in a different tailnet than the one addressed, or it is an ephemeral device
that deleted itself on disconnect, which is a race rather than an error when it
happens part way through a run.

A newly created OAuth client can answer 404 for a short while, and the failures
clear on their own as its scopes propagate. That is not a limitation of the `-`
shorthand for the default tailnet.

## 429: rate limited

Tailscale publishes no rate limits and documents no backoff interval, so there is
nothing to compute from the response. A rate-limited read is retried once after the
server's own `Retry-After`, capped so a mistaken value cannot park the run. Beyond
that, wait and re-run.

## No answer arrived: the request never reached a status

The connection was refused, reset after it was accepted, or timed out, or the body
stopped before it was complete. This is below HTTP, so there is no status and no
request id to quote, and nothing about the tailnet's health can be read from it. It
is a network or name resolution problem on the host running the module, not a
refusal.

A read that fails this way is retried once before you see it.

For a write, read what the message says carefully. It says the request may already
have been applied, and for `tailscale_policy` that matters: re-read the tailnet
before assuming your previous policy is still the live one. Re-running is safe
either way, because an unchanged policy writes nothing.

## 5xx: the API failed to serve the request

Server-side, so the request is not its cause and no change to the playbook will
fix it. Re-run, and quote the request id if it persists.

## 501: the API does not implement the operation

A statement about the server rather than about the request, so no change to the
playbook affects it. The one case with a known cause is deleting a device that was
shared into this tailnet from another one, which is not supported: a shared device
belongs to the tailnet it came from, so remove it there.

## The Service task reports a change on every run

A Service the API stores holds a pair of addresses the task never sent, because
the server assigns them. The module does not compare an address the task did not
declare, so a field it assigned cannot report a change. If you are hitting this,
the difference is a value the server will not store: an empty string or an empty
list is stored as an absent key, and sending one leaves a document that differs
from the tailnet for ever. The module drops those rather than sending them, so
this reaches a task written against something other than this module.

The other shape is a field the task omits that the endpoint requires. `addrs` and
`ports` are both mandatory on the wire, and a Service carrying neither is refused
by the API rather than stored.
## The user task says the API accepted the request and the change is not there

A success status is not proof that a write was carried out, and the users API
relies on that. Measured against a real tailnet, a role change for the user the
calling credential belongs to is answered 200 with no document and leaves the role
exactly as it was. The same request for the role the user already holds is
answered 500 with `failed to lookup actor info`, and a user-owned API access token
gets `not allowed to change own role`, so the same refusal arrives three ways and
only one of them says what it is.

Tailscale does not permit a credential to change the user it belongs to, and no
scope lifts that. The fix is a different credential: a client owned by the tailnet
but not by the user, or the other way round. Until then the module fails rather
than report a change it cannot see, which is also why a second run over the same
task would not have helped.

## The user task refuses because the user is the only owner

`is the only owner of the tailnet` means the change would leave nobody able to
administer it, which cannot be undone through the API. Give another user the
`owner` role first, in a task of its own, then re-run. The refusal is local and
holds in check mode, so a plan run tells you about it rather than promising a
change that the API would not accept.

## The user task says the tailnet holds no such user

A user exists once it has authenticated to the tailnet or accepted an invitation.
An invite is not a user: the user list does not carry it, so a tailnet can hold an
outstanding invitation and no user for it. Invitations need a user-owned key to
create, which an OAuth client cannot do, so this collection does not create them.

## The policy task reports a change on every run

Two different things produce this, and the difference is in what `changed_paths`
names.

A pointer to a field the server returns and your file omits is a real difference.
The modules do not inject the defaults the server materialises, because guessing
one would rewrite access rules, so the fix is to write the field into the file.

A pointer to a rule you did not touch is a canonicalisation gap: the two documents
disagree in a way the canonical form does not normalise, which is a defect worth
reporting with the two pointers.

## The device task reports a change on every run

Four measured behaviours produce this, and the fix is in the task rather than in the
module.

A device name that the task spells in a form Tailscale rewrites is refused outright
rather than sent, so this is not one of them: if a rename is reaching the API, the
name is already in the form the tailnet stores.

Tags and enabled routes come back from the API in its own order. They are compared
as sets, so a task that lists them in a different order is quiet. If a run does
report a change for tags or routes, the set really is different.

A boolean the server stores as an absent key, and an empty collection it stores as
an empty one, are both read as the value the task asked for. A repeated change on
`authorized`, `key_expiry_disabled` or `tags` means the value is arriving as
something other than the option, most often a string from a template.

A device selected by `device_name` is selected by the label it holds now, and a
rename moves that label. A task that renames and selects by name fails on its second
run with `No device in the tailnet matches`, which is a refusal rather than a quiet
run for the reason given above. Select by `device_id` or `address` when the name is
going to change.

## The policy task refuses to write anything

`Refusing to write the policy unguarded` means the read returned no `ETag`, so
there is no fingerprint to guard the write with. This is the API declining to
offer concurrency control rather than a transient failure, and re-running will not
help. Check what is between Ansible and the API: a proxy that strips response
headers will do it.

## A credential is refused but the scopes look right

Check which credential is actually in use. `api_token` and the OAuth options are
mutually exclusive, and a task that sets both fails rather than choosing, because
which one was meant is ambiguous. Values are stripped before use, so a token read
from a file that ended in a newline works.
