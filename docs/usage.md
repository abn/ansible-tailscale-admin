---
type: Guide
title: Usage
description: What one run of each module does, what it returns, and the behaviour worth knowing
  before the first real write.
status: draft
tags:
  - usage
  - tailscale
  - ansible
---

# Usage

These modules reach the Tailscale Admin API themselves, from the host that runs
the task, and change nothing on the machine Ansible is managing. Give them the
state you want and they make the tailnet match, so a task is a declaration rather
than a step in a procedure.

Every module takes the same connection options through the `tailscale` action
group. Declare them once with `module_defaults` and refer to the group, rather
than repeating `api_token` on each task:

```yaml
- name: Reconcile the tailnet
  hosts: localhost
  gather_facts: false
  module_defaults:
    group/abn.tailscale.tailscale:
      tailnet: "-"
      api_token: "{{ vault_tailscale_api_token }}"
  tasks:
    - name: Apply the access control policy
      abn.tailscale.tailscale_policy:
        policy: "{{ playbook_dir }}/policies/tailnet.hujson"

    - name: Require approval for new devices
      abn.tailscale.tailscale_settings:
        devices_approval_on: true

    - name: Turn MagicDNS on
      abn.tailscale.tailscale_dns:
        magic_dns: true
```

## What a run costs

| Module | Unchanged, or check mode | On a change |
|---|---|---|
| `tailscale_policy` | 1 read | read, validate, guarded write |
| `tailscale_dns` | 1 read | read, write |
| `tailscale_settings` | 1 read | read, patch |
| `tailscale_service` | 2 reads: the Service, then its hosts | read, write, read its hosts |
| `tailscale_service_info` | 1 read | never |
| `tailscale_log_streaming` | 2 reads | 2 reads, write, 1 read |
| `tailscale_logs` | 1 read | never |
| `tailscale_device` | 1 read | read, one write per property that differs, then a read back |
| `tailscale_device_info` | 1 read | never |
| `tailscale_device_routes` | 1 read, then the device's routes | the same, then one write if the routes differ |
| `tailscale_auth_key` | 1 list, or 1 read by `key_id` | read, then create, update or delete |
| `tailscale_user` | 1 read | read, one write per changed property, read |
| `tailscale_contacts` | 1 read | read, one patch per address that differs |
| `tailscale_device_attributes` | 1 read | read, one merge patch |
| `tailscale_aws_external_id` | 1 read | never: a read, unless `role_arn` is given, which adds one validation request |
| `tailscale_webhook` | 1 read | read, then create, patch or delete |

An OAuth client adds one token exchange per task, made on that task's first
request and reused for every request after it.

Check mode is a first-class path, not a write with the socket unplugged. For
`tailscale_policy` it is one read and a comparison, which is why it does not call
the server's validator: a check run that also validated would be two requests,
and the comparison is the answer the operator asked for.

## Return values

| Module | Returns | Meaning |
|---|---|---|
| `tailscale_policy` | `etag` | The fingerprint the run read the policy under |
| `tailscale_policy` | `changed_paths` | JSON Pointer of every node a write would change, empty when none would |
| `tailscale_policy` | `warnings` | What the module found in the document, and what the server reported about it, neither of which stops the write |
| `tailscale_policy` | `diff` | `before` and `after` policy documents |
| `tailscale_dns` | `dns_configuration` | The configuration the tailnet holds after the run, in the API's own camel case |
| `tailscale_dns` | `diff` | `before` and `after` configurations |
| `tailscale_settings` | `changed_settings` | The API field names this run changed, empty when it changed none |
| `tailscale_settings` | `diff` | `before` and `after` values, for the settings this run changed |
| `tailscale_service` | `service` | The Service the tailnet holds after the run, in the API's own camel case |
| `tailscale_service` | `hosts` | The devices hosting it, empty until a tagged device advertises the endpoint |
| `tailscale_service` | `approval` | Whether a device may host it, for a task that names a device |
| `tailscale_service` | `diff` | `before` and `after` Services, either of which is absent on a create or a removal |
| `tailscale_service_info` | `services` | Every Service the tailnet holds, as the API returns them |
| `tailscale_log_streaming` | `stream_configuration` | The destination the tailnet holds after the run, in the API's own camel case |
| `tailscale_log_streaming` | `streaming_status` | What the API reports about publishing to the destination |
| `tailscale_log_streaming` | `unverified_options` | The options this run wrote that it could not check, which are the write-only ones |
| `tailscale_log_streaming` | `diff` | `before` and `after` destinations |
| `tailscale_logs` | `logs` | The entries recorded over the window asked for |
| `tailscale_logs` | `log_count` | How many entries the window held |
| `tailscale_logs` | `window` | The window that was asked for, as the task gave it |
| `tailscale_logs` | `log_version` | The version of the response format, empty for a flow log |
| `tailscale_device` | `devices` | The device documents the run concerned, read back after any write |
| `tailscale_device` | `changed_devices` | Each changed device with the option names that changed on it |
| `tailscale_device` | `diff` | `before` and `after` for the changed properties, keyed by device ID |
| `tailscale_device_info` | `devices` | Every device the tailnet holds, as the API returns them |
| `tailscale_device_routes` | `device` | The device the routes belong to |
| `tailscale_device_routes` | `routes` | The advertised and enabled routes, after the run |
| `tailscale_device_routes` | `diff` | `before` and `after` enabled routes |
| `tailscale_contacts` | `contacts` | Every contact type as the tailnet holds it after the run |
| `tailscale_contacts` | `changed_contacts` | The contact types this run changed, empty when it changed none |
| `tailscale_contacts` | `diff` | `before` and `after` addresses, for the types this run changed |
| `tailscale_device_attributes` | `attributes` | The custom attributes the device holds after the run |
| `tailscale_device_attributes` | `changed_attributes` | The attribute keys this run set or deleted |
| `tailscale_device_attributes` | `device` | The device the attributes belong to |
| `tailscale_device_attributes` | `diff` | `before` and `after` values, for the attributes this run changed |
| `tailscale_aws_external_id` | `external_id` | The reusable external id this tailnet presents to AWS |
| `tailscale_aws_external_id` | `tailscale_aws_account_id` | The AWS account the trust policy has to allow |
| `tailscale_aws_external_id` | `validation` | The verdict, when `role_arn` was given: whether the policy trusts this tailnet, and the server's reason when it does not |
| `tailscale_auth_key` | `key` | The credential the tailnet holds after the run, in the API's own camel case and with the secret removed |
| `tailscale_auth_key` | `secret` | The key material, and only on the run that minted the credential |
| `tailscale_auth_key` | `removed_key` | The credential this run removed, empty when it removed none |
| `tailscale_auth_key` | `changed_fields` | The API field names this run set, empty when it set none |
| `tailscale_user` | `user` | The user as the tailnet holds it after the run, and null once it is gone |
| `tailscale_user` | `changed_fields` | The properties this run changed, in the order they were applied |
| `tailscale_user` | `diff` | `before` and `after` values, for the properties this run changed |
| `tailscale_webhook` | `webhook` | The endpoint the tailnet holds after the run, in the API's own camel case |
| `tailscale_webhook` | `secret` | The signing secret, and only on the run that created the endpoint |
| `tailscale_webhook` | `diff` | `before` and `after` endpoints, either of which is absent on a create or a removal |

`--diff` renders the `diff` key. For the policy and DNS modules it holds the whole
document on each side, so a large policy produces a large diff. For settings,
devices and routes it covers only what the run changed, because a diff across the
whole document would bury the line that matters. When nothing changes, both sides are
the same document and the diff is empty.

`changed_paths` remains the cheaper answer to "which rules would move", and unlike
the diff it does not carry the whole document to read past.

## tailscale_policy

The document is given either as a file path or as HuJSON text, and exactly one of
`policy` and `content` supplies it. A file is read on the host that runs the
module, so a path relative to the playbook has to be built with `playbook_dir`.
Either form may be HuJSON: comments, trailing commas and a byte order mark are all
accepted. `content` is for a document a template or a play has already produced,
and the declared sections splice into it exactly as they do into a file.

Both documents are put into a canonical form before they are compared, because the
same policy serialises differently depending on who wrote it and when. The
canonical form:

- sorts mapping keys, since any fixed order would differ from the order the
  server chooses;
- sorts the members of a set: `groups` and `tagOwners` members, `postures`
  conditions, and the approvers of a route or of an exit node. Rule lists
  (`acls`, `grants`, `ssh`) keep the order they were written in, because the file
  is what an operator authors and reviews, and a canonicaliser that reshuffled
  the rules would fold an unrelated edit into a rewrite of the whole policy;
- reads an `acls` entry as having one spelling, renaming the legacy `users` and
  `ports` to `src` and `dst`. An `ssh` rule's `users` names local unix accounts and
  is left alone.

The `ssh` section is Tailscale SSH's access rules, and this module passes it
through unaltered rather than reconciling it field by field. One field in it is
worth knowing about before it is written. `checkPeriod` decides how often a client
re-authenticates, and `"always"` asks for a check on every connection; Tailscale's
own policy reference notes that `always` "might cause unexpected behavior with
automation tools that open many SSH connections in quick succession (such as
Ansible)". This collection is not such a tool: it reaches the Admin API and never
SSH. But a play that provisions over Tailscale SSH will meet that behaviour if the
document it writes sets `always`, so choose the value deliberately.

What the canonical form does not do is as important. Comments are consumed on the
way in and not reproduced on the way out, and defaults the server materialises are
not injected. A file that omits a field the server returns therefore reports a
difference, and the fix is to write the field rather than to make the module guess
it.

The `etag` returned is the one the read produced. A write makes the server issue a
fresh fingerprint even when the content is identical, so treat the returned value
as the fingerprint of what this run compared against, not as something to hand to a
later run.

`allow_all_traffic` exists because an absent key is an easy accident. A document
with neither `acls` nor `grants` means allow-all to Tailscale, and an empty file or
a truncated document produces one. The refusal happens before any request, so
check mode reports it too.

Three of these properties were checked against a real tailnet, because no mock can
answer them: reconciling the policy a tailnet already holds reports no change; a
write of that document back is accepted and leaves the effective policy
byte-identical; and the server neither reorders nor reshapes what it was sent, so a
canonical form that did not account for server normalisation would report a change
on every run forever.

### Declaring part of the document on the task

`groups`, `app_connectors` and `tests` declare the three sections of the policy
language whose shape is regular enough to be mechanical, for a playbook that
would rather not hand-write them. Each is merged into what the file holds, so a
document can be written by the file, by the task, or by both. Where the two
disagree about the same group, the same connector or the same target, the module
refuses rather than choosing: a silent precedence would let a task overwrite its
own policy file without saying so.

An app connector is the one with a prerequisite worth knowing about. A connector
names tags, and a tag exists only where `tagOwners` grants it, so the server
refuses the whole write with `connector (...) must be a tag` when the document
does not grant one. The module checks that first and names the missing line. Two
further prerequisites the server does not insist on are reported as warnings
instead, because the document is accepted and the connector routes nothing:

- no access rule sends traffic to the connector's tag, so no client discovers the
  application at all. Discovery is a DNS query to the connector, so the rule has to
  exist even though it grants nothing else;
- no auto approver covers the connector's routes. A preset app's own routes are
  fetched and approved by Tailscale, so this one applies to a custom app.

A preset application is named as Tailscale publishes it, and the module holds the
mapping to the `presetAppID` the API wants, because the two are not the same
string: `Google Workspace` is `google-workspace`, and of the two Salesforce
environments the hosted one is `salesforce` and Hyperforce is
`salesforce-hyperforce`. Four of the fifteen carry a region in the identifier, and
Tailscale owns the list of regions and local zones, so those are given as
`preset_id` and written as given. An identifier the server does not recognise is
refused with `preset app ID (...) is not valid`.

An access test declared on the task is run by the server exactly as one the file
writes, which is not as safe as it looks. The server runs the assertions the
document contains and judges nothing else: it does not ask whether the rules would
leave you able to reach the tailnet. A `tests` block only catches what somebody
thought to assert.

## tailscale_dns

The endpoint replaces the whole configuration, so an option this module is not
given is taken from the current configuration rather than reset. Every option is
therefore optional, and a task that sets one option leaves the rest as they are.

The API behaves here in ways the option names do not suggest:

- `nameservers` is an ordered preference list, and the order is preserved. An
  entry is either the address on its own, as a string, or a mapping with
  `address` and an optional `use_with_exit_node`.
- A resolver mapping that leaves `use_with_exit_node` out keeps whatever the
  tailnet holds for that address, so omitting the field does not turn it off.
  `use_with_exit_node: false` is the explicit way to clear it. The field is never
  sent as false, because the server stores a false as an absent key.
- MagicDNS resolves names through a resolver, so enabling it with an empty
  `nameservers` list is refused with a 400.
- Removing every nameserver turns MagicDNS off, so the two settings are not
  independent.
- `override_local_dns` decides whether `nameservers` replaces the host's own
  resolvers or acts as fallbacks behind them. With it false, the list is the
  fallback.
- `split_dns` maps a domain suffix to its resolvers. Give a domain an empty list
  to clear it.

## tailscale_settings

This endpoint merges, so no option carries a default: an option the task left out
is dropped from the request and the server leaves that setting alone. That is why
`devices_approval_on: false` is an instruction and an absent `devices_approval_on`
is not one.

Only the options given are compared. A setting this module does not manage cannot
make a run report a change, however the server chooses to report it, which is what
stops a run reporting drift on a field nobody asked about.

The API authorises this endpoint per field, so the scope a task needs depends on
the option. See [authentication](authentication.md).

## tailscale_service

A Service is a named resource published into the tailnet with its own MagicDNS
name, its own addresses and its own access control, fronting one or more back-end
hosts. Its name starts with `svc:` and the rest is a DNS label.

The PUT replaces the whole Service, so a field the task does not mention is sent
back as the value the Service already holds. Two fields are not optional on the
wire, and the module carries them forward for that reason rather than by a rule
of its own:

- `addrs` must carry both addresses on an update. A PUT naming only a comment and
  carrying no `addrs` is refused with `when updating a service, addrs must
  contain 2 elements`, and so is one carrying a single address.
- `ports` must not be empty, on a create as much as on an update. Declaring an
  empty list is refused with the advice to use `do-not-validate` to stop the API
  validating the list, and a create that names no port at all is refused the
  same way.

`addrs` and `ports` are the two things the API will not store as absent, and the
other three will: a comment, a display name and a tag list sent empty are each
stored as an absent key, so `comment: ''` and no comment are the same state. The
module removes an empty value from the request rather than sending it, and treats
it as the same state, which is what makes clearing a comment converge.

The addresses are the server's to assign. A Service that does not exist yet takes
either no `addrs` at all, to let the server choose, or a single IPv4 to assign;
the IPv6 is always assigned, and the pair comes back in `service` rather than in
the diff, because a check run cannot know them. An address the task did not
declare is never compared, so an address the server assigned cannot report a
change.

`tags` on a Service are access control rather than metadata: a device can host
the Service only if it carries one of them, and a tag exists only where the
policy's `tagOwners` grants it. A tag with no owner is refused with the reason.

Setting a device option turns the task from managing the Service into managing
whether that device may host it, and `approved` is the whole of that
instruction. The device is named the way `tailscale_device` names one: by
`device_id`, or by `device_name` or `address`, in which case the device list is
read and the selector applied to it, so a name matching no device, or more than
one, is refused rather than guessed at. The device options are refused alongside
the options that describe the Service, and `state` has to stay at `present`,
because a task about one device removing the Service it hosts is not something
to infer. A device the API cannot see is an error rather than a state to
reconcile: it either does not exist or it is shared in from another tailnet, and
neither is something an approval reconciles.

A Service declared together with the hosts it may run on is therefore two tasks,
one declaring the Service and one approving each host. That is the intended shape
rather than a limitation: a Service and an approval are two resources, and the
module covers both because a reader thinks of `Services` as the whole feature.
The two tasks are independent, so either can be applied without the other.

`state: absent` removes the Service, and the MagicDNS name it published goes with
it, along with the addresses. A run over a Service that is already gone reports
no change, because the 404 is the answer to whether it is there rather than a
failure.

Three of these properties were measured against a real tailnet rather than
assumed, because each of them is a difference a mock cannot produce: the server
assigns a pair of addresses a create never asked for, an update is refused
without the pair, and an empty value is stored as an absent key.
## tailscale_service_info

Returns the list endpoint `tailscale_service` selects a name from, for a task that
has no name yet. `services` holds the API's own `VIPServiceInfo` documents
unaltered, so `name` carries the `svc:` prefix, `addrs` is the IPv4 followed by the
IPv6, and `ports`, `tags`, `displayName` and `comment` are as the Service was
created. It always reports `changed=False` and reads once.

A task that already names a Service reads it through `tailscale_service` in check
mode instead. This module is for enumerating what exists.

## tailscale_log_streaming

This one declares a destination, and the API replaces it rather than merging, so
an option the task left out is taken from the destination the tailnet already has
instead of being reset. `state: absent` removes the destination and is quiet on a
tailnet that has none.

A password is the awkward part, and it is the API's awkwardness rather than this
module's. The API never returns one, which has two consequences worth planning
around:

- a task that changes any other field of a destination that holds a password has
  to give the password too, because the write replaces the whole destination and
  there is no stored password for the module to carry over;
- a task that gives a password writes on every run and reports a change on every
  run, because there is nothing to compare it against. The write is the same
  document each time, so the effect is idempotent even though the report is not.
  The run says so in `unverified_options`, and the diff shows the field as
  `(write-only)` rather than either omitting it or printing the value.

`streaming_status` is read on every run, which is the second request in the cost
table above. It is there because a destination that is configured and not
receiving anything is the failure worth seeing, and because the counters in it are
the only evidence of that. It moves on its own, so it is reported and never
compared: an unchanged destination is `changed: 0` however much the status has
moved since the last run.

The whole family, and the network flow log read, is refused on a plan that does
not include log streaming. See [troubleshooting](troubleshooting.md).

That gate is also why one thing about this module is unmeasured. Every other
module here stores as an absent key whatever value the server will not keep, and
the comparison has to know that or a satisfied task reports a change for ever.
That behaviour was measured for DNS, for the settings and for a Service. It has
not been measured for a log destination, because writing one needs a plan that
offers streaming, and the test tailnet does not. A destination option whose value
the server declines to store would therefore report a change on every run until
this is measured on a plan that allows it. The write-only options above are the
one case that is known, and they are handled.

## tailscale_logs

This one is not a resource. It reads the entries a tailnet recorded over a window
and hands them back, so it has no `state`, always reports `changed: 0`, and
returns no diff. A diff between two reads of a window that has moved describes the
passing of time rather than anything a task did, and rendering it would read as
configuration drift.

`log_type` selects the endpoint rather than filtering one, because the two logs
are separate endpoints with separate scopes. `actor`, `target` and `event` filter
the configuration audit log only, and the module refuses them with
`log_type: network` rather than sending a parameter the API has no meaning for,
which it would ignore without complaining.

The window is `start` and `end`, both required and both RFC 3339. The API accepts
a `Z` suffix or a numeric offset, and refuses a date on its own, a timestamp with
no offset, and anything it cannot parse. `end` in the future is not a wait: the API
does not block for a window to close, and answers with what exists. `end` before
`start` is not an error either, and yields no entries.

The whole window comes back, so a wide window on a busy tailnet produces a large
result. Narrow it, or filter it, and use `log_count` when only the number matters.
The entries are the API's own documents, unaltered, so a task reading them needs
to tolerate fields Tailscale adds.
## tailscale_device

A device cannot be created. One appears when something authenticates to the
tailnet, so every task names a device the tailnet already holds, with exactly one
of `device_id`, `device_name`, `address` or `tag`. A selector matching no device is
a failure, and so is one matching several: the module will not choose between two
devices for you, because the cost of choosing wrongly is a rename, a tag or an
approval on the wrong machine. Under `state: absent` the intent is that nothing
matching the selector is left, so every match is removed and no match is the
desired state.

Selecting by name means selecting by the label the device holds now, and that is
the label a rename changes. A task that renames has to select by `device_id` or
`address`, or its second run will not find the device it renamed.

The API stores several of these values in a form the request does not have, and
each one was measured rather than assumed:

- A device name is rewritten, not stored. Uppercase is lowercased, a dot and an
  underscore both become a dash, a trailing dash is dropped, and the tailnet's own
  suffix is appended. The module accepts only a name already in the form Tailscale
  keeps and refuses any other, rather than reporting a change on every run for a
  name the tailnet will never hold.
- Tags and enabled routes are sets. The server returns them in its own order
  whatever order they were sent in, so they are compared without regard to order.
- A boolean that is off is stored as an absent key, and an empty collection as an
  empty one. Both are read as the value the task asked for, so `authorized: false`
  on an unapproved device and `tags: []` on an untagged one are quiet.
- The name Tailscale reports as a device's `hostname` does not follow a rename.
  The renamed value is the label of its MagicDNS name, and that is what this module
  compares.

Three of the options reach past the device's record. `expire_key` makes the device
authenticate again, `tailscale_ip` breaks every existing connection to it,
including the one Ansible is running over when the device is the control node, and
`authorized: false` disconnects the device: measured against the real API, a device
whose approval is revoked is gone from the tailnet within seconds and has to
authenticate again.

`expire_key` converges because the expiry a device already carries is visible to
the API: a key that has passed is not expired again.

## tailscale_device_info

Returns every device the tailnet holds, which is the list `tailscale_device`
selects one device from. `devices` holds the API's own `Device` documents
unaltered, so `addresses` is the IPv4 followed by the IPv6, `name` is the MagicDNS
name, `hostname` is the machine name, and `nodeId` and `id` are the two
identifiers the API accepts. It always reports `changed=False` and reads once.

`tailscale_device` reads one device, the one its task named, and returns its state
after the run. This module reads them all, which is what a task feeding another
control plane needs and what a check-mode run of `tailscale_device` cannot do,
because that module declines a task naming no device.

## tailscale_device_routes

Routes are advertised, not received. A device advertises the subnets it is willing
to serve and no API call changes that, so this module enables among the routes a
device has advertised. Enabling one it has not advertised is accepted and stored,
and takes effect when the device advertises it, so `routes` in the result is worth
reading before a playbook assumes a subnet router is serving.

The endpoint replaces the list, so `enabled_routes` is the whole list the device
should have, and an empty list is how a device is stopped acting as a subnet router
or an exit node without deleting it.
## tailscale_auth_key

The three kinds of credential share one endpoint and three request shapes rather
than being one resource, so `key_type` selects the shape a task uses and the
module refuses an option belonging to another kind rather than passing it on. The
option names mirror the API's own nesting, so the auth key's device capabilities
sit under `capabilities.devices.create` and its tags sit there, while the tags a
client may put on the keys it creates are the top-level `tags`.

Two properties of the endpoint shape what a task can ask for:

- **The secret is returned once.** The API sends the key material in the response
  that creates the credential and never again, so it can only be read from a
  `register` on the run that reported a change, with `no_log: false` on that task.
  A second run finds the credential already in place and reports no secret, which
  is not a defect: there is nothing to compare and nothing to hand over.
- **An auth key cannot be updated.** The API refuses to change one at all, so a
  task describing an existing auth key differently fails rather than reporting a
  change it cannot make. Remove the key and let the next run mint another, which
  also leaves the devices that registered with it holding a key that no longer
  works. OAuth clients and federated identities do update, and that update
  replaces the whole credential, so the module carries over every field the task
  did not name.

The description is the handle, because a key id is opaque and the API accepts a
duplicate description without complaint. A description two credentials share is
refused rather than resolved by picking one. A description also accepts only
alphanumerics, hyphens and spaces, and the API refuses anything else.

An auth key minted with an OAuth client or a federated identity belongs to the
tailnet rather than to a user, and the API refuses one with no tags at all. A key
minted with a user's API access token belongs to that user and may omit them. A
tag exists only where the policy file's `tagOwners` grants it, so a key naming a
tag the tailnet does not own is refused, and the failure names `tagOwners`
because that is the file to change.
## tailscale_user

A user is not something a playbook creates. One appears on the tailnet when
somebody authenticates to it or is invited and accepts, and the API has no
operation that makes one. So this module reads the user list, selects one user
from it, and reconciles the properties the API lets it change: `role`,
`suspended`, `approved`, and `state: absent` to remove the user.

The selection is deliberately unforgiving. A task that names a user the tailnet
does not hold fails, because the module cannot make the user exist and reporting
success would be a lie. A selector matching several users is refused rather than
resolved to one of them, and the failure names the candidates so `user_id` can
disambiguate. `state: absent` is the exception: a user that is not there is the
state the task asked for, so the run is quiet.

`suspended` and `approved` are two readings of the one status field the API
returns. `active`, `idle` and `over-billing-limit` all mean neither suspended nor
awaiting approval, so neither operation is called for a user in one of them. That
is what keeps `suspended: false` quiet against a user who has simply not been
seen for a month.

Three things about this endpoint are worth knowing before the first real write:

- A change that would leave the tailnet with no owner is refused before anything
  is sent, in check mode as well as in a real run, because a tailnet nobody can
  administer cannot be repaired through the API.
- Every per-user operation answers with no document, so the module reads the user
  back after writing it. That is also how it notices a write the API accepted and
  did not perform, which it does not report as a change.
- A credential cannot change the user it belongs to, and the API does not say so
  consistently. See [troubleshooting](troubleshooting.md).

## tailscale_contacts

Three addresses, `account`, `support` and `security`. Each is reconciled
independently and an option the task leaves out is not managed, so a task that
names one address writes one address.

Only the address is compared. A contact that is waiting for someone to follow a
verification link carries `needsVerification: true`, which is the server's state
and not this module's, so a pending verification never reports a change. The
module returns it so a task can see it.

An empty address is refused before the request. The API answers an empty or
missing address with a bare 500 that says nothing actionable, and there is no way
to clear a contact through it, so the refusal is the module's own message rather
than the server's.

The resend endpoint is not exposed. It sends a verification email and changes
nothing the API reports, so a task using it could never reach `changed: 0` on a
second run, and invariant 1 is that a second run is quiet.

## tailscale_device_attributes

The custom posture attributes of one device, selected the same way
`tailscale_device` selects one: exactly one of `device_id`, `device_name`,
`address` or `tag`, and a selector matching none or several is refused.

`attributes` is a list of `{key, value}`. A key carries the `custom:` prefix;
`node:` attributes are the server's own and a task naming one is refused before a
request.

A set and a delete travel in one request. The tailnet-level endpoint is a JSON
merge patch, so an attribute the task names is written, an attribute it gives no
value for is deleted with `null`, and an attribute the task does not mention is
left alone. Only the attributes this task manages are compared, so the read-only
`node:` attributes never report drift.

Writing a custom attribute is plan-gated. The read works on any plan and every
write is refused with `403 feature not available on current billing plan` on a
plan that does not offer custom device posture attributes. See
[troubleshooting](troubleshooting.md).

## tailscale_aws_external_id

A read, with one option that is not reconciled state. The module asks for a
reusable external id and returns it, and it reports `changed: false` on every run,
including the first. There is no delete for the id and no field in the response
that distinguishes a creation from a read, so no honest `changed: true` exists and
the module does not claim one.

`role_arn` is optional and is a validator rather than a state. When it is given,
the module asks the API to check that the named role's trust policy trusts this
tailnet's AWS account and requires this external id, and returns the verdict. A
policy that does not answers `422` with the server's own reason, which the module
reports as a verdict rather than as a task failure.

Without `{"reusable": true}` every call mints a new id. That is why the module
always asks for a reusable one: it is what makes the family a read rather than a
write.

## tailscale_webhook

A webhook endpoint is a URL Tailscale POSTs tailnet events to. It has no name a
task can use before it exists, so the module addresses it by `endpoint_url`: it
reads the tailnet's endpoints, finds the one holding that URL, and creates one
only when none does. The API refuses a second endpoint on a URL, so this lookup is
what makes a second run quiet rather than a failure.

Only the subscription list can change after the endpoint exists. The update
operation takes `subscriptions` and nothing else, so `endpoint_url` and
`provider_type` are fixed at creation. A task declaring a different provider type
on an existing endpoint is refused, because the only way to change it is to remove
the endpoint and create another, which issues a new signing secret.

Three measured properties are worth knowing before the first write:

- An update replaces the subscription list rather than merging into it, so the
  task's list is the whole list the endpoint should hold. The API refuses an
  update that clears the list, and an endpoint subscribed to nothing never
  receives an event, so the module declines an empty one.
- The server returns the events in its own order with duplicates removed, so
  `subscriptions` is compared as a set. Declaring the same events in another order
  is not a change.
- `endpoint_url` must be an absolute HTTPS URL. The API checks the URL's shape and
  not its reachability, so a URL that answers nothing is accepted at creation and
  an event sent to it later fails at that point rather than here. The module
  refuses a URL that is not HTTPS before making a request.

The signing secret is returned by the API only in the response that creates the
endpoint, and never by a later read. The module returns it as `secret` on that run
alone, so read it from a `register` on the run that reported a change.

The test and rotate operations are not exposed. One sends a real event and changes
nothing the API reports; the other issues a secret that is returned once, like
minting an auth key. A task driving either could never report `changed: 0` on a
second run.

## Looking a value up in a template

Two lookups resolve a single value for a template, where registering a facts module
and indexing it would be noise.

```
{{ lookup('abn.tailscale.device', 'nibbler', want='ipv4') }}
{{ lookup('abn.tailscale.service', 'svc:web', want='ipv4') }}
```

`want` picks the property: `name`, `hostname`, `ipv4`, `ipv6`, `node_id`, `id` and
`tags` for a device, and `name`, `display_name`, `comment`, `ipv4`, `ipv6`, `ports`
and `tags` for a Service. A device may also be named by an address it holds or by
the id the API lists; a Service is named by its `svc:` name. A term matching no
device, or more than one, is an error rather than a guess.

A lookup takes the connection options the modules share, but the action group and
`module_defaults` do not reach a lookup, so the credential comes from the call or
from a variable. The variables are `tailscale_api_token`,
`tailscale_oauth_client_id`, `tailscale_oauth_client_secret` and
`tailscale_tailnet`, which are the names the collection's examples already use for
the values they feed a module.

## Running it for the first time

Three steps, in order.

1. **Get a credential.** An OAuth client is preferred and
   [authentication](authentication.md) says how to make one and which scopes each
   module needs. A user-owned API access token also works and carries every
   permission its owner has, which is why it is second choice.
2. **Write the play**, or start from [`examples/site.yml`](../examples/site.yml),
   which declares a policy, DNS, settings and a Service and is walked through in
   [examples](examples.md). Credentials come from the environment, so nothing
   secret is written into the play.
3. **Check, then apply.**

```sh
ansible-playbook examples/site.yml --check
ansible-playbook examples/site.yml
ansible-playbook examples/site.yml     # changed: 0
```

Read the recap from the check run before applying. A policy task that reports
differences tells you which nodes would change, so a wrong `policy` path or a
truncated file shows up as a change you did not intend rather than as a silent
no-op. The third command is the one that matters: the same playbook over the same
tailnet reports no change at all, which is what the collection is for.

If a module refuses rather than writing, the message names what it refused and
why. [troubleshooting](troubleshooting.md) is the index of the failures the API
actually produces and what each one means.
