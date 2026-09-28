# Ansible Collection: abn.tailscale

Manage a Tailscale tailnet declaratively through the Tailscale Admin API v2.

A playbook declares the access control policy, the DNS configuration, the tailnet
settings, the Services, the devices and the users it wants. Each module reads what
the tailnet holds and writes only what differs, so a playbook that applies the same
state twice reports `changed: 0` the second time.

Version 1.0.0. Sixteen modules cover the access control
policy, the DNS configuration, the tailnet settings, the Services and their host
approvals, the devices and their routes, the credentials, the users, the logs and
log streaming, the contacts, the posture attributes, the webhooks and the AWS
external id. `tailscale_device_info` and `tailscale_service_info` read a tailnet's
devices and Services as facts, and the `abn.tailscale.device` and
`abn.tailscale.service` lookups resolve one of each for a template. The
[overview](docs/overview.md) covers the design, and the
[safety model](docs/safety-model.md) covers what the modules refuse and what they
cannot protect you from.

## Read this first

The policy file is the one resource with real blast radius, so the collection is
built around it. Read the [safety model](docs/safety-model.md) before a first real
run: it covers what the modules refuse, what a check run does not tell you, and the
one case where a document that denies you access is still accepted by the server.

## Requirements

- `ansible-core` 2.19 or later.
- Python 3.12 or later on the host that runs the module. A module can use only
  the standard library and `ansible.module_utils`.
- No collection dependencies and no Python package dependencies, because a module
  has nowhere to install one.
- A credential: an API access token, or an OAuth client ID and secret.

## Install

```sh
ansible-galaxy collection install abn.tailscale
```

To track `main` instead of a release, install from the repository:

```sh
ansible-galaxy collection install git+https://github.com/abn/ansible-tailscale-admin.git
```

A release tarball installs the same way, with a path in place of the URL:

```sh
ansible-galaxy collection install ./abn-tailscale-1.0.0.tar.gz
```

Either way the collection lands in `ansible_collections/abn/tailscale` under the
first entry of `collections_path`, which is `~/.ansible/collections` unless you
have set that.

## Authentication

Both schemes are accepted by every module, through the `tailscale` action group.

An **API access token** (`tskey-api-` prefix) is created in the admin console
under Settings, then Keys. It expires within 90 days and carries every permission
of the user who created it: there is no such thing as a read-only API access
token. Treat one as the user's own password.

An **OAuth client** is created under Settings, then Trust credentials. The client
secret is recognisable by its `tskey-client-` prefix. The collection exchanges the
secret for an access token on the first request of a task, reuses that token for
every call after it, and mints a fresh one 60 seconds before the endpoint says it
expires. The scopes come from the client, not from the request, so narrowing them
is a console action. An OAuth client is the right credential for automation: it
belongs to the tailnet rather than to a person, and its tokens do not linger for
months.

Nothing is read from the environment. A task with no credential fails
immediately, by name, rather than after a request it had no business making.

Declare the credential once for the whole play:

```yaml
- name: Reconcile the tailnet
  hosts: localhost
  gather_facts: false
  module_defaults:
    group/abn.tailscale.tailscale:
      tailnet: "-"
      oauth_client_id: "{{ vault_tailscale_oauth_client_id }}"
      oauth_client_secret: "{{ vault_tailscale_oauth_client_secret }}"
  tasks:
    - name: Apply the access control policy
      abn.tailscale.tailscale_policy:
        policy: "{{ playbook_dir }}/policies/tailnet.hujson"
```

`tailnet: "-"` is Tailscale's shorthand for the default tailnet of the credential
in use, and it survives the credential being moved. Name a tailnet explicitly when
one playbook manages more than one.

The scopes each module needs are in
[docs/authentication.md](docs/authentication.md). The short version: a policy run
needs `policy_file:read` to read and validate and `policy_file` to write, and
both of those also require `devices:posture_attributes:read` and
`devices:core:read`. A credential without all of them is refused with a 403 that
does not name the two extra ones.

## First run

Put a policy file next to the playbook. It may use HuJSON: comments and trailing
commas are allowed, and they are not preserved in what gets sent.

```json
// policies/tailnet.hujson
{
  "groups": {
    "group:admins": ["user1@example.com"],
  },
  "acls": [
    { "action": "accept", "src": ["group:admins"], "dst": ["*:*"] },
  ],
}
```

Then ask what would change, without changing it:

```sh
ansible-playbook site.yml --check
```

Check mode makes exactly one request, a read. `tailscale_policy` reports the
JSON Pointer of every node that a write would touch, so `--check` tells you which
rules move rather than only that something does. When the output is what you
expected, drop `--check`. The run after that one reports `changed: 0`.

## The modules

| Module | Reconciles | Endpoint |
|---|---|---|
| `tailscale_policy` | The whole access control policy, from a HuJSON file or text | `GET`/`POST /tailnet/{tailnet}/acl`, `POST .../acl/validate` |
| `tailscale_dns` | Nameservers, split DNS, search paths, MagicDNS and override preferences | `GET`/`POST /tailnet/{tailnet}/dns/configuration` |
| `tailscale_settings` | Individual settings such as device approval and key duration | `GET`/`PATCH /tailnet/{tailnet}/settings` |
| `tailscale_service` | A Tailscale Service, and whether a device may host it | `GET`/`PUT`/`DELETE /tailnet/{tailnet}/services/{serviceName}`, and the host and approval paths under it |
| `tailscale_service_info` | Every Service the tailnet holds | `GET /tailnet/{tailnet}/services` |
| `tailscale_device` | One device's name, tags, approval, key expiry and address, or its removal | `GET /tailnet/{tailnet}/devices`, `POST`/`DELETE /device/{deviceId}/...` |
| `tailscale_device_info` | Every device the tailnet holds | `GET /tailnet/{tailnet}/devices` |
| `tailscale_device_routes` | The subnet routes an admin has enabled for one device | `GET`/`POST /device/{deviceId}/routes` |
| `tailscale_auth_key` | Auth keys, OAuth clients and federated identities | `GET`/`POST /tailnet/{tailnet}/keys`, `GET`/`PUT`/`DELETE /tailnet/{tailnet}/keys/{keyId}` |
| `tailscale_user` | The role, suspension, approval and membership of a user | `GET /tailnet/{tailnet}/users`, `POST /users/{userId}/...` |
| `tailscale_logs` | The audit log, or the network flow log, over a window the task gives | `GET /tailnet/{tailnet}/logging/configuration`, `.../logging/network` |
| `tailscale_log_streaming` | The destination logs are published to, and its publishing status | `GET`/`PUT`/`DELETE /tailnet/{tailnet}/logging/{logType}/stream` |
| `tailscale_contacts` | The address Tailscale writes to for each contact type | `GET /tailnet/{tailnet}/contacts`, `PATCH /tailnet/{tailnet}/contacts/{contactType}` |
| `tailscale_device_attributes` | One device's custom posture attributes | `GET /device/{deviceId}/attributes`, `PATCH /tailnet/{tailnet}/device-attributes` |
| `tailscale_aws_external_id` | The reusable external id this tailnet presents to AWS | `POST /tailnet/{tailnet}/aws-external-id`, `POST .../validate-aws-trust-policy` |
| `tailscale_webhook` | The events a tailnet posts to an endpoint URL, and the destination format | `GET`/`POST /tailnet/{tailnet}/webhooks`, `GET`/`PATCH`/`DELETE /webhooks/{endpointId}` |

Two lookups are not modules and are not in that table: `abn.tailscale.device` and
`abn.tailscale.service` resolve one device or Service and return a property, for a
template that needs a value rather than a list. The
[usage](docs/usage.md) page has both.

The shapes behave differently, and the difference is the API's. The policy
file and the DNS configuration are replaced whole, so a module that was not told
about a field has to send the value the tailnet already holds rather than a
default. `tailscale_settings` merges, so an option the task left out is absent
from the request and the server leaves it alone. A device has one endpoint per
property, so each option is its own request and an option left out is never sent.
Either way only the options the task set are compared, so a second run over
unchanged input reports no change.

A device cannot be created: one appears when something authenticates to the
tailnet. `tailscale_device` therefore selects a device the tailnet already holds,
by ID, by name, by Tailscale IP or by tag, and refuses a selector that matches
none or several rather than guessing which one the task meant.

A key's secret is returned by the API exactly once, in the response that creates
it, so `tailscale_auth_key` can only hand it over on the run that minted the
credential. A second run over the same task reports no secret at all.

`tailscale_user` is not a document at all. A user appears when somebody
authenticates or is invited, so the module finds the user first and then
reconciles the properties the API lets it change, refusing a selector that
matches nobody or more than one.

`tailscale_dns` has no separate module per DNS feature. The API offers both the
one-document endpoint and four legacy per-feature endpoints, and the legacy set
cannot express `use_with_exit_node` on a resolver. See
[adr/0004](docs/adr/0004-atomic-dns-configuration.md).

## Safety model

The policy file is the resource with real blast radius, so the collection is
built around it.

- Writes are guarded. The module reads the current policy, keeps the `ETag` the
  read returned, and writes with `If-Match`. A console edit between the read and
  the write is refused with a 412 instead of being overwritten. A read that
  returned no `ETag` aborts the write, because a retry cannot help.
- A policy that opens the tailnet is refused. A document with neither an `acls`
  nor a `grants` key means allow-all to Tailscale, and an absent key is easy to
  write by accident. Set `allow_all_traffic: true` to say that is what you meant.
  An empty `acls` list denies everything and needs no confirmation.
- A change is offered to the server's validator before the write, and the write
  itself is refused for a policy that does not parse or whose own tests fail. The
  validator runs the `tests` your document declares, not an independent judgement
  about reachability, so a document that denies the operator applying it access can
  still be accepted if its tests pass. That is the case to cover with a `tests`
  block, and `docs/safety-model.md` says how.
- Only reads are retried. A write that answers 5xx, or a connection that drops,
  may already have been applied, so a second attempt would turn a visible failure
  into a divergence. A rate-limited read is retried once.

None of that protects you from a credential that is too powerful, a policy that is
wrong in a way the server accepts, or an operator editing the console at the same
time as a DNS or settings write: the policy file is the only resource this
collection guards, because it is the only one the API offers concurrency control
for. The full account, including what a check run does not tell you, is in
[docs/safety-model.md](docs/safety-model.md), and
[docs/troubleshooting.md](docs/troubleshooting.md) is keyed to the message the API
returned.

## When not to use this

- **Node-side work.** Installing `tailscaled`, running `tailscale up`, configuring
  Serve or Funnel. The modules reach the Admin API and nothing else.
- **Invites.** Tailscale permits them only to user-owned keys, because an invite
  needs an inviting user, so an OAuth-derived token cannot create one.
- **Anything needing third-party Python.** Modules run where dependencies cannot
  be installed, so the collection carries none and never will.

## Versioning

Semantic versioning, `MAJOR.MINOR.PATCH`.

- **MAJOR**: incompatible change. Only major releases remove things.
- **MINOR**: new functionality, backwards compatible. Additions and deprecations.
- **PATCH**: backwards compatible fixes. No features, no deprecations.

Every Ansible minor series keeps the collection's major version constant.
Dropping Python support is a breaking change.

## Contributing

See [docs/contribution/README.md](docs/contribution/README.md). Development setup
is `make init`, then `make check`.

## Licensing

GNU General Public License v3.0 or later. Code under `plugins/module_utils/` is
BSD-2-Clause so it can be reused by projects under incompatible licences, which
is why ansible-core relicenses its own `module_utils` the same way. Per-file
licensing follows REUSE; see [LICENSE](LICENSE).

`tests/fixtures/openapi/tailscale.yaml` is Tailscale's published description of
its own API, redistributed unmodified under BSD-3-Clause.
