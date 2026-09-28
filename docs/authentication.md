---
type: Guide
title: Authentication
description: The two credentials, how a token reaches the API, and the OAuth scopes each module
  needs.
status: draft
tags:
  - authentication
  - oauth
  - scopes
---

# Authentication

Every Tailscale API call is authenticated, so every task needs a credential. The
collection accepts two, and they are not interchangeable.

## The two credentials

An **API access token** (`tskey-api-` prefix) is its own bearer: it is sent as
written and nothing else happens. Create one in the admin console under Settings,
then Keys. It expires within 90 days, and it carries the full permissions of the
user who created it. There is no way to narrow one, so an API access token is the
user's own credentials with a shorter life, and a compromise of it is a compromise
of that user.

An **OAuth client** is created under Settings, then Trust credentials. The client
secret carries the `tskey-client-` prefix. The collection exchanges the secret for
an access token, and it is that token, never the secret, that authenticates a
call. The exchange happens on the first request of a task and the token is reused
for every request after it, so a task costs one exchange rather than one per call.

An OAuth client belongs to the tailnet rather than to a person, it is named and
revocable in one place, and the tokens it mints stop working on their own. For
automation it is the better credential, and the reason is ownership and lifetime
rather than least privilege, because the collection asks the token endpoint for no
scope at all: the client is created with the scopes it may grant and narrowing
them is a console action.

The modules do not read the environment. A task with no credential fails on the
spot and says which option is missing, rather than after a request it had no
business making. A token that is only whitespace counts as absent, because that
is what an undefined template variable looks like.

## Choosing a tailnet

`tailnet` defaults to `-`, Tailscale's shorthand for the default tailnet of the
credential in use. Use it unless one playbook manages more than one tailnet, since
it keeps working when the credential is moved to another tailnet. Otherwise give
the tailnet ID, including its leading dash, as `"-1234567890123"`.

## Scopes

Tailscale authorises OAuth clients by scope, and the mapping from module to scope
is not obvious. This is a snapshot, not a contract: Tailscale extends an existing
scope when it adds an API to it, so re-check the client's scopes in the console
rather than treating this table as fixed.

| Module | Request | Scopes |
|---|---|---|
| `tailscale_policy` | Read the policy | `policy_file:read` |
| `tailscale_policy` | Validate the proposal | `policy_file:read` |
| `tailscale_policy` | Write the policy | `policy_file` |
| `tailscale_dns` | Read the configuration | `dns:read` |
| `tailscale_dns` | Write the configuration | `dns` |
| `tailscale_device`, `tailscale_device_routes`, `tailscale_device_info` | Read a device, or the device list | `devices:core:read` |
| `tailscale_device` | Rename, tag, approve, change the key expiry or the address, expire a key, delete a device | `devices:core` |
| `tailscale_device_routes` | Read a device's routes | `devices:routes:read` |
| `tailscale_device_routes` | Enable a device's routes | `devices:routes` |
| `tailscale_settings` | Read the settings | `feature_settings:read`, `logs:network:read`, `networking_settings:read`, `policy_file:read` |
| `tailscale_settings` | Write the settings | `feature_settings`, `logs:network`, `networking_settings`, `policy_file` |
| `tailscale_service`, `tailscale_service_info` | Read a Service, or list them | `services:read` |
| `tailscale_service` | Create, update or remove a Service | `services` |
| `tailscale_service` | Read the devices hosting a Service | `services`, `devices:core` |
| `tailscale_service` | Approve or revoke a device as a host | `services`, `devices:core` |
| `tailscale_logs` | Read the configuration audit log | `logs:configuration:read` |
| `tailscale_logs` | Read the network flow log | `logs:network:read` |
| `tailscale_log_streaming` | Read the destination and its status | `log_streaming:read` |
| `tailscale_log_streaming` | Write or delete the destination | `log_streaming` |
| `tailscale_webhook` | Read the endpoints, or one endpoint | `webhooks:read` |
| `tailscale_webhook` | Create, update or remove an endpoint | `webhooks` |
| `tailscale_auth_key` | List credentials | `api_access_tokens:read`, `auth_keys:read`, `oauth_keys:read`, `federated_keys:read` |
| `tailscale_auth_key` | Read one credential | `api_access_tokens:read`, `auth_keys:read`, `oauth_keys:read`, `federated_keys:read` |
| `tailscale_auth_key` | Mint an auth key | `auth_keys` |
| `tailscale_auth_key` | Mint or update an OAuth client | `oauth_keys` |
| `tailscale_auth_key` | Mint or update a federated identity | `federated_keys` |
| `tailscale_auth_key` | Remove a credential | `api_access_tokens`, `auth_keys`, `oauth_keys`, `federated_keys` |

The keys endpoint authorises each kind of credential separately, so the scope a
`tailscale_auth_key` task needs follows its `key_type` rather than the module. A
task that mints an auth key needs `auth_keys` and nothing else.

A list is filtered by the credential making the call: a token derived from an
OAuth client sees the tailnet's auth keys, OAuth clients and federated
identities, while a user's API access token sees only the credentials that user
owns. A credential this module cannot see is one it cannot reconcile, so a task
managing a tailnet's keys wants a client rather than a personal token.
| `tailscale_user` | Read the users | `users:read` |
| `tailscale_user` | Change a user | `users` |
| `tailscale_contacts` | Read the contacts | `account_settings:read` |
| `tailscale_contacts` | Set a contact address | `account_settings` |
| `tailscale_device_attributes` | Read a device's attributes | `devices:posture_attributes:read` |
| `tailscale_device_attributes` | Set or delete a custom attribute | `devices:posture_attributes` |
| `tailscale_aws_external_id` | Read the external id, and validate a trust policy | `log_streaming` |

A policy run that changes something needs both `policy_file:read` and
`policy_file`, because it reads, validates and writes.

A `tailscale_service` run needs `services` even when it only reads, because the
two paths that name a device, the host list and the approval record, are gated
on it as well as on `devices:core`. A credential that can read a Service but not
write one still fails on the host list, which surprises until you have read the
table above.

`policy_file` and `policy_file:read` additionally require
`devices:posture_attributes:read` and `devices:core:read`. A policy can name a
device by its attributes, and Tailscale grants reading those attributes
separately. This is the most common reason a credential that looks correctly
scoped is still refused, and the refusal does not name the two extra scopes on its
own. The collection's own failure message does, because it knows them.

The tailnet settings endpoint is authorised per field rather than per operation, so
which scope a write needs depends on the option:

| Option | Scope in addition to `feature_settings` |
|---|---|
| `network_flow_logging_on` | `logs:network` |
| `https_enabled` | `networking_settings` |
| `acls_externally_managed_on` | `policy_file` |
| `acls_external_link` | `policy_file` |

The read is not per option. `tailscale_settings` compares against the document the
API returned, and a credential that can only see part of that document cannot tell
"unchanged" from "not visible to me", so give it all four read scopes. Reading
`policy_file:read` also drags in the two device scopes above, even for a task that
only sets `devices_approval_on`.

Streaming to a private endpoint additionally needs `device_invites` and
`policy_file`, because the endpoint is addressed from inside the tailnet and the
policy is what decides whether it can reach there.

Tailscale's own description of the API annotates no scope on the two DNS
endpoints. `dns` and `dns:read` come from the trust-credential documentation,
which lists them among the current scopes.

A scope is not the only thing that can refuse a request. Tailscale answers a plan
refusal on the log streaming endpoints and the network flow log read with a 403
and the message `feature not available on current billing plan`, which is the
status it uses for a missing scope. Widening the credential does not help that
one. See [troubleshooting](troubleshooting.md).
A device task needs `devices:core:read` as well as the write scope, because both
device modules read the device list to find the device a task named rather than
trusting the task to have named the right one. `tailscale_device_routes` reads its
own endpoint, which is gated on `devices:routes:read`.

## When a scope is refused

A 403 names the scope the operation needs and, where they apply, the scopes that
scope depends on. Granting a scope does not rescue a token that already exists:
scopes are fixed when a token is issued. Mint a new one from the client or trust
credential.

A personal API access token cannot be re-scoped either, because it has no scopes.
It carries its owner's permissions, so the only way to widen it is to raise that
user's role in the admin console.

A credential cannot change the user it belongs to, whichever of the two it is.
That is not a scope question: Tailscale refuses the change because the actor and
the target are the same user, and the `users` scope does not lift it. The refusal
is not consistent enough to recognise on sight, so `tailscale_user` reads the user
back after writing it and reports a change only when the tailnet holds it. See
[troubleshooting](troubleshooting.md).

## Keeping the secret out of the playbook

The credential options take ordinary Ansible expressions, so use whatever you
already use for secrets. With Ansible Vault:

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

`api_token` and `oauth_client_secret` are marked `no_log`, so Ansible redacts them
in task output. The client ID is not a secret and is not redacted.
