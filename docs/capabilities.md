---
type: Reference
title: What the collection manages
description: Every Tailscale API endpoint, whether a module calls it, and
  the reason for each one that none does.
status: stable
tags:
  - tailscale
  - api
  - coverage
---

# What the collection manages

55 of the 93 endpoints in the API description are used by the
collection. The other 38 are listed here with the reason each is left.

Generated from the operation table and the coverage classification by
`.contrib/scripts/render-capabilities.py`. `make check` regenerates it and fails if this
page and the code disagree.

## By area

| Area | Called | Not called |
|---|---|---|
| policy | 3 | 1 |
| dns | 2 | 9 |
| settings | 2 | 0 |
| devices | 11 | 0 |
| device attributes | 4 | 0 |
| services | 7 | 0 |
| keys | 5 | 0 |
| users | 6 | 1 |
| logs | 6 | 0 |
| contacts | 2 | 1 |
| aws external id | 2 | 0 |
| webhooks | 5 | 2 |
| oauth applications | 0 | 5 |
| posture integrations | 0 | 5 |
| invites | 0 | 11 |
| organizations | 0 | 2 |
| tailnet | 0 | 1 |

## What is called

### policy

| Operation | Endpoint |
|---|---|
| `policy_get` | `GET /tailnet/{tailnet}/acl` |
| `policy_set` | `POST /tailnet/{tailnet}/acl` |
| `policy_validate` | `POST /tailnet/{tailnet}/acl/validate` |

### dns

| Operation | Endpoint |
|---|---|
| `dns_configuration_get` | `GET /tailnet/{tailnet}/dns/configuration` |
| `dns_configuration_set` | `POST /tailnet/{tailnet}/dns/configuration` |

### settings

| Operation | Endpoint |
|---|---|
| `tailnet_settings_get` | `GET /tailnet/{tailnet}/settings` |
| `tailnet_settings_update` | `PATCH /tailnet/{tailnet}/settings` |

### devices

| Operation | Endpoint |
|---|---|
| `device_delete` | `DELETE /device/{deviceId}` |
| `device_get` | `GET /device/{deviceId}` |
| `device_authorize` | `POST /device/{deviceId}/authorized` |
| `device_expire_key` | `POST /device/{deviceId}/expire` |
| `device_set_ip` | `POST /device/{deviceId}/ip` |
| `device_set_key_expiry` | `POST /device/{deviceId}/key` |
| `device_rename` | `POST /device/{deviceId}/name` |
| `device_routes_get` | `GET /device/{deviceId}/routes` |
| `device_routes_set` | `POST /device/{deviceId}/routes` |
| `device_set_tags` | `POST /device/{deviceId}/tags` |
| `device_list` | `GET /tailnet/{tailnet}/devices` |

### device attributes

| Operation | Endpoint |
|---|---|
| `device_attributes_get` | `GET /device/{deviceId}/attributes` |
| `device_attribute_delete` | `DELETE /device/{deviceId}/attributes/{attributeKey}` |
| `device_attribute_set` | `POST /device/{deviceId}/attributes/{attributeKey}` |
| `device_attributes_batch_set` | `PATCH /tailnet/{tailnet}/device-attributes` |

### services

| Operation | Endpoint |
|---|---|
| `service_list` | `GET /tailnet/{tailnet}/services` |
| `service_delete` | `DELETE /tailnet/{tailnet}/services/{serviceName}` |
| `service_get` | `GET /tailnet/{tailnet}/services/{serviceName}` |
| `service_set` | `PUT /tailnet/{tailnet}/services/{serviceName}` |
| `service_approval_get` | `GET /tailnet/{tailnet}/services/{serviceName}/device/{deviceId}/approved` |
| `service_approval_set` | `POST /tailnet/{tailnet}/services/{serviceName}/device/{deviceId}/approved` |
| `service_hosts_list` | `GET /tailnet/{tailnet}/services/{serviceName}/devices` |

### keys

| Operation | Endpoint |
|---|---|
| `keys_list` | `GET /tailnet/{tailnet}/keys` |
| `keys_create` | `POST /tailnet/{tailnet}/keys` |
| `keys_delete` | `DELETE /tailnet/{tailnet}/keys/{keyId}` |
| `keys_get` | `GET /tailnet/{tailnet}/keys/{keyId}` |
| `keys_set` | `PUT /tailnet/{tailnet}/keys/{keyId}` |

### users

| Operation | Endpoint |
|---|---|
| `users_list` | `GET /tailnet/{tailnet}/users` |
| `user_approve` | `POST /users/{userId}/approve` |
| `user_delete` | `POST /users/{userId}/delete` |
| `user_restore` | `POST /users/{userId}/restore` |
| `user_set_role` | `POST /users/{userId}/role` |
| `user_suspend` | `POST /users/{userId}/suspend` |

### logs

| Operation | Endpoint |
|---|---|
| `logging_configuration_get` | `GET /tailnet/{tailnet}/logging/configuration` |
| `logging_network_get` | `GET /tailnet/{tailnet}/logging/network` |
| `logging_stream_delete` | `DELETE /tailnet/{tailnet}/logging/{logType}/stream` |
| `logging_stream_get` | `GET /tailnet/{tailnet}/logging/{logType}/stream` |
| `logging_stream_set` | `PUT /tailnet/{tailnet}/logging/{logType}/stream` |
| `logging_stream_status_get` | `GET /tailnet/{tailnet}/logging/{logType}/stream/status` |

### contacts

| Operation | Endpoint |
|---|---|
| `contacts_get` | `GET /tailnet/{tailnet}/contacts` |
| `contact_update` | `PATCH /tailnet/{tailnet}/contacts/{contactType}` |

### aws external id

| Operation | Endpoint |
|---|---|
| `aws_external_id_get` | `POST /tailnet/{tailnet}/aws-external-id` |
| `aws_external_id_validate` | `POST /tailnet/{tailnet}/aws-external-id/{id}/validate-aws-trust-policy` |

### webhooks

| Operation | Endpoint |
|---|---|
| `webhook_list` | `GET /tailnet/{tailnet}/webhooks` |
| `webhook_create` | `POST /tailnet/{tailnet}/webhooks` |
| `webhook_delete` | `DELETE /webhooks/{endpointId}` |
| `webhook_get` | `GET /webhooks/{endpointId}` |
| `webhook_update` | `PATCH /webhooks/{endpointId}` |

## What is not called

### replaced

Superseded by an endpoint this collection does use, and the replacement can express something the older one cannot.

### no-scope

No OAuth scope documents it, so a scoped credential cannot be granted it.

### unimplemented

Reachable and with a scope, and no module exposes it yet.

### unverifiable

Reachable, and nothing can be created without an account or a plan the test tailnet does not have, so the write path could not be verified against the API.

### out-of-scope

Acts above or outside a single tailnet, which is the unit this collection manages.

### second-way

A second way to do what a module already does. The collection uses one way, so this one is not exposed and is not needed to reconcile anything.

### action

Side-effecting and with no observable end state, so no task could reach `changed: 0` on a second run. A module that called it would report a change for ever, which the collection's first invariant forbids.

**policy**

| Endpoint | Why |
|---|---|
| `POST /tailnet/{tailnet}/acl/preview` | Preview the ACLs a policy document would produce. (`unimplemented`) |

**dns**

| Endpoint | Why |
|---|---|
| `GET /tailnet/{tailnet}/dns/nameservers` | Read the nameservers alone. (`replaced`) |
| `GET /tailnet/{tailnet}/dns/preferences` | Read the MagicDNS and override preferences alone. (`replaced`) |
| `GET /tailnet/{tailnet}/dns/searchpaths` | Read the search paths alone. (`replaced`) |
| `GET /tailnet/{tailnet}/dns/split-dns` | Read the split DNS mappings alone. (`replaced`) |
| `PATCH /tailnet/{tailnet}/dns/split-dns` | Merge into the split DNS mappings alone. (`replaced`) |
| `POST /tailnet/{tailnet}/dns/nameservers` | Write the nameservers alone. (`replaced`) |
| `POST /tailnet/{tailnet}/dns/preferences` | Write the MagicDNS and override preferences alone. (`replaced`) |
| `POST /tailnet/{tailnet}/dns/searchpaths` | Write the search paths alone. (`replaced`) |
| `PUT /tailnet/{tailnet}/dns/split-dns` | Replace the split DNS mappings alone. (`replaced`) |

**users**

| Endpoint | Why |
|---|---|
| `GET /users/{userId}` | Read one user, which `tailscale_user` reads from the list. (`second-way`) |

**contacts**

| Endpoint | Why |
|---|---|
| `POST /tailnet/{tailnet}/contacts/{contactType}/resend-verification-email` | Send a verification email for a contact address. (`action`) |

**webhooks**

| Endpoint | Why |
|---|---|
| `POST /webhooks/{endpointId}/rotate` | Issue a new secret for one webhook endpoint. (`action`) |
| `POST /webhooks/{endpointId}/test` | Send a test event to one webhook endpoint. (`action`) |

**oauth applications**

| Endpoint | Why |
|---|---|
| `DELETE /tailnet/{tailnet}/oauth-apps/{appId}` | Remove one OAuth application. (`unimplemented`) |
| `GET /tailnet/{tailnet}/oauth-apps` | List the OAuth applications. (`unimplemented`) |
| `GET /tailnet/{tailnet}/oauth-apps/{appId}` | Read one OAuth application. (`unimplemented`) |
| `POST /tailnet/{tailnet}/oauth-apps` | Create an OAuth application. (`unimplemented`) |
| `PUT /tailnet/{tailnet}/oauth-apps/{appId}` | Update one OAuth application. (`unimplemented`) |

**posture integrations**

| Endpoint | Why |
|---|---|
| `DELETE /posture/integrations/{id}` | Remove one posture integration. (`unverifiable`) |
| `GET /posture/integrations/{id}` | Read one posture integration. (`unverifiable`) |
| `GET /tailnet/{tailnet}/posture/integrations` | List the posture integrations. (`unverifiable`) |
| `PATCH /posture/integrations/{id}` | Update one posture integration. (`unverifiable`) |
| `POST /tailnet/{tailnet}/posture/integrations` | Create a posture integration. (`unverifiable`) |

**invites**

| Endpoint | Why |
|---|---|
| `DELETE /device-invites/{deviceInviteId}` | Remove one device invite. (`no-scope`) |
| `DELETE /user-invites/{userInviteId}` | Remove one user invite. (`no-scope`) |
| `GET /device-invites/{deviceInviteId}` | Read one device invite. (`no-scope`) |
| `GET /device/{deviceId}/device-invites` | Read the invites for a device. (`no-scope`) |
| `GET /tailnet/{tailnet}/user-invites` | Read the user invites for a tailnet. (`no-scope`) |
| `GET /user-invites/{userInviteId}` | Read one user invite. (`no-scope`) |
| `POST /device-invites/-/accept` | Accept a device invite. (`no-scope`) |
| `POST /device-invites/{deviceInviteId}/resend` | Resend a device invite. (`no-scope`) |
| `POST /device/{deviceId}/device-invites` | Create an invite for a device. (`no-scope`) |
| `POST /tailnet/{tailnet}/user-invites` | Create a user invite. (`no-scope`) |
| `POST /user-invites/{userInviteId}/resend` | Resend a user invite. (`no-scope`) |

**organizations**

| Endpoint | Why |
|---|---|
| `GET /organizations/{organization}/tailnets` | List the tailnets of an organization. (`out-of-scope`) |
| `POST /organizations/{organization}/tailnets` | Create a tailnet in an organization. (`out-of-scope`) |

**tailnet**

| Endpoint | Why |
|---|---|
| `DELETE /tailnet/{tailnet}` | Delete a whole tailnet. (`out-of-scope`) |
