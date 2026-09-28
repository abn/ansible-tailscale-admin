# SPDX-License-Identifier: BSD-2-Clause
"""Which Tailscale API endpoints this collection calls, and which it does not.

``_spec.py`` holds the operations the collection uses. This holds the other half:
every endpoint in the vendored description that no module calls, with the reason.
A test asserts the two together name exactly the endpoints the description has, so
neither can drift without the other failing.

The page a user reads is generated from this, not written beside it. A hand-written
list of what is covered is wrong the first time a module is added, and nothing
catches it, which is how the project's own overview came to claim the operation
table covered webhooks when it did not.
"""

from __future__ import annotations

from typing import NamedTuple

#: Why an endpoint is not called. Each is a reason a reader can act on or accept.
REPLACED = "replaced"
NO_SCOPE = "no-scope"
UNIMPLEMENTED = "unimplemented"
UNVERIFIABLE = "unverifiable"
OUT_OF_SCOPE = "out-of-scope"
DUPLICATE = "second-way"
ACTION = "action"

#: One line per category, for the generated page.
CATEGORIES: dict[str, str] = {
    REPLACED: (
        "Superseded by an endpoint this collection does use, and the replacement can "
        "express something the older one cannot."
    ),
    NO_SCOPE: ("No OAuth scope documents it, so a scoped credential cannot be granted it."),
    UNIMPLEMENTED: ("Reachable and with a scope, and no module exposes it yet."),
    UNVERIFIABLE: (
        "Reachable, and nothing can be created without an account or a plan the test "
        "tailnet does not have, so the write path could not be verified against the API."
    ),
    OUT_OF_SCOPE: (
        "Acts above or outside a single tailnet, which is the unit this collection manages."
    ),
    DUPLICATE: (
        "A second way to do what a module already does. The collection uses one way, so "
        "this one is not exposed and is not needed to reconcile anything."
    ),
    ACTION: (
        "Side-effecting and with no observable end state, so no task could reach "
        "`changed: 0` on a second run. A module that called it would report a change "
        "for ever, which the collection's first invariant forbids."
    ),
}


class Exclusion(NamedTuple):
    """An endpoint the collection does not call, and why."""

    category: str
    note: str


#: The endpoints in the vendored description that ``_spec.py`` does not hold, keyed
#: by verb and the description's own path template.
EXCLUDED: dict[tuple[str, str], Exclusion] = {
    # A second way to check a policy. The module runs the document's own access
    # tests through `acl/validate`, which is what a task wants to know before the
    # write; preview reports the ACLs a policy would produce, which nothing here
    # needs.
    ("POST", "/tailnet/{tailnet}/acl/preview"): Exclusion(
        UNIMPLEMENTED, "Preview the ACLs a policy document would produce."
    ),
    # It sends an email and changes nothing the API reports, so a task using it
    # could never report no change.
    (
        "POST",
        "/tailnet/{tailnet}/contacts/{contactType}/resend-verification-email",
    ): Exclusion(ACTION, "Send a verification email for a contact address."),
    # Invites. Tailscale permits them only to user-owned keys, because an invite
    # needs an inviting user, and an invited user does not appear in the user list
    # until it accepts. Eight of the eleven carry no scope at all.
    ("GET", "/device/{deviceId}/device-invites"): Exclusion(
        NO_SCOPE, "Read the invites for a device."
    ),
    ("POST", "/device/{deviceId}/device-invites"): Exclusion(
        NO_SCOPE, "Create an invite for a device."
    ),
    ("GET", "/device-invites/{deviceInviteId}"): Exclusion(NO_SCOPE, "Read one device invite."),
    ("DELETE", "/device-invites/{deviceInviteId}"): Exclusion(
        NO_SCOPE, "Remove one device invite."
    ),
    ("POST", "/device-invites/{deviceInviteId}/resend"): Exclusion(
        NO_SCOPE, "Resend a device invite."
    ),
    ("POST", "/device-invites/-/accept"): Exclusion(NO_SCOPE, "Accept a device invite."),
    ("GET", "/tailnet/{tailnet}/user-invites"): Exclusion(
        NO_SCOPE, "Read the user invites for a tailnet."
    ),
    ("POST", "/tailnet/{tailnet}/user-invites"): Exclusion(NO_SCOPE, "Create a user invite."),
    ("GET", "/user-invites/{userInviteId}"): Exclusion(NO_SCOPE, "Read one user invite."),
    ("DELETE", "/user-invites/{userInviteId}"): Exclusion(NO_SCOPE, "Remove one user invite."),
    ("POST", "/user-invites/{userInviteId}/resend"): Exclusion(NO_SCOPE, "Resend a user invite."),
    # The legacy DNS endpoints. `dns/configuration` replaces all of them and is the
    # only one that can express a resolver's `useWithExitNode`. ADR 0004.
    ("GET", "/tailnet/{tailnet}/dns/nameservers"): Exclusion(
        REPLACED, "Read the nameservers alone."
    ),
    ("POST", "/tailnet/{tailnet}/dns/nameservers"): Exclusion(
        REPLACED, "Write the nameservers alone."
    ),
    ("GET", "/tailnet/{tailnet}/dns/preferences"): Exclusion(
        REPLACED, "Read the MagicDNS and override preferences alone."
    ),
    ("POST", "/tailnet/{tailnet}/dns/preferences"): Exclusion(
        REPLACED, "Write the MagicDNS and override preferences alone."
    ),
    ("GET", "/tailnet/{tailnet}/dns/searchpaths"): Exclusion(
        REPLACED, "Read the search paths alone."
    ),
    ("POST", "/tailnet/{tailnet}/dns/searchpaths"): Exclusion(
        REPLACED, "Write the search paths alone."
    ),
    ("GET", "/tailnet/{tailnet}/dns/split-dns"): Exclusion(
        REPLACED, "Read the split DNS mappings alone."
    ),
    ("PATCH", "/tailnet/{tailnet}/dns/split-dns"): Exclusion(
        REPLACED, "Merge into the split DNS mappings alone."
    ),
    ("PUT", "/tailnet/{tailnet}/dns/split-dns"): Exclusion(
        REPLACED, "Replace the split DNS mappings alone."
    ),
    # Webhooks. `tailscale_webhook` reconciles the five that hold a document. The
    # remaining two are actions rather than state: `test` queues a real event and
    # `rotate` issues a secret returned once, so neither leaves anything a later
    # read can compare against and neither can reach `changed: 0`.
    ("POST", "/webhooks/{endpointId}/test"): Exclusion(
        ACTION, "Send a test event to one webhook endpoint."
    ),
    ("POST", "/webhooks/{endpointId}/rotate"): Exclusion(
        ACTION, "Issue a new secret for one webhook endpoint."
    ),
    # OAuth applications. Distinct from the trust credentials `tailscale_auth_key`
    # manages: an OAuth app carries redirect URIs and is for third-party sign-in,
    # while a trust credential is a client-credentials grant. Measured reachable.
    ("GET", "/tailnet/{tailnet}/oauth-apps"): Exclusion(
        UNIMPLEMENTED, "List the OAuth applications."
    ),
    ("POST", "/tailnet/{tailnet}/oauth-apps"): Exclusion(
        UNIMPLEMENTED, "Create an OAuth application."
    ),
    ("GET", "/tailnet/{tailnet}/oauth-apps/{appId}"): Exclusion(
        UNIMPLEMENTED, "Read one OAuth application."
    ),
    ("PUT", "/tailnet/{tailnet}/oauth-apps/{appId}"): Exclusion(
        UNIMPLEMENTED, "Update one OAuth application."
    ),
    ("DELETE", "/tailnet/{tailnet}/oauth-apps/{appId}"): Exclusion(
        UNIMPLEMENTED, "Remove one OAuth application."
    ),
    # A single-user read, which the user module does by reading the list it needs
    # anyway and selecting from it. A second way to reach a user the collection
    # already reaches.
    ("GET", "/users/{userId}"): Exclusion(
        DUPLICATE, "Read one user, which `tailscale_user` reads from the list."
    ),
    # Posture integrations. The description's update is a PATCH, and nothing can be
    # created to patch: the server validates a provider's credentials against the
    # vendor, and every provider refused a fabricated set.
    ("GET", "/tailnet/{tailnet}/posture/integrations"): Exclusion(
        UNVERIFIABLE, "List the posture integrations."
    ),
    ("POST", "/tailnet/{tailnet}/posture/integrations"): Exclusion(
        UNVERIFIABLE, "Create a posture integration."
    ),
    ("GET", "/posture/integrations/{id}"): Exclusion(UNVERIFIABLE, "Read one posture integration."),
    ("PATCH", "/posture/integrations/{id}"): Exclusion(
        UNVERIFIABLE, "Update one posture integration."
    ),
    ("DELETE", "/posture/integrations/{id}"): Exclusion(
        UNVERIFIABLE, "Remove one posture integration."
    ),
    # Above or outside one tailnet.
    ("GET", "/organizations/{organization}/tailnets"): Exclusion(
        OUT_OF_SCOPE, "List the tailnets of an organization."
    ),
    ("POST", "/organizations/{organization}/tailnets"): Exclusion(
        OUT_OF_SCOPE, "Create a tailnet in an organization."
    ),
    ("DELETE", "/tailnet/{tailnet}"): Exclusion(OUT_OF_SCOPE, "Delete a whole tailnet."),
}
