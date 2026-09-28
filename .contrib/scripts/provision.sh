#!/usr/bin/env bash
# Provisioning and diagnostics for the throwaway tailnet the live suites run
# against. Owner-run and once-per-credential, and the only code here that touches
# a personal API token.
#
# The test OAuth secret is not a bearer token: it is exchanged at the OAuth token
# endpoint, which the vendored schema does not describe. Each subcommand refuses
# without the live acknowledgement, because a credential merely being present must
# not be enough to reach a real tailnet.
#
# Usage: provision.sh <tailnet|probe|client> <scratch-dir>
#   tailnet   record the tailnet ID, for playbooks managing more than one
#   probe     exchange the OAuth secret and report what the token reaches
#   client    mint the test OAuth client, or re-scope the existing one
#
# Environment: TS_API_BASE, LIVE_ACK, TS_KEY_FILE, TS_OAUTH, TS_TAILNET_FILE,
# OAUTH_CLIENT_NAME, OAUTH_SCOPES, TS_TAILNET.
set -euo pipefail

api_base="${TS_API_BASE:?}"
ack="${LIVE_ACK:?}"
key_file="${TS_KEY_FILE:?}"
oauth_file="${TS_OAUTH:?}"
tailnet_file="${TS_TAILNET_FILE:?}"
client_name="${OAUTH_CLIENT_NAME:?}"
scopes="${OAUTH_SCOPES:?}"
tailnet="${TS_TAILNET:--}"
scratch="${2:?}"

require_ack() {
    if [ "${TS_LIVE_SMOKE:-}" != "$ack" ]; then
        printf '\n  refused. Set TS_LIVE_SMOKE=%s to proceed,\n' "$ack"
        printf '  and only against a tailnet you are willing to discard.\n\n'
        exit 1
    fi
}

owner_token() {
    if [ -z "${TS_API_TOKEN:-}" ] && [ -r "$key_file" ]; then
        TS_API_TOKEN=$(cat "$key_file")
        export TS_API_TOKEN
    fi
    [ -n "${TS_API_TOKEN:-}" ] || {
        printf '\n  provisioning needs the owner API token. Set TS_API_TOKEN, or \n'
        printf '  place one at %s\n\n' "$key_file"
        exit 1
    }
}

cmd_tailnet() {
    umask 077
    require_ack
    owner_token
    curl -sS --max-time 30 -o "$scratch/users.json" -w 'HTTP %{http_code}\n' \
        -H "Authorization: Bearer $TS_API_TOKEN" -H 'Accept: application/json' \
        "$api_base/tailnet/-/users"
    jq -er '.users[0].tailnetId' "$scratch/users.json" > "$tailnet_file" &&
        chmod 600 "$tailnet_file" &&
        printf '  tailnet ID recorded to %s, not echoed\n\n' "$tailnet_file" ||
        printf '  no tailnet ID in the response\n\n'
}

cmd_probe() {
    umask 077
    require_ack
    [ -r "$oauth_file" ] || { printf '\n  no OAuth client yet. Run: provision.sh client\n\n'; exit 1; }
    local cid sec code tok ep c token_json
    cid=$(sed -n 1p "$oauth_file")
    sec=$(sed -n 2p "$oauth_file")
    token_json="$scratch/token.json"
    code=$(curl -sS --max-time 30 -o "$token_json" -w '%{http_code}' \
        -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode "client_id=$cid" --data-urlencode "client_secret=$sec" \
        --data-urlencode 'grant_type=client_credentials' \
        "$api_base/oauth/token")
    if [ "$code" != 200 ]; then
        printf '  token endpoint -> HTTP %s: ' "$code"
        jq -r '.message // .error // "no message"' "$token_json"
        exit 1
    fi
    jq -r '"  granted    : \(.scope)\n  expires in : \(.expires_in)s"' "$token_json"
    tok=$(jq -r .access_token "$token_json")
    for ep in acl dns/configuration users devices; do
        c=$(curl -sS --max-time 30 -o /dev/null -w '%{http_code}' \
            -H "Authorization: Bearer $tok" -H 'Accept: application/json' \
            "$api_base/tailnet/$tailnet/$ep")
        printf '  %-18s HTTP %s\n' "$ep" "$c"
    done
    printf '\n'
}

cmd_client() {
    umask 077
    require_ack
    owner_token
    local body method path client_json
    client_json="$scratch/client.json"
    body=$(jq -nc --arg n "$client_name" --arg s "$scopes" \
        '{keyType: "client", description: $n, scopes: ($s | split(" "))}')
    if [ -r "$oauth_file" ]; then
        method=PUT
        path="keys/$(sed -n 1p "$oauth_file")"
    else
        method=POST
        path=keys
    fi
    printf '  %s scopes: %s\n' "$method" "$scopes"
    curl -sS --max-time 30 -o "$client_json" -w '  HTTP %{http_code}\n' \
        -X "$method" -H "Authorization: Bearer $TS_API_TOKEN" \
        -H 'Content-Type: application/json' -H 'Accept: application/json' \
        --data "$body" "$api_base/tailnet/-/$path"
    if [ "$method" = POST ] && jq -e '.key' "$client_json" >/dev/null 2>&1; then
        jq -r '.id, .key' "$client_json" > "$oauth_file"
        chmod 600 "$oauth_file"
        printf '  id and secret to %s, not echoed\n\n' "$oauth_file"
    elif [ "$method" = PUT ]; then
        jq -r '"  granted: \(.scopes // "unchanged")"' "$client_json"
    else
        printf '  refused: '
        jq -r '.message // "no message"' "$client_json"
    fi
}

case "${1:-}" in
    tailnet) cmd_tailnet ;;
    probe) cmd_probe ;;
    client) cmd_client ;;
    *) printf 'usage: %s <tailnet|probe|client>\n' "$(basename "$0")" >&2; exit 2 ;;
esac
