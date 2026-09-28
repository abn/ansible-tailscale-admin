#!/usr/bin/env bash
# Fetch the upstream Tailscale OpenAPI description and report whether the vendored
# copy moved. Tailscale states the spec is unstable and may change without notice.
#
# Usage: spec-drift.sh <vendored-spec> <spec-url> <scratch-dir>
set -euo pipefail

spec="$1"
url="$2"
scratch="$3"

mkdir -p "$scratch"
printf '\n  fetching %s\n' "$url"
curl -fsSL --max-time 60 "$url" -o "$scratch/tailscale-openapi.yaml"

if diff -q "$scratch/tailscale-openapi.yaml" "$spec" >/dev/null; then
    printf '  no drift\n\n'
    exit 0
fi

printf '\n  DRIFT DETECTED. The upstream spec changed. Review the diff, then:\n'
printf '    cp %s %s\n\n' "$scratch/tailscale-openapi.yaml" "$spec"
diff -u "$spec" "$scratch/tailscale-openapi.yaml" | head -200
exit 1
