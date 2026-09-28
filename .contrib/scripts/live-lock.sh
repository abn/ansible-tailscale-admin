#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Hold a machine-level lock across a live run, then run the given command.
#
# Development tooling and nothing else. It serialises live runs on this machine;
# it cannot protect a run anywhere else, because it is not present there. Neither
# `make check` nor the unit suite takes it, and neither touches a tailnet.
#
# The path is machine-level rather than inside a worktree: each worktree is a
# separate checkout, so a lock under one would be invisible to the others.
# TS_LIVE_LOCK overrides the path, which is how the harness test exercises this
# without contending with the run that already holds the real lock.

set -eu -o pipefail

lock="${TS_LIVE_LOCK:-${TMPDIR:-/tmp}/ansible-tailscale/live.lock}"
mkdir -p "$(dirname "$lock")"

# Opened read-write without truncating: a contender has to read the holder before
# `flock` reports the collision, and `>` would erase that entry first.
exec 9<>"$lock"

if ! flock -n 9; then
	holder_pid="$(sed -n 1p "$lock" 2>/dev/null || true)"
	holder_since="$(sed -n 2p "$lock" 2>/dev/null || true)"
	printf '\n  a live run already holds the machine lock: %s\n' "$lock"
	if [ -n "$holder_pid" ]; then
		printf '  held by pid %s since %s\n' "$holder_pid" "${holder_since:-unknown}"
	else
		printf '  held by another process\n'
	fi
	printf '  This lock is development tooling. It serialises live runs on this\n'
	printf '  machine and protects a run from nothing else. Not waiting; rerun\n'
	printf '  when the holder exits.\n\n'
	exit 1
fi

# Written only after the lock is held, so a refused contender cannot overwrite
# the entry it is about to report.
printf '%s\n%s\n' "$$" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$lock"

exec "$@"
