#!/usr/bin/env python
# SPDX-License-Identifier: GPL-3.0-or-later
"""A stand-in for the Tailscale Admin API, bound to loopback.

`base_url` is the one genuinely portable option in this collection, and pointing
it at a loopback server is what lets the module be driven end to end without a
credential, a tailnet or a network. Only the two policy endpoints and the DNS
and settings reads are served, and every response is a fixed fixture, so a run
here is as hermetic as a unit test.

The port is taken from the environment and the state file records whatever was
last written, so the caller can assert on convergence across two runs.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from typing import Any

STATE = os.environ["STUB_STATE"]
PORT = int(os.environ["STUB_PORT"])

DENY_ALL: dict = {"acls": []}
ONE_RULE: dict = {"acls": [{"action": "accept", "src": ["group:eng"], "dst": ["tag:web:443"]}]}
DNS_CURRENT: dict = {
    "nameservers": [{"address": "1.1.1.1", "useWithExitNode": False}],
    "preferences": {"magicDNS": False, "overrideLocalDNS": False},
}
SETTINGS_CURRENT: dict = {"devicesApprovalOn": False, "usersApprovalOn": False}

#: The one fingerprint the stub issues and the one it will accept back, so that a
#: policy write without `If-Match` is refused rather than silently accepted.
POLICY_ETAG = '"stub-etag"'


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        """Silence the default stderr logging."""

    def _send(self, status: int, body: object, *, etag: bool = False) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        if etag:
            self.send_header("ETag", POLICY_ETAG)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        # Every read comes back from the recorded state, not from a constant, or a
        # second run would see the pre-write document and could never converge.
        if self.path.endswith("/acl"):
            self._send(200, _read_state("policy", DENY_ALL), etag=True)
        elif self.path.endswith("/dns/configuration"):
            self._send(200, _read_state("dns", DNS_CURRENT), etag=True)
        elif self.path.endswith("/settings"):
            self._send(200, _read_state("settings", SETTINGS_CURRENT), etag=True)
        else:
            self._send(404, {"message": f"the stub serves no path {self.path}"})

    def do_POST(self) -> None:
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path.endswith("/acl/validate"):
            # A passing validation. The real endpoint reports a failure with a
            # 200 and a `data` array rather than a status, and the unit tests
            # cover that; here a pass is all a converging run needs.
            self._send(200, {"message": "ok"})
        elif self.path.endswith("/acl"):
            if not self._check_if_match():
                return
            _write_state("policy", json.loads(raw))
            self._send(200, {})
        elif self.path.endswith("/dns/configuration"):
            _write_state("dns", json.loads(raw))
            self._send(200, {})
        else:
            self._send(404, {"message": f"the stub serves no path {self.path}"})

    def do_PATCH(self) -> None:
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path.endswith("/settings"):
            merged = dict(_read_state("settings", SETTINGS_CURRENT))
            merged.update(json.loads(raw))
            _write_state("settings", merged)
            self._send(200, {})
        else:
            self._send(404, {"message": f"the stub serves no path {self.path}"})

    def _check_if_match(self) -> bool:
        """Refuse a policy write that did not carry the fingerprint it read.

        The policy write is the only concurrency-guarded request in the collection,
        and a stub that ignored `If-Match` would pass this target even with the
        header removed from `write()`. Refusing makes the guard load-bearing here,
        the way it is against the real API.

        Returns whether the write may proceed.
        """
        if self.headers.get("If-Match") == POLICY_ETAG:
            return True
        self._send(412, {"message": "If-Match hash mismatch."})
        return False


def _read_state(key: str, default: dict) -> dict:
    """One recorded document, or the default when there is no usable state file.

    The narrowing is deliberate rather than an assertion: a state file that has
    been truncated by a killed run should fall back to the default rather than
    make the target fail for a reason that has nothing to do with the module.
    """
    try:
        with open(STATE) as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return default
    if not isinstance(document, dict):
        return default
    value = document.get(key, default)
    return value if isinstance(value, dict) else default


def _write_state(key: str, value: object) -> None:
    try:
        with open(STATE) as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        document = {}
    document[key] = value
    with open(STATE, "w") as handle:
        json.dump(document, handle)


def main() -> int:
    if "--serve" not in sys.argv:
        print("this stub is started by runme.sh", file=sys.stderr)
        return 2
    # Threaded because the protocol version is HTTP/1.1, which means keep-alive:
    # a single-threaded server would block a second connection behind a first that
    # has not been closed, and the symptom would be a hang rather than a failure.
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
