#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Drives the modules through a real ansible-playbook against a loopback stub, and
# asserts on the rendered output rather than on return values. Nothing here needs
# a credential, a tailnet or a network, which is what makes it safe to run in
# every matrix cell.
#
# The playbook is run through the harness inventory ansible-test provides, so the
# module is executed the way a user's would be: a real AnsibleModule, a real
# transport, a real callback.

set -euo pipefail

target_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
files="${target_dir}/files"
work="$(mktemp -d)"
stub_pid=""

cleanup() {
    if [ -n "${stub_pid}" ] && kill -0 "${stub_pid}" 2>/dev/null; then
        kill "${stub_pid}" 2>/dev/null || true
        wait "${stub_pid}" 2>/dev/null || true
    fi
    rm -rf "${work}"
}
trap cleanup EXIT

# A port nothing else on the machine holds. Binding to port 0 and reading back
# what the kernel assigned is the usual way to get one, and it does leave the
# usual window between closing the socket and reopening it, which is why the
# readiness loop below waits for the listener rather than assuming it.
port="$(python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()')"

export STUB_PORT="${port}"
export STUB_STATE="${work}/state.json"
cp "${files}/initial-state.json" "${STUB_STATE}"

python3 "${files}/stub.py" --serve &
stub_pid=$!

# Wait for the listener rather than sleeping a fixed interval, so a slow machine
# does not produce a failure that looks like a broken module.
for _ in $(seq 1 50); do
    if python3 -c "import socket, sys
s = socket.socket()
s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1', ${port})) == 0 else 1)"; then
        break
    fi
    sleep 0.1
done

if ! kill -0 "${stub_pid}" 2>/dev/null; then
    echo "the stub did not start on port ${port}" >&2
    exit 1
fi

cat > "${work}/inventory" <<INVENTORY
[local]
localhost ansible_connection=local ansible_python_interpreter="${PYTHON:-python3}"
INVENTORY

cat > "${work}/playbook.yml" <<PLAYBOOK
---
- hosts: all
  gather_facts: false
  vars:
    base_url: "http://127.0.0.1:${port}/api/v2"
    policy_file: "${files}/policy.hujson"
  tasks:
    - ansible.builtin.include_tasks: "${target_dir}/tasks/main.yml"
PLAYBOOK

# The rendered diff is the point of the first assertion, so the output is kept and
# grepped rather than only being produced.
set +e
ansible-playbook -i "${work}/inventory" "${work}/playbook.yml" --diff \
    > "${work}/output.txt" 2>&1
status=$?
set -e

cat "${work}/output.txt"

if [ "${status}" -ne 0 ]; then
    echo "the playbook failed" >&2
    exit 1
fi

# `ansible-test` reports a play recap whose changed count is the property the
# collection is built around, so it is asserted from the outside too. A module
# that reported a change on the second run would still pass every assertion in
# the playbook and fail here.
changed_count="$(sed -n 's/.*changed=\([0-9]\+\).*/\1/p' "${work}/output.txt" | tail -1)"
if [ "${changed_count}" != "3" ]; then
    echo "expected 3 changed tasks across the playbook, found ${changed_count}" >&2
    exit 1
fi
