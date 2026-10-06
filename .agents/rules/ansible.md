# Ansible rules

Extends `AGENTS.md`. Applies to `plugins/`, `galaxy.yml`, `meta/` and the
ansible-test suites.

## Module authoring

- `AnsibleModule` from `ansible.module_utils.basic` is the only supported base for
  modules, and its signature is unchanged. There is no newer module class and no
  `@plugin` decorator; `AnsiblePlugin` and its Jinja2 subclasses are for
  non-module plugins only. Do not mix the two hierarchies.
- File layout inside a module, in this exact order: shebang, copyright plus the
  short GPL line, `DOCUMENTATION`, `EXAMPLES`, `RETURN`, then imports. The
  `import-placement` check requires imports directly below `RETURN`.
- Shebang is exactly `#!/usr/bin/python`, with no arguments, and the file must not
  be executable.
- The short licence line is required and must carry no year:
  `# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)`
- `short_description` must not end in a period. It is listed by `ansible-doc -l`
  with no surrounding context, so it has to stand alone.
- Check mode and diff support are declared in `attributes:`, never in `notes:`.
  `validate-modules` cross-checks `attributes.check_mode.support` against
  `supports_check_mode`, and requires `details:` for `partial`.
- Never pass `warnings=` or `deprecations=` to `exit_json` or `fail_json`. Both
  are deprecated for removal in 2.23; use `module.warn` and `module.deprecate`.
- Option removal uses `removed_in_version` (semver, must be `x.0.0`) together with
  the mandatory `removed_from_collection`, or `removed_at_date` in the future.
  `removed_in` is the `DOCUMENTATION` spelling; the argument spec uses
  `removed_in_version`.
- Deprecating a return value uses `deprecate_value` from
  `ansible.module_utils.datatag`, not a module-level warning.
- `state` must not offer `get`, `list`, `query` or `info`. Read-only behaviour
  belongs in a separate `<thing>_info` or `<thing>_facts` module.
- Module files are flat under `plugins/modules/`. Nesting breaks short FQCNs and
  fails `ansible-lint`.
- New options and new plugins declare `version_added` as `x.y.0`; it is the
  **collection** version, never an ansible-core version.

## Secrets

- Any option whose name matches `pass|secret|token|key` and that is not obviously
  benign must set `no_log=True`. Options that merely *look* secret, such as
  `key_name` or `token_type`, must set `no_log=False` explicitly, or
  `no-log-needed` fails.
- `no_log` values are scrubbed from the result automatically. If a secret can end
  up in a **dict key**, call `sanitize_keys` as well.
- Never echo credentials in a failure message. In particular never include the
  request headers. Raise a module-local exception carrying an already-sanitised
  message and let `main()` convert it to `fail_json`.
- Return values are a whitelist projection of the API response, not the raw
  object. A returned secret must be opt-in.

## Private module_utils

`plugins/module_utils/_tailscale/` is internal to this collection. The leading
underscore is the declaration: the kernel may be refactored in any release
without a major version bump. Every file under that path carries a comment
saying so. Promoting one of these files to public is a breaking change and
requires a rename plus a major release.

## Target-side constraints

Modules execute on the target host under AnsiballZ:

- Standard library and `ansible.module_utils` only. No third-party imports. If a
  dependency is unavoidable, guard it with `try`/`except ImportError` and report
  it through `missing_required_lib`.
- HTTP goes through `ansible.module_utils.urls`. The `replace-urlopen` and
  `use-module-utils-urls` sanity tests enforce this.
- `print`, `sys.exit`, `subprocess` and `os.system` are banned in modules. Use
  `module.log`, `module.exit_json` and `module.run_command`.
- Modules target **Python 3.12 and later**. The owner set this; it is not derived
  from an ansible-core floor, so builtin generics and PEP 604 unions are usable at
  runtime and not only inside annotations, and `from __future__ import
  annotations` is a convention rather than a requirement. The interpreter in
  `.python-version` governs tooling and happens to agree with this, which is not
  the reason it does.
- The 2.19 porting guide made `exit_json` reject non-string dict keys outright.
  Coerce keys explicitly.

## The live API is off limits by default

No module, test or fixture may contact `api.tailscale.com` or a real tailnet.
A credential being present in the environment is deliberately **not** sufficient
authorisation: a token left in a shell profile should never be enough to rewrite
someone's ACLs by accident.

The single sanctioned route is `make live-smoke`, which requires an explicit
acknowledgement before it does anything. A module that needs to prove behaviour
against a real tailnet goes through that target, against a tailnet the operator is
willing to discard, and never in default CI.

Tests that need HTTP use `httmock`, or the Prism mock built from the vendored
OpenAPI description. Neither reaches a network.

Two rules are absolute rather than conditional. No agent invokes the `tailscale`
CLI, and no agent uses the credentials the machine already holds. Where that
machine is itself on the tailnet, its CLI is authenticated and its local socket
is node-scoped and typically world-writable, so a "quick check" needs no
credential and can reconfigure or drop it. `tailscale cert` and `tailscale lock`
are tailnet-wide rather than node-scoped, so they reach beyond one machine even
without a credential.

A personal account is not a shortcut for a lane. A personal API token carries
the full permissions of whoever created it, all or nothing, and it is their
credential rather than a test one, so a lane that reaches for it can affect more
than it meant to.

The test OAuth client is preferred to it, but not on the grounds of least
privilege: it holds every scope, because the collection needs them all. What it
has instead is ownership and lifetime. It belongs to the tailnet rather than to a
person, it is named on the Trust credentials page and revocable in one click, and
the access tokens it mints last an hour, so nothing leaks forward. `live-smoke`
prints which credential it used.

An agent never creates a credential. Provisioning an OAuth client is a
coordinator action, taken once and reported; a credential an agent made itself is
a credential nobody tracked.

A freshly provisioned OAuth client answers 404 on every endpoint for a short
while before its scopes take effect, and a dash resolves the default tailnet
under OAuth exactly as it does under an API token. Both were established by
measurement: the 404s appear immediately after minting and clear on their own, so
a live check that 404s straight after provisioning says nothing about permissions
and must be repeated before it is believed.

## Licensing split

Per REUSE, declared in `LICENSE` and resolved through `LICENSES/`:

- `plugins/modules/**` and everything else: `GPL-3.0-or-later`.
- `plugins/module_utils/**`: `BSD-2-Clause`, so that module authors under
  GPL-incompatible licences can still reuse them. This mirrors ansible-core, which
  relicenses its own `module_utils` for the same reason.

## Sanity tests

`make check/full` runs them; CI runs them across every supported ansible-core
branch. The ones that actually bite:

- `validate-modules`: documentation versus argument-spec agreement,
  `no-log-needed`, `attributes-check-mode`, `import-placement`, GPL header.
- `pylint` with the collection config: banned imports and functions, deprecation
  correctness.
- `import`: only the standard library is visible to a module.
- `changelog`: needs at least one user-affecting fragment. Do **not** write a
  fragment for a new module; antsibull derives those from `version_added`. The
  test parses **every** file in `changelogs/fragments/` as YAML, so nothing else
  may live there, not even a README.
- `yamllint`, driven by `.yamllint`.
- `empty-init` requires `__init__.py` in every plugin subdirectory, and requires
  each one to be **completely empty**, zero bytes. This directly conflicts with
  the REUSE convention of an SPDX header in every file, and ansible-test wins:
  the `__init__.py` files carry no header. The licensing of those files is stated
  in `LICENSE.md` instead.
- `ansible-doc`, which parses module documentation on every supported Python.
- All 34 tests pass with an empty ignore file. Keep it that way.

### Ignore files

`tests/sanity/ignore-<core>.txt` is treated as a smell. Each line is a known
defect with a comment justifying it. Ignoring an error that does not occur is
itself an error, so a stale entry fails the run, which is the intended pressure to
delete it. Never ignore `doc-choices-do-not-match-spec`, `doc-missing-type`,
`no-log-needed`, or the other errors on the must-not-ignore list.

Keep it empty.
