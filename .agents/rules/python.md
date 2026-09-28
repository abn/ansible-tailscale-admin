# Python rules

Extends `AGENTS.md`. Applies to `tests/`, `.contrib/`, and anything else outside
`plugins/`. Where a rule covers `plugins/` too it says so, because most of them
do not: the code under `plugins/` runs on the target host with no third-party
packages, and `.agents/rules/ansible.md` owns the parts of it that are not
ordinary Python.

## Interpreter and environment

- Interpreter pinned in `.python-version` governs **development tooling only**.
- `uv` manages the environment. `uv.lock` is committed and `uv sync --locked` is
  the only way to install. A resolution that needs to change the lockfile is a
  deliberate act, not a side effect.
- Every command goes through `uv run --no-sync --locked`. `--no-sync` prevents a
  silent dependency mutation mid-command; `--locked` fails rather than
  re-resolving. The Makefile wraps this in `$(UV)`.
- `[tool.uv] package = false`. An Ansible collection is published as a Galaxy
  artifact, never as a wheel, so there is nothing for uv to build or install.

This does **not** set the floor for module execution. Modules run on the target
host. See `.agents/rules/ansible.md`.

## Layout

- `src`-style packaging is not used and `pythonpath = ["."]` is forbidden. A
  repository-root entry on the import path lets tests silently import the wrong
  thing.
- Import with absolute paths only. `ruff`'s `TID252` bans relative imports: they
  break under Ansible's collection loader, which imports plugin code by absolute
  `ansible_collections` path.
- One import per line: no statement binds more than one name. Keeps refactor
  diffs to the lines that actually moved. `ruff`'s `force-single-line` enforces it
  across the whole tree, `plugins/` included. The rule is about statements, not
  about line breaks: one long import the formatter wrapped in parentheses is
  still one import.

## Style

- `line-length = 100`. The formatter owns wrapping; `E501` is disabled.
- Selected: `E`, `W`, `F`, `I`, `B`, `UP`, `SIM`, `N`, `TID`, `RUF`.
- Ignored: `B008` (a call in an argument default is the idiom for argument
  specs), `SIM108` (ternaries hide intent in reconciliation branches).
- Comments describe the current state of the code only. Never "changed from X",
  never a restatement of the next line, never a file-by-file list that will rot.
  A comment earns its place by explaining something the code cannot.

## Types

- `ty` for static analysis, scoped to `plugins/`, `tests/` and `.contrib/`. The
  `plugins/` scope is not optional: nothing under `module_utils` is reachable from
  `tests` by import, so excluding it left the code that runs on the target host
  unverified, including the `Api` satisfies `PolicyClient` seam.
- Annotate function signatures. Prefer `X | None` over `Optional[X]`; `UP` will
  enforce the syntax where the target version allows it.
- Where a narrowing is implied but not visible to the checker, make it visible
  with a `TypeGuard` or by nesting. Six such sites existed in `module_utils` and
  none was a runtime bug, which is the point: they are bugs waiting for a caller
  that reaches them differently.
- Type hints do not replace `validate-modules`. The Ansible argument spec is the
  contract that reaches the user, and it is validated separately.

## Tests

- **Plain pytest functions and fixtures. Not `unittest.TestCase`.** ansible-test
  runs the suite through pytest with the `ansible_pytest_collections` plugin, so
  classes buy nothing and cost the fixtures. Prefer `mocker` from `pytest-mock`
  over `unittest.mock.patch` decorators, and `tmp_path` over `tempfile`.
- Fixtures over `setUp`. A fixture scoped narrower than the module is usually the
  right scope: the expensive part is building a fake client, not each assertion.
- Arrange, act, assert, with a blank line between the three phases. When a test
  needs a comment to say which phase it is in, it is too long.
- Name tests for the behaviour and the condition, not the function under test:
  `test_reports_no_change_when_policy_matches`, not `test_policy_1`.
- The runner is `ansible-test units` (see `make test`), not bare `uv run pytest`.
  ansible-test owns the interpreter, the collection import path and the
  `ansible_pytest_collections` plugin. The `[tool.pytest.ini_options]` section
  exists for editor integration and single-file runs.
- Every imported third-party package in `tests/unit/**` must be listed in
  `tests/unit/requirements.txt`.
- Mocks live in `tests/` only. Production code under `plugins/` contains no
  test doubles, no `if DEBUG`, and no hooks for tests.
