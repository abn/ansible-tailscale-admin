# AGENTS.md

The committed entrypoint for humans and agents working on this repository. Short
by design: invariants, not essays.

## Project

`abn.tailscale` is an Ansible collection that manages a Tailscale tailnet
declaratively through the Tailscale Admin API v2.

The working design, the API research behind it, and the build order are internal
documents under `.agents/brain/docs/`. They are deliberately not committed: they
are working material, and publishing them would put process narrative into the
project's public history. Read them before proposing changes, and expect them to
be absent on a fresh clone.

The repository root **is** the collection root, so what is committed here is what
ships to Galaxy (minus `build_ignore` in `galaxy.yml`).

## Invariants

These are not negotiable without an explicit decision recorded in
`docs/log.md`.

1. **Idempotency is the product.** A second run of the same playbook must report
   `changed: 0`. Any change that cannot achieve this for a resource is not ready.
2. **Fail closed on concurrency.** Only the policy file is concurrency
   controlled. Policy writes are always `If-Match` guarded, and an empty `ETag`
   aborts rather than proceeding.
3. **Never silently widen access.** A policy that omits `acls` means allow-all;
   `"acls": []` means deny-all. The modules must refuse to open a tailnet without
   an explicit opt-in.
4. **No third-party Python in `plugins/`.** Modules run on the target host with
   only the standard library and `ansible.module_utils`. Use
   `ansible.module_utils.urls`; never `requests`, `urllib.request` directly, or a
   generated client.
5. **Two linters, two jurisdictions.** `ansible-test sanity` owns module layout
   and correctness under `plugins/`; `ruff` and `ty` own `plugins/`, `tests/` and
   `.contrib/`, and `ruff` additionally owns import order everywhere, which `sanity`
   does not check. `ty` reads `plugins/` because nothing in `module_utils` is
   reachable from `tests` by import, so excluding it left the code that runs on the
   target host unchecked, including whether `Api` satisfies `PolicyClient`. Two
   boundaries, not three: `ty` does not check what `sanity` checks, and `sanity`
   does not check what `ty` checks. Auto-fixes and formatting
   always apply, including to code that has already been reviewed: a reviewed file
   is not a frozen one. Do not add a hand-written hook for anything the existing
   tooling can already do.
6. **No sudo** unless a human explicitly asks for elevation.
7. **No reaching outside the worktree, for reads or writes.** An agent works in its
   own worktree and reads only what that change needs. Credential files, vault
   files and other repositories' secrets are out of scope for *reads* as well as
   writes. Scope discipline governs what you may change; this governs what you may
   look at.
8. **The live API is reachable, but only deliberately.** The owner has authorised
   live verification against a throwaway tailnet, using test OAuth credentials
   the owner provides for exactly that purpose.

   Two prohibitions, and neither has an exception:
   - **Never the host's own Tailscale credentials.** A development machine may
     itself be on the tailnet, in which case its `tailscale` CLI is already
     authenticated and its local socket is node-scoped and typically
     world-writable, so a "quick check" needs no credential at all and can
     reconfigure or drop that machine. `tailscale cert` and `tailscale lock` are
     tailnet-wide rather than node-scoped, so they reach beyond the one machine
     even without a credential. No test uses any of it: a live run takes only the
     key set for it, which is also what makes it behave the same on a machine that
     is not on the tailnet.
   - **A lane never uses a personal account.** A personal API token carries the
     full permissions of the user who created it, all or nothing, and it belongs
     to whoever owns the tailnet rather than to this project's tests. A token left
     in a shell profile should never be enough for an agent to rewrite someone's
     ACLs by accident.

   The test OAuth client is preferred to the owner's personal API token, and not
   because of what it can reach: it is granted every scope, because the
   collection manages policy, DNS, devices, keys, users and webhooks. It is
   preferred because it belongs to the tailnet rather than to a person, it is
   named and revocable in one click from the console, and the access tokens it
   mints expire in an hour on their own rather than lingering for ninety days.
   `make live-smoke` says which credential it used. An agent never creates a
   credential: provisioning is a coordinator action, taken once and reported.

   Every live test takes its credential from a file set explicitly, `./.tskey` by
   default or whatever `TS_KEY_FILE` names, and the tailnet it runs against is
   expected to be a development tailnet the owner is willing to discard. Nothing
   is read from the host's own Tailscale configuration. Live calls go through
   `make live-smoke`, which refuses without both a key and an explicit
   acknowledgement. The default is a mock: `httmock`, or the Prism mock built from
   the vendored description. Neither reaches a network. A lane that cannot verify
   its change without the live API says so and stops, rather than working around
   the gate.
9. **Zero AI slop.** No em dashes or en dashes anywhere, no marketing prose, no
   filler. Full rules in `.agents/rules/comments.md`.
10. **Every comment earns its place.** A comment either explains a non-obvious
   constraint or says something the code cannot. It never narrates how the code
   came to be, never addresses the reader, never uses the first person, and never
   restates the code or an obvious convention. Before writing one, ask: if the
   line below it were deleted, would this leave the reader worse off? If not,
   delete it. A comment describing the past rather than the present is wrong, not
   merely verbose.
11. **Docs move with the change.** Behaviour changes update `docs/` and `docs/log.md`.
12. **Automation over manual conformance.** If a rule can be a hook or a check
    target, it is a hook or a check target.
13. **Public-ready by default.** Nothing committed may contain hostnames, absolute
    home paths, tokens, or internal task identifiers. `.agents/brain/` is the only
    place for internal working material, and it is git-ignored.

## Working procedure

- **State the scope in one sentence before starting:** unit of work, target,
  acceptance condition. Anything not needed for that outcome is out of scope.
- **Stage explicit paths.** Never `git add -A`. The pre-commit hook runs the full
  gate over the staged index, so a partial commit would fail it.
- **Conventional Commits, summary-only.** Titles are at most 52 characters, in
  the imperative mood, with no type suffix noise. Add a body only when the *why*
  is not evident from the diff.
- **No AI attribution trailers.** Do not add `Co-Authored-By` or similar.
- **Clean history.** Fixup or amend into the owning commit rather than stacking
  noisy fix commits.
- **One worktree per scoped change** on a conventional branch (`feat/`,
  `fix/`, `docs/`, `chore/`, `refactor/`), hyphenated, rebased on the latest
  `main` before work starts. *Bootstrap is the exception: the repository was
  initialised directly on `main`.*
- **Review gate before push.** A subagent reviews the change as a skeptical
  maintainer, then the human holds the approve-to-push decision.

## Verification

A change is done only when the check target passes with real captured output.

```
make check          # fast, hermetic, no containers. The pre-commit hook runs this.
make check/full     # adds ansible-test sanity, units and integration in containers.
```

`make check` runs `make lint` first, which is `ruff`, then `ty`, then
`ansible-lint`, then all pre-commit hooks over every file, which is where
`okf validate docs/` runs, then the changelog fragments, then
`antsibull-docs lint-collection-docs`. That last one is what parses each module's
`DOCUMENTATION`, `EXAMPLES` and `RETURN` as YAML, and nothing else in the fast path
does, so a stray colon in a description is caught here rather than at
`check/full` or at the docsite. It must never need Docker or Podman.

Live verification is not part of `check` and never will be. It runs separately,
through `make live-smoke`, on a throwaway tailnet, with the test OAuth credential
and an explicit acknowledgement.

The pre-commit hook does not call `make check`. It runs the pre-commit hooks
alone, because it fires on files already staged and `make check` is the superset
that CI runs. Anything added to `make check` is not automatically enforced locally
at commit time.

Claims like "the tests pass" without output are not verification. If a gate cannot
run in the current environment, say so rather than implying it passed.

## Division of labour

| Concern | Owner |
|---|---|
| Module layout and `module_utils` correctness | `ansible-test sanity` |
| Import order, everywhere | `ruff` |
| Repo tooling and test code style | `ruff`, `ty` |
| Collection manifest, FQCN usage, YAML | `ansible-lint` |
| Docs bundle structure and frontmatter | `okf validate docs/` |
| Commit message form and editorial invariants | `pre-commit` |
| Galaxy artifact contents and size | `make build`, which asserts both |
| Upstream API drift | `make spec/drift` |
| The ansible-core x Python matrix | CI, via `ansible-test-gh-action` |

Locally, one ansible-test version is used. The matrix belongs in CI, not in a
hand-rolled local runner.

`ansible-galaxy build` does not read `.gitignore`, so a development path missing
from `build_ignore` in `galaxy.yml` ships silently. `make build` therefore
verifies the artifact rather than trusting the list: it fails on any known
development path and on anything over the 20 MB Galaxy limit. When you add a
tool that writes into the tree, extend that assertion in the same change.

## Scratch area

`.agents/brain/` is git-ignored and holds transient working material:
`inbox/` for incoming material, `outbox/` for the internal progress log,
`tasks/` for breakdowns and risk registers, `assets/` for reusable material.

`ansible-test` needs a second, separate scratch area, and it deliberately does
**not** live in `.agents/brain/`. `ansible-test` enumerates content through git,
so a tree nested anywhere inside this repository, git-ignored or not, reports
`All targets skipped` and silently checks nothing. Verified empirically: the same
copy under `/tmp` runs and reports violations, the same copy under
`.agents/brain/` does not. A copy is used rather than symlinks, because
`ansible-test` does not traverse symlinked content directories.

`make collection/link` therefore stages the collection at
`$TMPDIR/ansible-tailscale/ansible_collections/abn/tailscale`, and the `sanity`,
`test` and `integration` targets depend on it.

## Project rules

Extended, never replacing, the above:

- `.agents/rules/comments.md`: what a comment may say, and what it must never say.
- `.agents/rules/python.md`: interpreter, uv workflow, ruff and `ty` scope.
- `.agents/rules/ansible.md`: module conventions, private `module_utils`, the
  GPL/BSD licensing split, sanity-test expectations.
- `.agents/rules/documentation.md`: OKF bundle rules and the scope table the
  collection owes its users.
- `.agents/rules/lanes.md`: how to brief a parallel lane, including the brief
  template that carries the credential and live-API rules.

## Further reading

- [Overview](docs/overview.md)
- [Contributing](docs/contribution/README.md)
