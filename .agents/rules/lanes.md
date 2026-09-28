# Running parallel lanes

A lane is a subagent with one worktree, one branch and one file set. The point of
splitting is that no two writers share a file, so every rule here exists to keep
that true or to stop a lane reaching something it was not given.

## One writer per file

The coordinator publishes a file-ownership map before the wave starts. A lane
stages explicit paths and never `git add -A`, so a lane that strays onto another
lane's file shows up as a conflict at rebase rather than as a silent overwrite.

Two lanes may run concurrently. A lane and the coordinator may not share a
worktree, and the coordinator does not touch a lane's worktree while its agent is
live. Review fixes belong on `main` and reach the lane by rebase.

## The brief is generated from this template

Briefs are written by hand, which is how a clause gets left out of one. Copy this
and fill the marked slots. The credential clause is not optional and is not
summarised: a lane that cannot see the live API rules will assume it may use
whatever Tailscale the machine already has.

```
## Scope
Unit of work: <one sentence>
Target: <files this lane may create or modify, listed explicitly>
Acceptance: <the condition that ends the lane, and the command that proves it>
Out of scope: <anything not needed for that outcome>

## Ground rules
- Work only in <worktree path>, on branch <branch>, rebased on the latest main
  before you start.
- Commit after each file goes green, not at the end. A lane that writes everything
  and commits nothing has to be redone from scratch.
- Stage explicit paths. Never `git add -A`.
- Conventional Commits, title at most 52 characters, imperative, summary only.
  Add a body only when the why is not evident from the diff.
- No AI attribution trailers.
- Do not modify a real Tailscale tailnet, and do not use the tailscale CLI.

## Credentials and the live API
- Testing uses the test OAuth credentials the owner provides, and only those. The
  default is a mock: httmock, or the Prism mock built from the vendored OpenAPI
  description. Neither reaches a network.
- Never use the credentials the machine already holds, and never a live or
  personal account. A personal API token is the tailnet owner's credential,
  carries all of their permissions, and is not a test credential however
  convenient it looks.
- Never invoke the `tailscale` CLI and never touch /var/run/tailscale/. Where the
  machine is itself on the tailnet, its local socket is node-scoped and typically
  world-writable, so a quick check needs no credential at all. `tailscale cert`
  and `tailscale lock` are tailnet-wide rather than node-scoped, so they are the
  ones that would do real damage.
- Do not create a credential of any kind: no API key, no OAuth client, no trust
  credential. Provisioning is the coordinator's job, done once. A credential you
  made yourself is one nobody tracked.
- Do not call api.tailscale.com by hand. The only sanctioned route is
  `make live-smoke`, and it refuses without
  TS_LIVE_SMOKE=I_HAVE_A_THROWAWAY_TAILNET set.
- If your change cannot be verified without the live API, say so in your report
  and stop. Do not work around the gate.

## Reporting
State what you ran and paste the real output. "The tests pass" is not
verification. If a gate could not run in this environment, say that instead of
implying it passed. If a brief clause is wrong, correct it in your report rather
than bending your code to fit it.
```

## What a lane reports back

The gate output, the commit list, and anything it found that the brief got wrong.
The last part matters most: two lanes in this project have corrected the
coordinator on a factual claim, and both were right. A lane that obeys a wrong
brief produces green output and a wrong module.

## Why the credential clause is so long

A machine that is on the tailnet has a working `tailscale` CLI. An agent that
decides to "just check" something can reconfigure or drop that machine without
any credential at all, because the local socket is node-scoped and typically
world-writable. The credential rules are therefore not only about secrets; they
are about the fact that the nearest available thing may be a live tailnet.
