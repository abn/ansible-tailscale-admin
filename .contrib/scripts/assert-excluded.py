#!/usr/bin/env python
# SPDX-License-Identifier: GPL-3.0-or-later
"""Report artifact entries that a `build_ignore` entry was supposed to exclude.

Reads the lists `make build` has already written and prints the offending paths,
one per line, for the recipe to append to its leak file. A non-empty result means
`ansible-galaxy build` shipped something the manifest said to leave out, which is
the failure `build_ignore` cannot report about itself.

The comparison walks each artifact path's ancestors rather than matching a
substring, because `build_ignore` entries are paths and a path is a prefix of
itself at component boundaries. A substring match on the entries alone would fail
the build for a legitimate `plugins/lookup/dist_cache.py`, because `dist` is an
excluded path and `dist_cache` contains it.

Writes nothing and imports nothing outside the standard library, since this runs
from the Makefile rather than from the test suite.
"""

from __future__ import annotations

import sys
from pathlib import Path

#: A directory entry in a tarball listing, so `foo` also covers `foo/bar.py`.
SUFFIX = "/"


def covered(artifact_path: str, excluded: set[str]) -> bool:
    """Whether `artifact_path` is, or is beneath, any excluded path."""
    candidate = artifact_path
    while candidate:
        if candidate in excluded:
            return True
        head, separator, _tail = candidate.rpartition("/")
        if not separator:
            return False
        candidate = head
    return False


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {Path(argv[0]).name} <scratch-dir>", file=sys.stderr)
        return 2
    scratch = Path(argv[1])
    excluded = {
        line.strip().rstrip("/")
        for line in (scratch / "excluded.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    for line in (scratch / "artifact.txt").read_text(encoding="utf-8").splitlines():
        path = line.strip()
        if not path:
            continue
        # `ansible-galaxy` lists directories with a trailing slash; a leak is the
        # file beneath one, not the directory entry, so both are checked.
        trimmed = path.rstrip(SUFFIX)
        if covered(trimmed, excluded) or f"{trimmed}/" in excluded:
            print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
