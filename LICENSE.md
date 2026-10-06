# License

The collection is licensed under the GNU General Public License v3.0 or later
(SPDX: `GPL-3.0-or-later`).

Full text: [`LICENSES/GPL-3.0-or-later.txt`](LICENSES/GPL-3.0-or-later.txt).

## Per-file licensing

Some files carry a different, compatible license. Per-file licensing follows the
REUSE convention: each file declares its license through a `SPDX-License-Identifier`
comment, and every declaration resolves to a text under `LICENSES/`.

| Path | License | Why |
|---|---|---|
| `plugins/modules/**` | `GPL-3.0-or-later` | Ships to the target host as part of the AnsiballZ payload. |
| `plugins/module_utils/**` | `BSD-2-Clause` | Reused by module authors in other projects, including those under licenses incompatible with the GPL. ansible-core relicenses its own `module_utils` this way for the same reason. |
| `tests/**` | `GPL-3.0-or-later` | Imports code from `plugins/`. |
| everything else | `GPL-3.0-or-later` | |

Full texts: [`LICENSES/BSD-2-Clause.txt`](LICENSES/BSD-2-Clause.txt),
[`LICENSES/BSD-3-Clause.txt`](LICENSES/BSD-3-Clause.txt).

## Third-party material

`tests/fixtures/openapi/tailscale.yaml` is Tailscale's published OpenAPI description
of its own Admin API v2, redistributed unmodified under `BSD-3-Clause`
(SPDX: `BSD-3-Clause`). See [`tests/fixtures/openapi/README.md`](tests/fixtures/openapi/README.md).
