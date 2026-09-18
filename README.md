# @drumee/server-runtime

Drumee minimal backend runtime. This is a pre-release CommonJS API extracted
from the validated Phase 4.5 minimal-kernel boundary. It is application-neutral
and remains private during R0; it is not yet published to npm and does not claim
stable API compatibility.

The runtime owns request/session context, Domain authorization, descriptor
discovery, `module.method` dispatch, lazy worker loading, frontend plugin
resolution, WebSocket authentication/routing and its intrinsic Yellow Page SQL
closure. It does not own Hub, MFS, Team policy or application behavior.

## Development

Node.js 18 or newer is required.

```bash
npm ci
npm test
npm pack --dry-run --ignore-scripts
```

The test suite includes unit tests, schema-manifest validation and negative
cases, a shipped-file dependency audit, `npm pack`, and installation into a
clean consumer with `NODE_PATH` disabled.

## Intrinsic schemas

`schemas/SCHEMA_MANIFEST.json` is the executable install/upgrade inventory.
Every entry is package-relative, confined below the installed package root and
validated against the package name/version before use. Runtime code, intrinsic
runtime schemas and their migrations remain in this repository and package.

Schema installation is not platform provisioning. A valid Drumee instance
provides canonical organisation `DEFAULT_ORG_ID = 1` and nobody identity
`NOBODY_UID = ffffffffffffffff`; guest and privileged system identities remain
provisioned and distinct. The runtime consumes and requires these invariants.
It does not create or silently repair them.

## Non-goals

R0 does not add platform bootstrap, provisioning, MFS, Hub/resource ACL,
Finder, Window Manager, Marketing, Team migration, ESM, Debian packaging or
npm publication.

## Provenance

The repository was history-extracted from
`drumee/transient:target/foundation/server-runtime` at transient commit
`e3f4468d3ea882baeee4c7fefbd956aca4128d28`. See [PROVENANCE.md](PROVENANCE.md)
for extraction and symbol-level source details.
