# @drumee/server-runtime

Drumee minimal backend runtime. This is a pre-release CommonJS API extracted
from the validated Phase 4.5 minimal-kernel boundary. It is application-neutral
and prepared for a public prerelease under the `next` dist-tag; it is not yet
published to npm and does not claim stable API compatibility.

The runtime owns request/session context, Domain authorization, generic
descriptor-driven MFS authorization orchestration, descriptor
discovery, `module.method` dispatch, lazy worker loading, frontend plugin
resolution, WebSocket authentication/routing and its intrinsic Yellow Page SQL
closure. MFS authorization is dependency-injected: runtime compares descriptor
requirements with effective privileges supplied by an application backend; it
does not import MFS storage or SQL. It does not own Hub, MFS business behavior,
Team policy or application behavior.

The HTTP adapter normalizes the historical logical `/vdo/` routes to the known
`video.master`, `video.stream` and `video.segment` services. `RuntimeOutput`
keeps structured/control output and header-only internal redirects explicit;
large payload delivery remains outside the Node data plane.

Hosts may explicitly configure a bounded binary-upload service. The runtime
authorizes its query metadata before reading the body, optionally applies an
owner preflight, streams `application/octet-stream` into a server-generated
tempfile with backpressure and a hard byte limit, and deletes any unclaimed
tempfile after dispatch. Generic structured JSON remains limited to 64 KiB.

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

This prerelease does not add platform bootstrap, provisioning, MFS,
Hub/resource ACL, Finder, Window Manager, Marketing, Team migration, ESM or
Debian packaging.

## Provenance

The repository was history-extracted from
`drumee/transient:target/foundation/server-runtime` at transient commit
`e3f4468d3ea882baeee4c7fefbd956aca4128d28`. See [PROVENANCE.md](PROVENANCE.md)
for extraction and symbol-level source details.
