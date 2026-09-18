# Phase 2 server runtime extraction

This is a private, transitional CommonJS workspace for the first
application-neutral Drumee backend runtime. It is not a public API, a package
to publish, or an approved final repository boundary.

It deliberately contains descriptor discovery, `module.method` resolution,
public/private worker selection, lazy worker loading, frontend plugin path
resolution, and the smallest approved authentication/Domain-ACL seam. Generic
database, cache, logging, configuration, and transaction primitives remain in
the current `@drumee/server-essentials` dependency.

The approved private seam is limited to `scope: "domain"` → Yellow Page
`domain_permission`, with real `session_signin`/`regsid` session handling.
Hub scope, Hub shards, MFS, provisioning and Team router policy are excluded.

## Phase 4.5 export boundary

The private `npm pack` artifact contains only the runtime executable closure:
`lib/`, `acl/`, `service/`, `schemas/`, this README and provenance. It excludes
tests, `sources/**`, Team code, build output and temporary artifacts. Its
`schemas/SCHEMA_MANIFEST.json` deterministically lists the intrinsic Yellow
Page base and WebSocket SQL in install order and their idempotent Phase 4.4
upgrade entry point. Installing these SQL files does not provision an
organisation or create `system`, `nobody` or `guest`; that remains an external
organisation-provisioning responsibility.

The package name and boundary are still transitional and are not a public API
or publication commitment.
