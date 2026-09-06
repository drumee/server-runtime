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
