# Phase 2 server runtime extraction

This is a private, transitional CommonJS workspace for the first
application-neutral Drumee backend runtime. It is not a public API, a package
to publish, or an approved final repository boundary.

It deliberately contains only descriptor discovery, `module.method`
resolution, public/private worker selection, lazy worker loading, a small
authorization seam, and the frontend plugin path resolver. Generic database,
cache, logging, configuration, and transaction primitives remain in the
current `@drumee/server-essentials` dependency.

No Team router policy, MFS, provisioning, schemas, or Team service is included.
