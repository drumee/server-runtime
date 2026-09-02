# Provenance — server-runtime

This workspace is a symbol-level extraction, not a directory copy. The source
SHA references the immutable imports recorded in `SOURCE_MANIFEST.md`.

| New responsibility | Source evidence | Source SHA | Intentional Phase 2 boundary/difference |
|---|---|---|---|
| Descriptor discovery and service resolution | `sources/server-team/router/rest/index.js::{registerModules,Acl.getModule}` | `9923d32a117324af1d802ea0909d61aa6d31c7e0` | Keeps `acl/*.json`, public/private selection and `module.method`; removes Team router policy and mutable global singletons. |
| Lazy worker cache and post-authorisation invocation | `sources/server-team/router/rest/index.js::{Acl.run,exec}` | `9923d32a117324af1d802ea0909d61aa6d31c7e0` | Preserves constructor shape `new WorkerClass({ session, permission })`; returns the worker method result for the isolated test gateway instead of using Team `output`/`exception` objects. |
| Public ACL fast path | `sources/server-core/lib/acl.js::{check_preprocess,fast_check,check_env}` | `bf7c396b14614f247507f771f72e98184ed931b4` | Supports the approved `public-api` fast path without creating SQL/MFS dependencies. Both the historical nested `preproc.fast_check` and Phase 3 descriptor-level `fast_check` are accepted at this temporary seam. |
| Permission conversion | `sources/server-essentials/lib/lex/{permission,privilege}.js` | `b9460ba442c9962471a592c49ce36b01e0327ff5` | Callers inject the current Essentials converter. The runtime does not copy numeric permission tables or preserve the historical 1.3.1 mapping. |
| Frontend plugin resolver | `sources/server-team/service/bootstrap.js::plugin` | `9923d32a117324af1d802ea0909d61aa6d31c7e0` | Preserves logical name → `index.json` → `{ path }`; roots/public prefix are explicit instead of read from Team `sysEnv()`. |

The pending database-backed portions of `sources/server-core/lib/acl.js` are
explicitly deferred. They are not emulated by this workspace.
