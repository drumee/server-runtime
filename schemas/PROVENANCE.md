# Server runtime WebSocket schema provenance

This is the narrow Phase 4.4 Yellow Page closure owned by the transitional
`@drumee/server-runtime` extraction workspace. It is not yet a package
migration/version manager; Phase 4.5 owns that exportability work.

| Target object | Historical evidence | Source SHA | Runtime responsibility | Direct dependencies | Excluded behavior |
| --- | --- | --- | --- | --- | --- |
| `yellow-page/phase4.4-websocket.sql::authn` | `sources/schemas/yellow_page/tables/authn.sql` | `cb838e255600a4ec3797dc7ac13659ad9d187421` | Persist opaque one-time OTAK → runtime session associations | Phase 4 `cookie`; `authn_store` | Hub, MFS, guest/share policy |
| `session_ensure` | `sources/server-core/lib/input.js::{validCookie,_authorization}` plus `sources/schemas/yellow_page/procedures/session/session_check_cookie.sql` | `bf7c396b14614f247507f771f72e98184ed931b4`; `cb838e255600a4ec3797dc7ac13659ad9d187421` | Allocate or retain a persisted anonymous/authenticated runtime `regsid` context | `cookie`, `uniqueId` | Hub lookup, MFS token, organisation/support, DMZ/guest policy |
| `authn_store` | `sources/schemas/yellow_page/procedures/session/authorization/authn_store.sql` | `cb838e255600a4ec3797dc7ac13659ad9d187421` | Persist the historical `token,value` OTAK record | `authn` | HTTP header parsing, Hub-area policy |
| `yellow-page/phase4.4-websocket.sql::socket` | `sources/schemas/yellow_page/tables/socket.sql` | `cb838e255600a4ec3797dc7ac13659ad9d187421` | Socket-to-session binding for both anonymous and authenticated contexts | Phase 4 `cookie`, optional `entity` | Hub, MFS, conference, presence |
| `socket_bind` | `sources/schemas/yellow_page/procedures/session/socket_bind.sql` | `cb838e255600a4ec3797dc7ac13659ad9d187421` | Resolve and consume OTAK, then bind its authoritative session to a socket ID | `authn`, `socket`, `cookie`, optional `entity` | guest/nobody, endpoint/location/state, DMZ/profile/quota branches |
| `socket_get` | `sources/schemas/yellow_page/procedures/session/socket/socket_get.sql` | `cb838e255600a4ec3797dc7ac13659ad9d187421` | Retrieve a minimal socket/session record for generic runtime diagnostics | `socket` | Profile, quota, DMZ and Hub lookup |
| `socket_free` | `sources/schemas/yellow_page/procedures/session/socket_free.sql` | `cb838e255600a4ec3797dc7ac13659ad9d187421` | Remove a closed socket binding | `socket` | Historical conference cleanup |
| `socket_list_session` | `socket_get.sql` and `get_user_from_socket.sql` in the same source closure | `cb838e255600a4ec3797dc7ac13659ad9d187421` | Resolve targeted sockets belonging to a runtime session | `socket` | Profile, quota, DMZ and Hub lookup |
| `socket_refresh` | `sources/schemas/yellow_page/procedures/session/socket_refresh.sql` | `cb838e255600a4ec3797dc7ac13659ad9d187421` | Keep live bindings fresh and prune stale bindings; retains the historical endpoint/list signature | `socket` | Historical conference cleanup |

`authn_store(token, value)` and `socket_bind(args)` retain the historical
OTAK shape. The target intentionally narrows `session_check_cookie` to
`session_ensure`: it allocates/reuses only a cookie context and excludes its
Hub, MFS, organisation, support, DMZ and guest closure. The target adds a
60-second expiry and an atomic `SELECT … FOR UPDATE` claim in `socket_bind`;
one OTAK can bind exactly one socket. The same schema file contains the
idempotent `e8e7bac8e` upgrade: it invalidates pre-`ctime` OTAKs, repairs null
cookie/socket UIDs to a verified provisioned nobody principal where possible,
then enforces the current non-null constraints. `sys_conf` and `entity.type`
are added only as prior-Phase-4 prerequisites; the runtime still never
provisions principal values. No object references Hub, MFS, Finder, Desktop,
Window Manager or a Team schema. The Phase 4.4 cross-site corrective pass
reuses this complete closure: its historical `x-param-*` header parser
validates against the existing cookie context query and adds no application
authorization table, function or procedure.
