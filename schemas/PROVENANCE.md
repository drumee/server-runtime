# Server runtime WebSocket schema provenance

This is the narrow Phase 4.4 Yellow Page closure owned by the transitional
`@drumee/server-runtime` extraction workspace. It is not yet a package
migration/version manager; Phase 4.5 owns that exportability work.

| Target object | Historical evidence | Source SHA | Runtime responsibility | Direct dependencies | Excluded behavior |
| --- | --- | --- | --- | --- | --- |
| `yellow-page/phase4.4-websocket.sql::socket` | `sources/schemas/yellow_page/tables/socket.sql` | `cb838e255600a4ec3797dc7ac13659ad9d187421` | Socket-to-session identity binding | Phase 4 `cookie`, `entity` | Hub, MFS, conference, presence |
| `socket_bind` | `sources/schemas/yellow_page/procedures/session/socket_bind.sql` | `cb838e255600a4ec3797dc7ac13659ad9d187421` | Bind a real active `regsid` session to a socket ID | `socket`, `cookie`, `entity` | Historical `authn`, guest/nobody, endpoint/location/state fields |
| `socket_free` | `sources/schemas/yellow_page/procedures/session/socket_free.sql` | `cb838e255600a4ec3797dc7ac13659ad9d187421` | Remove a closed socket binding | `socket` | Historical conference cleanup |
| `socket_list_session` | `socket_get.sql` and `get_user_from_socket.sql` in the same source closure | `cb838e255600a4ec3797dc7ac13659ad9d187421` | Resolve sockets belonging to the authenticated HTTP session | `socket` | Profile, quota, DMZ and Hub lookup |
| `socket_refresh` | `sources/schemas/yellow_page/procedures/session/socket_refresh.sql` | `cb838e255600a4ec3797dc7ac13659ad9d187421` | Keep live bindings fresh and prune stale bindings | `socket` | Historical conference cleanup |

The target deliberately reuses historical SQL object names where they are
part of the intrinsic socket/session contract, but narrows their bodies to
the Phase 4 real-session model. No object references Hub, MFS, Finder,
Desktop, Window Manager or a Team schema.
