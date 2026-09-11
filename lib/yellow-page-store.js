const { RuntimeError } = require("./errors");
const { firstRow } = require("./session");

const OTAK_TTL_SECONDS = 60;

// Current server-essentials await_func() returns the first SELECT row. For a
// SQL function that row has a generated column name (for example
// `domain_permission( 'uid', 41, 2)`), not a scalar. Keep that generic
// database representation at this narrow runtime adaptation seam.
function scalarFunctionValue(value) {
  if (value == null || typeof value !== "object") return value;
  const values = Object.values(value);
  return values.length ? values[0] : undefined;
}

function rows(value) {
  if (Array.isArray(value)) return value.flatMap((entry) => rows(entry));
  return value && typeof value === "object" ? [value] : [];
}

const SESSION_QUERY = `
  SELECT
    c.id AS session_id,
    c.uid,
    c.status,
    e.id,
    e.dom_id AS domain_id,
    o.name AS domain,
    d.username AS ident,
    nobody.conf_value AS nobody_id,
    guest.conf_value AS guest_id,
    IF(
      nobody.conf_value IS NOT NULL
      AND guest.conf_value IS NOT NULL
      AND guest.conf_value <> ''
      AND guest.conf_value <> nobody.conf_value
      AND EXISTS (
        SELECT 1 FROM entity guest_entity
          INNER JOIN drumate guest_drumate ON guest_drumate.id = guest_entity.id
          WHERE guest_entity.id = guest.conf_value
            AND guest_entity.ident = 'guest'
            AND guest_drumate.username = 'guest'
      ), 1, 0
    ) AS guest_configured,
    IF(
      nobody.conf_value IS NOT NULL
      AND guest.conf_value IS NOT NULL
      AND guest.conf_value <> ''
      AND guest.conf_value <> nobody.conf_value
      AND EXISTS (
        SELECT 1 FROM entity guest_entity
          INNER JOIN drumate guest_drumate ON guest_drumate.id = guest_entity.id
          WHERE guest_entity.id = guest.conf_value
            AND guest_entity.ident = 'guest'
            AND guest_drumate.username = 'guest'
      )
      AND c.uid NOT IN (nobody.conf_value, guest.conf_value)
      AND c.status = 'ok', 1, 0
    ) AS signed_in
  FROM cookie c
  INNER JOIN entity e ON e.id = c.uid
  INNER JOIN drumate d ON d.id = e.id
  INNER JOIN domain o ON o.id = e.dom_id
  LEFT JOIN sys_conf nobody ON nobody.conf_key = 'nobody_id'
  LEFT JOIN sys_conf guest ON guest.conf_key = 'guest_id'
  WHERE c.id = ?
    AND c.status = 'ok'
    AND c.mtime + c.ttl > UNIX_TIMESTAMP()
  LIMIT 1
`;

const SESSION_CONTEXT_QUERY = `
  SELECT
    c.id AS session_id,
    c.uid,
    c.status,
    e.id,
    e.dom_id AS domain_id,
    o.name AS domain,
    d.username AS ident,
    nobody.conf_value AS nobody_id,
    guest.conf_value AS guest_id,
    IF(
      nobody.conf_value IS NOT NULL
      AND guest.conf_value IS NOT NULL
      AND guest.conf_value <> ''
      AND guest.conf_value <> nobody.conf_value
      AND EXISTS (
        SELECT 1 FROM entity guest_entity
          INNER JOIN drumate guest_drumate ON guest_drumate.id = guest_entity.id
          WHERE guest_entity.id = guest.conf_value
            AND guest_entity.ident = 'guest'
            AND guest_drumate.username = 'guest'
      ), 1, 0
    ) AS guest_configured,
    IF(
      nobody.conf_value IS NOT NULL
      AND guest.conf_value IS NOT NULL
      AND guest.conf_value <> ''
      AND guest.conf_value <> nobody.conf_value
      AND EXISTS (
        SELECT 1 FROM entity guest_entity
          INNER JOIN drumate guest_drumate ON guest_drumate.id = guest_entity.id
          WHERE guest_entity.id = guest.conf_value
            AND guest_entity.ident = 'guest'
            AND guest_drumate.username = 'guest'
      )
      AND c.uid NOT IN (nobody.conf_value, guest.conf_value)
      AND c.status = 'ok', 1, 0
    ) AS signed_in
  FROM cookie c
  LEFT JOIN entity e ON e.id = c.uid
  LEFT JOIN drumate d ON d.id = e.id
  LEFT JOIN domain o ON o.id = e.dom_id
  LEFT JOIN sys_conf nobody ON nobody.conf_key = 'nobody_id'
  LEFT JOIN sys_conf guest ON guest.conf_key = 'guest_id'
  WHERE c.id = ?
    AND c.mtime + c.ttl > UNIX_TIMESTAMP()
  LIMIT 1
`;

const OTAK_QUERY = `
  SELECT JSON_UNQUOTE(JSON_EXTRACT(value, '$.id')) AS session_id
  FROM authn
  WHERE token = ?
    AND ctime >= UNIX_TIMESTAMP() - ${OTAK_TTL_SECONDS}
  LIMIT 1
`;

const OTAK_EXPIRE_QUERY = `
  DELETE FROM authn
  WHERE token = ?
    AND ctime < UNIX_TIMESTAMP() - ${OTAK_TTL_SECONDS}
`;

class YellowPageStore {
  constructor({ database } = {}) {
    if (!database || typeof database.await_proc !== "function" ||
      typeof database.await_func !== "function" || typeof database.await_query !== "function") {
      throw new RuntimeError("YELLOW_PAGE_DATABASE_REQUIRED", "Current server-essentials MariaDB operations are required");
    }
    this.database = database;
  }

  async signin(args) {
    return firstRow(await this.database.await_proc("session_signin", args));
  }

  async resolveSession(sid) {
    if (typeof sid !== "string" || sid.length < 16) return null;
    return firstRow(await this.database.await_query(SESSION_QUERY, sid));
  }

  async ensureSession(sid) {
    return firstRow(await this.database.await_proc("session_ensure", sid || null));
  }

  async resolveSessionContext(sid) {
    if (typeof sid !== "string" || sid.length < 16) return null;
    return firstRow(await this.database.await_query(SESSION_CONTEXT_QUERY, sid));
  }

  async storeAuthn(token, value) {
    return this.database.await_proc("authn_store", token, value);
  }

  async resolveOtak(token) {
    if (typeof token !== "string" || token.length !== 22) return null;
    await this.database.await_query(OTAK_EXPIRE_QUERY, token);
    return firstRow(await this.database.await_query(OTAK_QUERY, token));
  }

  async domainPermission(uid, domainId, permission) {
    return scalarFunctionValue(await this.database.await_func("domain_permission", uid, domainId, permission));
  }

  async bindSocket(args) {
    return firstRow(await this.database.await_proc("socket_bind", args));
  }

  async freeSocket(id) {
    return this.database.await_proc("socket_free", id);
  }

  async refreshSockets(ids) {
    return this.database.await_proc("socket_refresh", null, ids);
  }

  async socketRecipients(sessionId) {
    return rows(await this.database.await_proc("socket_list_session", sessionId));
  }

  async socketGet(id) {
    return firstRow(await this.database.await_proc("socket_get", id));
  }
}

module.exports = { OTAK_EXPIRE_QUERY, OTAK_QUERY, OTAK_TTL_SECONDS, SESSION_CONTEXT_QUERY, SESSION_QUERY, YellowPageStore, rows, scalarFunctionValue };
