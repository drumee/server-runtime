const { RuntimeError } = require("./errors");
const { firstRow } = require("./session");

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
    e.id,
    e.dom_id AS domain_id,
    o.name AS domain,
    d.username AS ident
  FROM cookie c
  INNER JOIN entity e ON e.id = c.uid
  INNER JOIN drumate d ON d.id = e.id
  INNER JOIN domain o ON o.id = e.dom_id
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
    d.username AS ident
  FROM cookie c
  LEFT JOIN entity e ON e.id = c.uid
  LEFT JOIN drumate d ON d.id = e.id
  LEFT JOIN domain o ON o.id = e.dom_id
  WHERE c.id = ?
    AND c.mtime + c.ttl > UNIX_TIMESTAMP()
  LIMIT 1
`;

const OTAK_QUERY = `
  SELECT JSON_UNQUOTE(JSON_EXTRACT(value, '$.id')) AS session_id
  FROM authn
  WHERE token = ?
  LIMIT 1
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

module.exports = { OTAK_QUERY, SESSION_CONTEXT_QUERY, SESSION_QUERY, YellowPageStore, rows, scalarFunctionValue };
