const { RuntimeError } = require("./errors");
const crypto = require("crypto");

const SESSION_COOKIE = "regsid";
const SESSION_TTL_SECONDS = 2592000;

function firstRow(value) {
  if (Array.isArray(value)) {
    if (!value.length) return null;
    return firstRow(value[0]);
  }
  return value && typeof value === "object" ? value : null;
}

function parseCookies(header) {
  const cookies = {};
  if (typeof header !== "string") return cookies;
  for (const entry of header.split(";")) {
    const separator = entry.indexOf("=");
    if (separator < 1) continue;
    const name = entry.slice(0, separator).trim();
    const value = entry.slice(separator + 1).trim();
    if (!name) continue;
    try {
      cookies[name] = decodeURIComponent(value);
    } catch (_) {
      cookies[name] = value;
    }
  }
  return cookies;
}

function credentials(input = {}) {
  const value = input && typeof input.vars === "object" && input.vars ? input.vars : input;
  const uid = value.uid || value.ident || value.username;
  if (typeof uid !== "string" || !uid.trim() || typeof value.password !== "string" || !value.password) {
    throw new RuntimeError("INVALID_CREDENTIALS", "Credentials require uid, username or ident and password");
  }
  return {
    uid: uid.trim(),
    username: typeof value.username === "string" && value.username.trim() ? value.username.trim() : undefined,
    password: value.password,
    host: typeof value.host === "string" && value.host.trim() ? value.host.trim() : undefined
  };
}

function identityFrom(row) {
  if (!row || !row.id || !row.domain_id) return null;
  return {
    id: row.id,
    domainId: Number(row.domain_id),
    domain: row.domain || undefined,
    ident: row.ident || row.username || undefined
  };
}

function validSessionId(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{16,64}$/.test(value) ? value : undefined;
}

function createOtak() {
  // The historical client receives a 22-character opaque OTAK. Keep that
  // wire-sized transport credential while never deriving it from `regsid`.
  return crypto.randomBytes(16).toString("base64url");
}

class KernelSession {
  constructor({ store, sid, identity } = {}) {
    if (!store || typeof store.signin !== "function" || typeof store.resolveSession !== "function") {
      throw new RuntimeError("SESSION_STORE_REQUIRED", "A Yellow Page session store is required");
    }
    this.store = store;
    this.sid = sid;
    this._identity = identity || null;
    this._setCookie = null;
  }

  identity() {
    return this._identity;
  }

  isAnonymous() {
    return !this._identity;
  }

  async ensure() {
    if (typeof this.store.ensureSession !== "function") {
      throw new RuntimeError("SESSION_STORE_REQUIRED", "The Yellow Page store must ensure runtime sessions");
    }
    const requested = validSessionId(this.sid);
    const result = firstRow(await this.store.ensureSession(requested));
    if (!result || !validSessionId(result.session_id)) {
      throw new RuntimeError("SESSION_INVALID", "Runtime session could not be allocated");
    }
    const changed = this.sid !== result.session_id;
    this.sid = result.session_id;
    if (!this._identity && typeof this.store.resolveSession === "function") {
      this._identity = identityFrom(await this.store.resolveSession(this.sid));
    }
    if (changed || !requested) this._setCookie = sessionCookie(this.sid);
    return this;
  }

  async authn() {
    if (typeof this.store.storeAuthn !== "function") {
      throw new RuntimeError("SESSION_STORE_REQUIRED", "The Yellow Page store must persist WebSocket transport credentials");
    }
    await this.ensure();
    const token = createOtak();
    await this.store.storeAuthn(token, { id: this.sid, type: "session" });
    return { token };
  }

  async signin(input = {}) {
    const values = credentials(input);
    const result = firstRow(await this.store.signin({ ...values, sid: this.sid }));
    if (!result || result.status !== "ok" || !result.id || !result.session_id) {
      throw new RuntimeError("AUTHENTICATION_FAILED", "Invalid credentials");
    }

    const identity = identityFrom(await this.store.resolveSession(result.session_id));
    if (!identity) {
      throw new RuntimeError("SESSION_INVALID", "Authenticated session could not be resolved");
    }

    this.sid = result.session_id;
    this._identity = identity;
    this._setCookie = sessionCookie(this.sid);
    return {
      authenticated: true,
      identity: { id: identity.id },
      domain: { id: identity.domainId, name: identity.domain }
    };
  }

  responseHeaders() {
    return this._setCookie ? { "set-cookie": this._setCookie } : {};
  }
}

function sessionCookie(sid) {
  return `${SESSION_COOKIE}=${encodeURIComponent(sid)}; Max-Age=${SESSION_TTL_SECONDS}; Path=/; HttpOnly; SameSite=Strict`;
}

class SessionManager {
  constructor({ store } = {}) {
    if (!store || typeof store.resolveSession !== "function") {
      throw new RuntimeError("SESSION_STORE_REQUIRED", "A Yellow Page session store is required");
    }
    this.store = store;
  }

  async fromRequest(request) {
    const cookie = parseCookies(request && request.headers && request.headers.cookie);
    const sid = validSessionId(cookie[SESSION_COOKIE]);
    if (!sid) return new KernelSession({ store: this.store });
    return (await this.fromSessionId(sid)) || new KernelSession({ store: this.store });
  }

  async fromSessionId(sid) {
    const valid = validSessionId(sid);
    if (!valid) return null;
    if (typeof this.store.resolveSessionContext === "function") {
      const context = firstRow(await this.store.resolveSessionContext(valid));
      if (!context || !validSessionId(context.session_id)) return null;
      return new KernelSession({ store: this.store, sid: context.session_id, identity: identityFrom(context) });
    }
    const identity = identityFrom(await this.store.resolveSession(valid));
    return identity ? new KernelSession({ store: this.store, sid: valid, identity }) : null;
  }

  async fromOtak(token) {
    if (typeof this.store.resolveOtak !== "function" || typeof token !== "string" || !token) return null;
    const record = firstRow(await this.store.resolveOtak(token));
    return record && this.fromSessionId(record.session_id);
  }
}

module.exports = {
  KernelSession,
  SESSION_COOKIE,
  SessionManager,
  credentials,
  createOtak,
  firstRow,
  identityFrom,
  parseCookies,
  sessionCookie,
  validSessionId
};
