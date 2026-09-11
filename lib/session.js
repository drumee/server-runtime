const { RuntimeError } = require("./errors");
const crypto = require("crypto");
const { SESSION_COOKIE, sessionAuthorization, validSessionId } = require("./input");

const SESSION_TTL_SECONDS = 2592000;
// Canonical fallback from server-essentials::Constants.ID_NOBODY. Runtime
// operations resolve sys_conf.nobody_id first; this value exists only so a
// misconfigured legacy row can be recognized before the database rejects its
// missing provisioned principal.
const NOBODY_UID = "ffffffffffffffff";

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

function principalFrom(row) {
  if (!row || !row.id || !row.domain_id) return null;
  const uid = row.uid || row.id;
  if (typeof uid !== "string" || !uid) return null;
  const nobodyId = row.nobody_id || NOBODY_UID;
  const guestId = row.guest_id;
  let kind = "drumate";
  if (uid === nobodyId) kind = "nobody";
  else if (typeof guestId === "string" && guestId && uid === guestId && guestConfigurationValid(row)) kind = "guest";
  else if (row.ident === "system" || row.username === "system") kind = "system";
  return {
    id: uid,
    domainId: Number(row.domain_id),
    domain: row.domain || undefined,
    ident: row.ident || row.username || undefined,
    kind
  };
}

function guestConfigurationValid(row) {
  const guestId = row && row.guest_id;
  const nobodyId = row && row.nobody_id || NOBODY_UID;
  if (typeof guestId !== "string" || !guestId || guestId === nobodyId) return false;
  // Store queries expose this explicit provisioning check. Keep the fallback
  // for narrow unit-store seams which predate that field, but never turn a
  // missing or invalid real configuration into an authenticated principal.
  if (row && Object.hasOwn(row, "guest_configured")) {
    return Number(row.guest_configured) === 1 || row.guest_configured === true;
  }
  return true;
}

function identityFrom(row) {
  return principalFrom(row);
}

function signedInFrom(row, principal) {
  if (!principal) return false;
  // A missing/malformed guest configuration is a security configuration
  // failure. Fail every authentication decision closed rather than allowing
  // the provisioned guest UID to be mistaken for a normal Drumate.
  if (!guestConfigurationValid(row)) return false;
  if (row && Object.hasOwn(row, "signed_in")) {
    return Number(row.signed_in) === 1 || row.signed_in === true;
  }
  // Historical session_check_cookie reports an OTP principal but makes it
  // unsigned. Do not infer authentication from any non-nobody UID.
  if (/^otp(?:_pending)?$/i.test(String(row && row.status || ""))) return false;
  return principal.kind === "drumate" && (!row || !row.status || row.status === "ok");
}

function createOtak() {
  // The historical client receives a 22-character opaque OTAK. Keep that
  // wire-sized transport credential while never deriving it from `regsid`.
  return crypto.randomBytes(16).toString("base64url");
}

class KernelSession {
  constructor({ store, sid, identity, signedIn, status, contextSource = "none", hasCookieContext = false } = {}) {
    if (!store || typeof store.signin !== "function" || typeof store.resolveSession !== "function") {
      throw new RuntimeError("SESSION_STORE_REQUIRED", "A Yellow Page session store is required");
    }
    this.store = store;
    this.sid = sid;
    this._principal = identity || null;
    this._signedIn = Boolean(signedIn);
    this._status = status || undefined;
    this._setCookie = null;
    // Safe diagnostic state only: neither value contains a credential.
    this.contextSource = contextSource;
    this.hasCookieContext = Boolean(hasCookieContext);
  }

  identity() {
    return this._principal;
  }

  principal() {
    return this._principal;
  }

  isAnonymous() {
    return !this._principal || this._principal.kind === "nobody";
  }

  isGuest() {
    return Boolean(this._principal && this._principal.kind === "guest");
  }

  isAuthenticated() {
    return this._signedIn;
  }

  signedIn() {
    return this._signedIn;
  }

  status() {
    return this._status;
  }

  _applyContext(row) {
    const principal = principalFrom(row);
    if (!principal) {
      throw new RuntimeError("SESSION_PRINCIPAL_REQUIRED", "Runtime session has no provisioned principal");
    }
    this._principal = principal;
    this._signedIn = signedInFrom(row, principal);
    this._status = row && row.status || undefined;
    return this;
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
    if (typeof this.store.resolveSessionContext === "function") {
      this._applyContext(firstRow(await this.store.resolveSessionContext(this.sid)));
    } else if (typeof this.store.resolveSession === "function") {
      this._applyContext(firstRow(await this.store.resolveSession(this.sid)));
    } else if (!this._principal) {
      throw new RuntimeError("SESSION_PRINCIPAL_REQUIRED", "Runtime session principal could not be resolved");
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
    // The historical procedure can allocate a cookie itself, but the runtime
    // now ensures one principal-bearing session context before every login.
    await this.ensure();
    const result = firstRow(await this.store.signin({ ...values, sid: this.sid }));
    if (!result || !result.session_id) {
      throw new RuntimeError("AUTHENTICATION_FAILED", "Invalid credentials");
    }

    const context = typeof this.store.resolveSessionContext === "function"
      ? firstRow(await this.store.resolveSessionContext(result.session_id))
      : firstRow(await this.store.resolveSession(result.session_id));
    this.sid = result.session_id;
    this._applyContext(context);
    this._setCookie = sessionCookie(this.sid);
    if (result.status === "otp" || result.status === "otp_pending") {
      throw new RuntimeError("AUTHENTICATION_PENDING", "Authentication is pending OTP completion");
    }
    if (result.status !== "ok" || !result.id || !this.isAuthenticated()) {
      throw new RuntimeError("AUTHENTICATION_FAILED", "Invalid credentials");
    }

    return {
      authenticated: true,
      identity: { id: this._principal.id },
      domain: { id: this._principal.domainId, name: this._principal.domain }
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
    const cookieSid = validSessionId(cookie[SESSION_COOKIE]);
    const authorization = sessionAuthorization(request);

    if (cookieSid && authorization.present && cookieSid !== authorization.sid) {
      throw new RuntimeError("SESSION_CONTEXT_CONFLICT", "Cookie and session authorization disagree");
    }
    if (authorization.present) {
      const resolved = await this.fromSessionId(authorization.sid, {
        contextSource: "authorization",
        hasCookieContext: Boolean(cookieSid)
      });
      if (!resolved) {
        throw new RuntimeError("SESSION_CONTEXT_INVALID", "Unknown runtime session authorization");
      }
      return resolved;
    }
    if (!cookieSid) return new KernelSession({ store: this.store });
    return (await this.fromSessionId(cookieSid, {
      contextSource: "cookie",
      hasCookieContext: true
    })) || new KernelSession({ store: this.store });
  }

  async fromSessionId(sid, { contextSource = "session", hasCookieContext = false } = {}) {
    const valid = validSessionId(sid);
    if (!valid) return null;
    if (typeof this.store.resolveSessionContext === "function") {
      let context = firstRow(await this.store.resolveSessionContext(valid));
      if (!context || !validSessionId(context.session_id)) return null;
      let principal = principalFrom(context);
      // session_ensure is also the targeted compatibility repair for a
      // historical cookie row whose uid was NULL. Never turn an OTP principal
      // back into nobody: the procedure updates NULL only.
      if (!principal && typeof this.store.ensureSession === "function") {
        const ensured = firstRow(await this.store.ensureSession(valid));
        if (!ensured || ensured.session_id !== valid) return null;
        context = firstRow(await this.store.resolveSessionContext(valid));
        principal = principalFrom(context);
      }
      if (!principal) return null;
      return new KernelSession({
        store: this.store,
        sid: context.session_id,
        identity: principal,
        signedIn: signedInFrom(context, principal),
        status: context.status,
        contextSource,
        hasCookieContext
      });
    }
    const context = firstRow(await this.store.resolveSession(valid));
    const identity = principalFrom(context);
    return identity ? new KernelSession({
      store: this.store,
      sid: valid,
      identity,
      signedIn: signedInFrom(context, identity),
      status: context && context.status,
      contextSource,
      hasCookieContext
    }) : null;
  }

  async fromOtak(token) {
    if (typeof this.store.resolveOtak !== "function" || typeof token !== "string" || !token) return null;
    const record = firstRow(await this.store.resolveOtak(token));
    return record && this.fromSessionId(record.session_id, { contextSource: "otak" });
  }
}

module.exports = {
  KernelSession,
  NOBODY_UID,
  SESSION_COOKIE,
  SessionManager,
  credentials,
  createOtak,
  firstRow,
  guestConfigurationValid,
  identityFrom,
  principalFrom,
  parseCookies,
  sessionCookie,
  signedInFrom,
  validSessionId
};
