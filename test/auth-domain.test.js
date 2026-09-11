const assert = require("assert/strict");
const childProcess = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const test = require("node:test");

const {
  DomainAuthorizer,
  KernelSession,
  NOBODY_UID,
  SESSION_COOKIE,
  SessionManager,
  SESSION_SELECTOR_HEADER,
  YellowPageStore,
  corsHeaders,
  createAuthorizer
} = require("../lib");
const { scalarFunctionValue } = require("../lib/yellow-page-store");

const root = path.resolve(__dirname, "../../../..");

function nobodyContext(session_id, status = "new") {
  return {
    session_id,
    uid: NOBODY_UID,
    id: NOBODY_UID,
    domain_id: 41,
    domain: "phase4.kernel.test",
    ident: "nobody",
    nobody_id: NOBODY_UID,
    guest_id: "phase4guest00001",
    status,
    signed_in: 0
  };
}

function drumateContext(session_id, { status = "ok", signed_in = 1 } = {}) {
  return {
    session_id,
    uid: "phase4authuser01",
    id: "phase4authuser01",
    domain_id: 41,
    domain: "phase4.kernel.test",
    ident: "phase4-auth",
    nobody_id: NOBODY_UID,
    guest_id: "phase4guest00001",
    status,
    signed_in
  };
}

test("Yellow Page store invokes the historical session_signin and domain_permission objects", async () => {
  const calls = [];
  const store = new YellowPageStore({
    database: {
      async await_proc(name, input) {
        calls.push({ kind: "procedure", name, input });
        return [{ status: "ok", id: "phase4authuser01", session_id: "session-phase4-0001" }];
      },
      async await_func(name, ...args) {
        calls.push({ kind: "function", name, args });
        return 2;
      },
      async await_query(sql, sid) {
        calls.push({ kind: "query", sql, sid });
        return [{ id: "phase4authuser01", domain_id: 41, domain: "phase4.kernel.test" }];
      }
    }
  });

  const login = await store.signin({ uid: "phase4-auth@kernel.test", password: "test-password" });
  const session = await store.resolveSession("session-phase4-0001");
  const permission = await store.domainPermission("phase4authuser01", 41, 2);
  const ensured = await store.ensureSession();
  await store.storeAuthn("abcdefghijklmnopqrstuv", { id: "session-phase4-0001", type: "session" });
  const otak = await store.resolveOtak("abcdefghijklmnopqrstuv");
  assert.equal(login.session_id, "session-phase4-0001");
  assert.equal(session.domain_id, 41);
  assert.equal(permission, 2);
  assert.equal(ensured.session_id, "session-phase4-0001");
  assert.equal(otak.domain_id, 41);
  assert.deepEqual(calls[0], {
    kind: "procedure",
    name: "session_signin",
    input: { uid: "phase4-auth@kernel.test", password: "test-password" }
  });
  assert.deepEqual(calls[2], {
    kind: "function",
    name: "domain_permission",
    args: ["phase4authuser01", 41, 2]
  });
  assert.deepEqual(calls[3], { kind: "procedure", name: "session_ensure", input: null });
  assert.deepEqual(calls[4], {
    kind: "procedure",
    name: "authn_store",
    input: "abcdefghijklmnopqrstuv"
  });
});

test("Yellow Page store adapts the current server-essentials function row shape", () => {
  assert.equal(scalarFunctionValue({ "domain_permission( 'phase4authuser01', 41, 2)": 2 }), 2);
  assert.equal(scalarFunctionValue(2), 2);
});

test("Phase 4 target SQL retains the historical domain_permission bitmask expression", () => {
  const historical = fs.readFileSync(
    path.join(root, "sources/schemas/yellow_page/procedures/domain/permission.sql"),
    "utf8"
  );
  const target = fs.readFileSync(
    path.join(root, "target/os/schemas/yellow-page-auth/phase4-schema.sql"),
    "utf8"
  );
  const bitmask = /SELECT\s+privilege\s*&\s*_perm\s+FROM\s+privilege/i;
  assert.match(historical, bitmask);
  assert.match(target, bitmask);
  assert.match(target, /RETURN\s+IFNULL\(_res,\s*0\)/i);
});

test("real-session abstraction accepts credentials, creates regsid and never exposes its value in data", async () => {
  const calls = [];
  const store = {
    async ensureSession(sid) {
      calls.push({ ensure: sid });
      return nobodyContext("session-phase4-0001");
    },
    async signin(input) {
      calls.push(input);
      return { status: "ok", id: "phase4authuser01", session_id: "session-phase4-0001" };
    },
    async resolveSession(sid) {
      assert.equal(sid, "session-phase4-0001");
      return drumateContext(sid);
    },
    async resolveSessionContext(sid) {
      assert.equal(sid, "session-phase4-0001");
      return calls.some((entry) => entry && entry.uid) ? drumateContext(sid) : nobodyContext(sid);
    }
  };
  const session = new KernelSession({ store });
  const result = await session.signin({ vars: { ident: "phase4-auth@kernel.test", password: "test-password" } });
  assert.equal(session.isAnonymous(), false);
  assert.deepEqual(result, {
    authenticated: true,
    identity: { id: "phase4authuser01" },
    domain: { id: 41, name: "phase4.kernel.test" }
  });
  assert.equal(Object.hasOwn(result, "session_id"), false);
  assert.match(session.responseHeaders()["set-cookie"], new RegExp(`^${SESSION_COOKIE}=`));
  assert.equal(session.responseHeaders()[SESSION_COOKIE], "session-phase4-0001");
  assert.deepEqual(calls[0], { ensure: undefined });
  assert.deepEqual(calls[1], {
    uid: "phase4-auth@kernel.test",
    username: undefined,
    password: "test-password",
    host: undefined,
    sid: "session-phase4-0001"
  });
});

test("session manager keeps resolved anonymous and authenticated regsid contexts distinct", async () => {
  const manager = new SessionManager({
    store: {
      async signin() {},
      async resolveSession(sid) {
        if (sid !== "accepted-session-id") return null;
        return { id: "phase4authuser01", domain_id: 41, domain: "phase4.kernel.test" };
      },
      async resolveSessionContext(sid) {
        if (sid === "accepted-session-id") return drumateContext(sid);
        if (sid === "anonymous-session-id") return nobodyContext(sid);
        return null;
      }
    }
  });
  const accepted = await manager.fromRequest({ headers: { cookie: "other=1; regsid=accepted-session-id" } });
  const anonymous = await manager.fromRequest({ headers: { cookie: "regsid=anonymous-session-id" } });
  const rejected = await manager.fromRequest({ headers: { cookie: "regsid=unknown-session-id" } });
  assert.equal(accepted.isAnonymous(), false);
  assert.equal(accepted.identity().id, "phase4authuser01");
  assert.equal(anonymous.sid, "anonymous-session-id");
  assert.equal(anonymous.isAnonymous(), true);
  assert.equal(rejected.isAnonymous(), true);
});

test("historical x-param authorization bridge validates session context and rejects conflicts", async () => {
  const manager = new SessionManager({
    store: {
      async signin() {},
      async resolveSession() { return null; },
      async resolveSessionContext(sid) {
        if (sid === "authorized-session-0001") return drumateContext(sid);
        if (sid === "anonymous-session-0001") return nobodyContext(sid);
        return null;
      }
    }
  });
  const headers = {
    [SESSION_SELECTOR_HEADER]: "regsid",
    "x-param-regsid": "authorized-session-0001"
  };
  const authenticated = await manager.fromRequest({ headers });
  assert.equal(authenticated.contextSource, "authorization");
  assert.equal(authenticated.hasCookieContext, false);
  assert.equal(authenticated.sid, "authorized-session-0001");
  assert.equal(authenticated.identity().id, "phase4authuser01");

  const encoded = await manager.fromRequest({
    headers: { [SESSION_SELECTOR_HEADER]: "regsid", "x-param-regsid": "authorized%2Dsession%2D0001" }
  });
  assert.equal(encoded.sid, "authorized-session-0001");

  const directHistoricalFallback = await manager.fromRequest({
    headers: { "x-param-regsid": "authorized-session-0001" }
  });
  assert.equal(directHistoricalFallback.sid, "authorized-session-0001");

  const standardAuthorizationOnly = await manager.fromRequest({
    headers: { authorization: "Bearer authorized-session-0001" }
  });
  assert.equal(standardAuthorizationOnly.sid, undefined);

  const anonymous = await manager.fromRequest({
    headers: { [SESSION_SELECTOR_HEADER]: "regsid", "x-param-regsid": "anonymous-session-0001" }
  });
  assert.equal(anonymous.contextSource, "authorization");
  assert.equal(anonymous.isAnonymous(), true);

  const matching = await manager.fromRequest({
    headers: { cookie: "regsid=authorized-session-0001", ...headers }
  });
  assert.equal(matching.contextSource, "authorization");
  assert.equal(matching.hasCookieContext, true);

  await assert.rejects(
    manager.fromRequest({ headers: { cookie: "regsid=authorized-session-0001", [SESSION_SELECTOR_HEADER]: "regsid", "x-param-regsid": "anonymous-session-0001" } }),
    (error) => error.code === "SESSION_CONTEXT_CONFLICT"
  );
  await assert.rejects(
    manager.fromRequest({ headers: { [SESSION_SELECTOR_HEADER]: "regsid", "x-param-regsid": "unknown-session-000000" } }),
    (error) => error.code === "SESSION_CONTEXT_INVALID"
  );
  await assert.rejects(
    manager.fromRequest({ headers: { [SESSION_SELECTOR_HEADER]: "hub-session", "x-param-hub-session": "authorized-session-0001" } }),
    (error) => error.code === "SESSION_CONTEXT_INVALID"
  );
  await assert.rejects(
    manager.fromRequest({ headers: { [SESSION_SELECTOR_HEADER]: "regsid", "x-param-regsid": "not-a-valid-session" } }),
    (error) => error.code === "SESSION_CONTEXT_INVALID"
  );
});

test("bootstrap transport authorization ensures regsid then stores a non-regsid OTAK", async () => {
  const calls = [];
  const store = {
    async signin() {},
    async resolveSession() { return null; },
    async ensureSession(sid) {
      calls.push({ operation: "ensure", sid });
      return nobodyContext("new-runtime-session-000000000000");
    },
    async resolveSessionContext(sid) { return nobodyContext(sid); },
    async storeAuthn(token, value) {
      calls.push({ operation: "authn_store", token, value });
    }
  };
  const session = new KernelSession({ store });
  const result = await session.authn();
  assert.match(result.token, /^[A-Za-z0-9_-]{22}$/);
  assert.notEqual(result.token, session.sid);
  assert.equal(session.sid, "new-runtime-session-000000000000");
  assert.match(session.responseHeaders()["set-cookie"], /^regsid=/);
  assert.equal(session.responseHeaders().regsid, session.sid);
  assert.deepEqual(calls[0], { operation: "ensure", sid: undefined });
  assert.deepEqual(calls[1].value, { id: session.sid, type: "session" });
  assert.equal(calls[1].token, result.token);
});

test("allowlisted cross-site bootstrap may read only the historical regsid response hand-off", () => {
  const headers = corsHeaders({ headers: { origin: "https://app.external.test" } }, ["https://app.external.test"]);
  assert.equal(headers["access-control-expose-headers"], "regsid");
  assert.equal(headers["access-control-allow-origin"], "https://app.external.test");
  assert.deepEqual(corsHeaders({ headers: { origin: "https://foreign.example" } }, ["https://app.external.test"]), {});
});

test("session principals keep nobody, guest, OTP and authentication state distinct", async () => {
  const contexts = new Map([
    ["anonymous-session-0001", nobodyContext("anonymous-session-0001")],
    ["otp-session-0000000001", drumateContext("otp-session-0000000001", { status: "otp", signed_in: 0 })],
    ["guest-session-00000001", {
      session_id: "guest-session-00000001",
      uid: "phase4guest00001",
      id: "phase4guest00001",
      domain_id: 41,
      domain: "phase4.kernel.test",
      ident: "guest",
      nobody_id: NOBODY_UID,
      guest_id: "phase4guest00001",
      // The guest is deliberately `ok`: unsigned state must be derived from
      // the provisioned guest identity, not an artificial guest status.
      status: "ok",
      signed_in: 0,
      guest_configured: 1
    }],
    ["system-session-0000001", {
      session_id: "system-session-0000001",
      uid: "phase4system0001",
      id: "phase4system0001",
      domain_id: 41,
      domain: "phase4.kernel.test",
      ident: "system",
      nobody_id: NOBODY_UID,
      guest_id: "phase4guest00001",
      status: "system",
      signed_in: 0
    }]
  ]);
  const manager = new SessionManager({
    store: {
      async signin() {},
      async resolveSession(sid) { return contexts.get(sid) || null; },
      async resolveSessionContext(sid) { return contexts.get(sid) || null; }
    }
  });

  const anonymous = await manager.fromSessionId("anonymous-session-0001");
  const otp = await manager.fromSessionId("otp-session-0000000001");
  const guest = await manager.fromSessionId("guest-session-00000001");
  const system = await manager.fromSessionId("system-session-0000001");
  assert.equal(anonymous.identity().id, NOBODY_UID);
  assert.equal(anonymous.principal().kind, "nobody");
  assert.equal(anonymous.isAnonymous(), true);
  assert.equal(anonymous.isAuthenticated(), false);
  assert.equal(otp.identity().id, "phase4authuser01");
  assert.equal(otp.principal().kind, "drumate");
  assert.equal(otp.isAnonymous(), false);
  assert.equal(otp.isAuthenticated(), false);
  assert.equal(otp.status(), "otp");
  assert.equal(guest.identity().id, "phase4guest00001");
  assert.equal(guest.isGuest(), true);
  assert.equal(guest.isAuthenticated(), false);
  assert.notEqual(guest.identity().id, anonymous.identity().id);
  assert.equal(system.principal().kind, "system");
  assert.notEqual(system.identity().id, anonymous.identity().id);
});

test("a missing or inconsistent guest configuration fails authentication closed", async () => {
  const missingGuest = {
    ...drumateContext("missing-guest-session-0001", { status: "ok", signed_in: 1 }),
    guest_id: null,
    guest_configured: 0
  };
  const inconsistentGuest = {
    ...drumateContext("inconsistent-guest-session-01", { status: "ok", signed_in: 1 }),
    guest_id: NOBODY_UID,
    guest_configured: 0
  };
  const manager = new SessionManager({
    store: {
      async signin() {},
      async resolveSession() { return null; },
      async resolveSessionContext(sid) {
        return sid === missingGuest.session_id ? missingGuest : inconsistentGuest;
      }
    }
  });
  const missing = await manager.fromSessionId(missingGuest.session_id);
  const inconsistent = await manager.fromSessionId(inconsistentGuest.session_id);
  assert.equal(missing.principal().kind, "drumate");
  assert.equal(missing.isAuthenticated(), false);
  assert.equal(inconsistent.isAuthenticated(), false);
});

test("legacy NULL uid contexts are repaired to the provisioned nobody principal without resetting OTP", async () => {
  let value = { session_id: "legacy-session-0000001", status: "new" };
  const store = {
    async signin() {},
    async resolveSession() { return value; },
    async resolveSessionContext() { return value; },
    async ensureSession(sid) {
      assert.equal(sid, "legacy-session-0000001");
      value = nobodyContext(sid);
      return value;
    }
  };
  const manager = new SessionManager({ store });
  const repaired = await manager.fromSessionId("legacy-session-0000001");
  assert.equal(repaired.identity().id, NOBODY_UID);
  assert.equal(repaired.isAnonymous(), true);

  const otp = drumateContext("legacy-session-0000001", { status: "otp", signed_in: 0 });
  value = otp;
  const preserved = await manager.fromSessionId("legacy-session-0000001");
  assert.equal(preserved.identity().id, "phase4authuser01");
  assert.equal(preserved.isAuthenticated(), false);
});

test("Domain authorization requires signed-in state even when an OTP session has a principal", async () => {
  const calls = [];
  const authorizer = new DomainAuthorizer({
    store: { async domainPermission(...args) { calls.push(args); return 2; } }
  });
  const otp = {
    isAnonymous: () => false,
    isAuthenticated: () => false,
    identity: () => ({ id: "phase4authuser01", domainId: 41 })
  };
  const result = await authorizer.authorize({ permission: { scope: "domain", src: 2 }, session: otp });
  assert.deepEqual(result, { granted: false, mode: "domain", reason: "AUTHENTICATION_REQUIRED" });
  assert.deepEqual(calls, []);
});

test("scope domain uses domain_permission and does not activate a hub branch", async () => {
  const calls = [];
  const authorizer = createAuthorizer({
    domainAuthorizer: new DomainAuthorizer({
      store: {
        async domainPermission(uid, domainId, permission) {
          calls.push({ uid, domainId, permission });
          return permission === 2 ? 2 : 0;
        }
      }
    })
  });
  const identity = { id: "phase4authuser01", domainId: 41 };
  const allowed = await authorizer({
    permission: { scope: "domain", src: 2 },
    session: { isAnonymous: () => false, identity: () => identity }
  });
  const denied = await authorizer({
    permission: { scope: "domain", src: 2 },
    session: { isAnonymous: () => true }
  });
  const deferredHub = await authorizer({
    permission: { scope: "hub", src: 2 },
    session: { isAnonymous: () => false, identity: () => identity }
  });
  assert.deepEqual(allowed, { granted: true, mode: "domain", procedure: "domain_permission" });
  assert.equal(denied.granted, false);
  assert.equal(denied.reason, "AUTHENTICATION_REQUIRED");
  assert.deepEqual(deferredHub, { granted: false, mode: "unconfigured" });
  assert.deepEqual(calls, [{ uid: "phase4authuser01", domainId: 41, permission: 2 }]);
});

test("bootstrap.authn remains a Domain-scoped public transport fast path without a business privilege", async () => {
  let domainChecks = 0;
  const authorizer = createAuthorizer({
    domainAuthorizer: {
      async authorize() {
        domainChecks++;
        return { granted: false, mode: "domain" };
      }
    }
  });
  const result = await authorizer({
    permission: { scope: "domain", src: 0, fast_check: "public-api" },
    session: { isAnonymous: () => true }
  });
  assert.deepEqual(result, { granted: true, mode: "public-api" });
  assert.equal(domainChecks, 0);
});

test("DomainAuthorizer preserves mandatory src and optional dest check_domain semantics", async () => {
  const calls = [];
  const authorizer = new DomainAuthorizer({
    store: {
      async domainPermission(uid, domainId, permission) {
        calls.push({ uid, domainId, permission });
        return new Map([[2, 2], [4, 4], [8, 0]]).get(permission);
      }
    }
  });
  const session = {
    isAnonymous: () => false,
    identity: () => ({ id: "phase4authuser01", domainId: 41 })
  };
  const cases = [
    {
      name: "no src or dest",
      permission: { scope: "domain" },
      granted: false,
      reason: "DOMAIN_SOURCE_REQUIRED",
      requested: []
    },
    {
      name: "dest only",
      permission: { scope: "domain", dest: 4 },
      granted: false,
      reason: "DOMAIN_SOURCE_REQUIRED",
      requested: []
    },
    {
      name: "src allowed with no dest",
      permission: { scope: "domain", src: 2 },
      granted: true,
      requested: [2]
    },
    {
      name: "src denied with no dest",
      permission: { scope: "domain", src: 8 },
      granted: false,
      reason: "DOMAIN_PERMISSION_DENIED",
      requested: [8]
    },
    {
      name: "src and dest allowed",
      permission: { scope: "domain", src: 2, dest: 4 },
      granted: true,
      requested: [2, 4]
    },
    {
      name: "src allowed and dest denied",
      permission: { scope: "domain", src: 2, dest: 8 },
      granted: false,
      reason: "DOMAIN_PERMISSION_DENIED",
      requested: [2, 8]
    },
    {
      name: "src denied and dest allowed",
      permission: { scope: "domain", src: 8, dest: 4 },
      granted: false,
      reason: "DOMAIN_PERMISSION_DENIED",
      requested: [8]
    }
  ];

  for (const scenario of cases) {
    calls.length = 0;
    const result = await authorizer.authorize({ permission: scenario.permission, session });
    assert.equal(result.granted, scenario.granted, scenario.name);
    assert.equal(result.reason, scenario.reason, scenario.name);
    assert.deepEqual(calls.map(({ permission }) => permission), scenario.requested, scenario.name);
  }
});

test("Phase 4 fixture injects only a shell-derived SHA-512 fingerprint into SQL", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "phase4-fixture-"));
  const capture = path.join(directory, "fixture.sql");
  const mariadb = path.join(directory, "mariadb");
  const password = "fixture-password-with-'sql-sensitive-characters";
  const fingerprint = crypto.createHash("sha512").update(password).digest("hex");
  const fixture = path.join(root, "target/os/schemas/yellow-page-auth/phase4-fixture.sh");

  fs.writeFileSync(mariadb, "#!/bin/sh\ncat > \"$PHASE4_FIXTURE_SQL_CAPTURE\"\n");
  fs.chmodSync(mariadb, 0o755);
  try {
    const result = childProcess.spawnSync("bash", [fixture], {
      encoding: "utf8",
      env: {
        ...process.env,
        MARIADB_DATABASE: "yp",
        MARIADB_ROOT_PASSWORD: "fixture-root-password",
        PHASE4_TEST_PASSWORD: password,
        PHASE4_FIXTURE_SQL_CAPTURE: capture,
        PATH: `${directory}:${process.env.PATH}`
      }
    });
    assert.equal(result.status, 0, result.stderr);
    const sql = fs.readFileSync(capture, "utf8");
    assert.equal(sql.includes(password), false);
    assert.equal(sql.includes(fingerprint), true);
    assert.doesNotMatch(sql, /SET @phase4_test_password/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
