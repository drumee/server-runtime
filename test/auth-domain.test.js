const assert = require("assert/strict");
const test = require("node:test");

const {
  DomainAuthorizer,
  KernelSession,
  SESSION_COOKIE,
  SessionManager,
  YellowPageStore,
  createAuthorizer
} = require("../lib");
const { scalarFunctionValue } = require("../lib/yellow-page-store");

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
  assert.equal(login.session_id, "session-phase4-0001");
  assert.equal(session.domain_id, 41);
  assert.equal(permission, 2);
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
});

test("Yellow Page store adapts the current server-essentials function row shape", () => {
  assert.equal(scalarFunctionValue({ "domain_permission( 'phase4authuser01', 41, 2)": 2 }), 2);
  assert.equal(scalarFunctionValue(2), 2);
});

test("real-session abstraction accepts credentials, creates regsid and never exposes its value in data", async () => {
  const calls = [];
  const store = {
    async signin(input) {
      calls.push(input);
      return { status: "ok", id: "phase4authuser01", session_id: "session-phase4-0001" };
    },
    async resolveSession(sid) {
      assert.equal(sid, "session-phase4-0001");
      return { id: "phase4authuser01", domain_id: 41, domain: "phase4.kernel.test" };
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
  assert.deepEqual(calls[0], {
    uid: "phase4-auth@kernel.test",
    username: undefined,
    password: "test-password",
    host: undefined,
    sid: undefined
  });
});

test("session manager accepts only a resolved historical regsid cookie", async () => {
  const manager = new SessionManager({
    store: {
      async signin() {},
      async resolveSession(sid) {
        if (sid !== "accepted-session-id") return null;
        return { id: "phase4authuser01", domain_id: 41, domain: "phase4.kernel.test" };
      }
    }
  });
  const accepted = await manager.fromRequest({ headers: { cookie: "other=1; regsid=accepted-session-id" } });
  const rejected = await manager.fromRequest({ headers: { cookie: "regsid=unknown-session-id" } });
  assert.equal(accepted.isAnonymous(), false);
  assert.equal(accepted.identity().id, "phase4authuser01");
  assert.equal(rejected.isAnonymous(), true);
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
