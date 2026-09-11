const assert = require("assert/strict");
const { EventEmitter } = require("events");
const fs = require("fs");
const http = require("http");
const path = require("path");
const test = require("node:test");
const { PushBus, WebSocketPushRouter } = require("../lib");

class FakeConnection extends EventEmitter {
  constructor() {
    super();
    this.connected = true;
    this.sent = [];
  }

  sendUTF(value) {
    this.sent.push(JSON.parse(value));
  }

  drop() {
    this.connected = false;
    this.emit("close");
  }
}

class FakeRequest {
  constructor({ protocol = "service", token = "valid-otak", origin = "http://kernel.test", host = "kernel.test", cookie } = {}) {
    this.httpRequest = {
      url: token == null ? "/-/websocket/" : `/-/websocket/?otak=${encodeURIComponent(token)}`,
      headers: { "sec-websocket-protocol": protocol, host, ...(cookie ? { cookie } : {}) }
    };
    this.origin = origin;
    this.rejected = null;
    this.connection = new FakeConnection();
  }

  accept(protocol) {
    this.accepted = protocol;
    return this.connection;
  }

  reject(code, message) {
    this.rejected = { code, message };
  }
}

class FakeWebSocketServer extends EventEmitter {}

class FakeRedisStore {
  static reset() {
    this.published = [];
    this.subscriber = {
      subscribed: null,
      async subscribe(channel, callback) { this.subscribed = { channel, callback }; },
      async unsubscribe() {},
      async quit() {}
    };
  }

  async init() {}

  static getLiveUpdateChannel() { return "KERNEL_PHASE44_PUSH"; }

  static async getSubscribe() { return this.subscriber; }

  static async sendData(payload, dest) { this.published.push({ payload, dest }); }
}

function socketStore() {
  const calls = { bind: [], free: [], refresh: [] };
  return {
    calls,
    async bindSocket({ id, token }) {
      calls.bind.push({ id, token });
      if (!/^(valid-otak|anonymous-otak)$/.test(token)) return { failed: 1 };
      return { socket_id: id, session_id: token === "anonymous-otak" ? "anonymous-session" : "real-session" };
    },
    async freeSocket(id) { calls.free.push(id); },
    async refreshSockets(ids) { calls.refresh.push(ids); },
    async socketRecipients(sid) { return sid === "real-session" ? [{ socket_id: "socket-a" }] : []; }
  };
}

function sessionManager() {
  return {
    async fromSessionId(sid) {
      if (!/^(real-session|anonymous-session)$/.test(sid)) return null;
      const authenticated = sid === "real-session";
      return {
        sid,
        isAnonymous: () => !authenticated,
        identity: () => authenticated ? { id: "phase4authuser01", domainId: 41 } : null
      };
    }
  };
}

test("WebSocket router requires an OTAK, preserves service protocol and targets only bound sockets", async () => {
  FakeRedisStore.reset();
  const store = socketStore();
  const logs = [];
  const router = new WebSocketPushRouter({
    httpServer: http.createServer(),
    sessionManager: sessionManager(),
    socketStore: store,
    redisStore: FakeRedisStore,
    WebSocketServer: FakeWebSocketServer,
    logger: { info: (message) => logs.push(message), warn: () => {} },
    clock: { now: () => 20000 }
  });
  await router.start();
  try {
    const missingToken = new FakeRequest({ token: null });
    assert.equal(await router.createConnection(missingToken), null);
    assert.equal(missingToken.rejected.code, 401);

    const invalidToken = new FakeRequest({ token: "invalid-otak" });
    assert.equal(await router.createConnection(invalidToken), null);
    assert.equal(invalidToken.rejected.code, 401);

    const unsupported = new FakeRequest({ protocol: "ping" });
    assert.equal(await router.createConnection(unsupported), null);
    assert.equal(unsupported.rejected.code, 400);

    const foreignOrigin = new FakeRequest({ origin: "https://foreign.example", host: "kernel.test" });
    assert.equal(await router.createConnection(foreignOrigin), null);
    assert.equal(foreignOrigin.rejected.code, 403);

    const request = new FakeRequest();
    const record = await router.createConnection(request);
    assert.equal(request.accepted, "service");
    assert.match(record.id, /^[a-f0-9]{32}$/);
    assert.deepEqual(store.calls.bind.at(-1), { id: record.id, token: "valid-otak" });
    assert.deepEqual(request.connection.sent[0], {
      service: "sys.hello",
      data: { socket_id: record.id, user: { id: "phase4authuser01" } }
    });

    assert.equal(await router.routeDownstream(JSON.stringify({
      source: "other-runtime",
      dest: { socket_id: record.id },
      payload: { service: "hello.push", data: { message: "Hello over WebSocket" } }
    })), 1);
    assert.deepEqual(request.connection.sent.at(-1), { service: "hello.push", data: { message: "Hello over WebSocket" } });
    assert.equal(await router.routeDownstream("not-json"), 0);
    assert.equal(await router.routeDownstream(JSON.stringify({ dest: { socket_id: "other-socket" }, payload: { service: "hello.push" } })), 0);

    request.connection.emit("message", { type: "utf8", utf8Data: JSON.stringify(["sys.ping", { type: "checkConnection" }]) });
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(request.connection.sent.at(-1), { service: "sys.ping", data: { type: "checkConnection", ok: true } });

    await router.updateConnectionsState();
    assert.deepEqual(store.calls.refresh, [[record.id]]);
    request.connection.emit("close");
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(store.calls.free, [record.id]);
    assert.ok(logs.some((entry) => entry.includes("kernel push delivered hello.push sockets=1")));
  } finally {
    await router.stop();
  }
});

test("WebSocket router accepts anonymous and configured external OTAK connections without a regsid credential", async () => {
  FakeRedisStore.reset();
  const store = socketStore();
  const router = new WebSocketPushRouter({
    httpServer: http.createServer(),
    sessionManager: sessionManager(),
    socketStore: store,
    redisStore: FakeRedisStore,
    WebSocketServer: FakeWebSocketServer,
    logger: { info() {}, warn() {} },
    allowedOrigins: ["https://approved.example"]
  });
  await router.start();
  try {
    const anonymous = new FakeRequest({ token: "anonymous-otak", cookie: "regsid=must-not-be-authoritative" });
    const anonymousRecord = await router.createConnection(anonymous);
    assert.equal(anonymousRecord.sessionId, "anonymous-session");
    assert.deepEqual(anonymous.connection.sent[0].data.user, {});
    assert.equal(anonymous.httpRequest.url.includes("regsid"), false);

    const external = new FakeRequest({ token: "valid-otak", origin: "https://approved.example", host: "runtime.example" });
    const externalRecord = await router.createConnection(external);
    assert.equal(externalRecord.sessionId, "real-session");
  } finally {
    await router.stop();
  }
});

test("PushBus resolves the caller session to socket recipients and publishes through Redis only", async () => {
  FakeRedisStore.reset();
  const bus = new PushBus({
    redisStore: FakeRedisStore,
    socketStore: { async socketRecipients(sid) { return sid === "real-session" ? [{ socket_id: "socket-a" }] : []; } },
    logger: { info() {} }
  });
  assert.deepEqual(await bus.publish({
    service: "hello.push",
    sessionId: "real-session",
    data: { message: "Hello over WebSocket" }
  }), { published: true, service: "hello.push", recipients: 1 });
  assert.deepEqual(FakeRedisStore.published, [{
    payload: { service: "hello.push", data: { message: "Hello over WebSocket" } },
    dest: { socket_id: "socket-a" }
  }]);
  assert.deepEqual(await bus.publish({ service: "hello.push", sessionId: "missing" }), {
    published: false, service: "hello.push", recipients: 0
  });
});

test("WebSocket runtime production code has no Team, Hub or MFS dependency", () => {
  const root = path.join(__dirname, "..", "lib");
  const source = fs.readdirSync(root, { recursive: true })
    .filter((file) => file.endsWith(".js"))
    .map((file) => fs.readFileSync(path.join(root, file), "utf8"))
    .join("\n")
    .replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "");
  assert.doesNotMatch(source, /require\([^)]*(?:server-team|ui-team|DrumeeMFS|Finder|WindowManager)/);
  assert.doesNotMatch(source, /\b(?:get_hub|conference|socket_set_state|drumate_online_state)\b/);
});
