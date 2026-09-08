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
  constructor({ protocol = "service", cookie = "regsid=real-session" } = {}) {
    this.httpRequest = { headers: { "sec-websocket-protocol": protocol, cookie } };
    this.origin = "http://kernel.test";
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
    async bindSocket({ id, sid }) {
      calls.bind.push({ id, sid });
      return { socket_id: id, session_id: sid };
    },
    async freeSocket(id) { calls.free.push(id); },
    async refreshSockets(ids) { calls.refresh.push(ids); },
    async socketRecipients(sid) { return sid === "real-session" ? [{ socket_id: "socket-a" }] : []; }
  };
}

function sessionManager() {
  return {
    async fromRequest(request) {
      const authenticated = request.headers.cookie === "regsid=real-session";
      return {
        sid: authenticated ? "real-session" : null,
        isAnonymous: () => !authenticated,
        identity: () => authenticated ? { id: "phase4authuser01", domainId: 41 } : null
      };
    }
  };
}

test("WebSocket router requires a real session, preserves service protocol and targets only bound sockets", async () => {
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
    const missingSession = new FakeRequest({ cookie: "" });
    assert.equal(await router.createConnection(missingSession), null);
    assert.equal(missingSession.rejected.code, 4001);

    const unsupported = new FakeRequest({ protocol: "ping" });
    assert.equal(await router.createConnection(unsupported), null);
    assert.equal(unsupported.rejected.code, 4000);

    const request = new FakeRequest();
    const record = await router.createConnection(request);
    assert.equal(request.accepted, "service");
    assert.match(record.id, /^[a-f0-9]{32}$/);
    assert.deepEqual(store.calls.bind, [{ id: record.id, sid: "real-session" }]);
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
