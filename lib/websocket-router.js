const crypto = require("crypto");
const http = require("http");
const { RuntimeError } = require("./errors");

const SERVICE_PROTOCOL = "service";
const WATCHDOG_INTERVAL = 15000;

function requestedProtocol(request) {
  const header = request && request.httpRequest && request.httpRequest.headers && request.httpRequest.headers["sec-websocket-protocol"];
  if (typeof header !== "string") return "";
  return header.split(",").map((value) => value.trim()).find(Boolean) || "";
}

function requestHeader(request, name) {
  const headers = request && request.httpRequest && request.httpRequest.headers;
  if (!headers) return undefined;
  return headers[String(name).toLowerCase()];
}

function otakFromRequest(request) {
  const url = request && request.httpRequest && request.httpRequest.url;
  if (typeof url !== "string") return "";
  try {
    return new URL(url, "http://kernel.invalid").searchParams.get("otak") || "";
  } catch (_) {
    return "";
  }
}

function normalizeOrigin(value) {
  if (typeof value !== "string" || !value) return "";
  try {
    return new URL(value).origin;
  } catch (_) {
    return "";
  }
}

function sameRequestOrigin(origin, request) {
  const normalized = normalizeOrigin(origin);
  const host = requestHeader(request, "host");
  if (!normalized || !host) return false;
  const parsed = new URL(normalized);
  const forwardedPort = requestHeader(request, "x-forwarded-port");
  const expectedPort = forwardedPort || new URL(`http://${host}`).port || (parsed.protocol === "https:" ? "443" : "80");
  const actualPort = parsed.port || (parsed.protocol === "https:" ? "443" : "80");
  return parsed.hostname === new URL(`http://${host}`).hostname && actualPort === expectedPort;
}

function originAllowed(request, { allowedOrigins = [], allowMissingOrigin = false } = {}) {
  const origin = request && request.origin || requestHeader(request, "origin");
  if (!origin) return Boolean(allowMissingOrigin);
  if (sameRequestOrigin(origin, request)) return true;
  if (typeof allowedOrigins === "function") return Boolean(allowedOrigins(origin, request && request.httpRequest));
  const accepted = Array.isArray(allowedOrigins) ? allowedOrigins : [allowedOrigins];
  const normalized = normalizeOrigin(origin);
  return accepted.some((entry) => normalizeOrigin(entry) === normalized);
}

function socketId() {
  return crypto.randomBytes(16).toString("hex");
}

function destinationIds(dest) {
  const entries = Array.isArray(dest) ? dest : [dest];
  return entries.map((entry) => {
    if (typeof entry === "string") return entry;
    if (entry && typeof entry === "object") return entry.socket_id || entry.id;
    return null;
  }).filter((id) => typeof id === "string" && id);
}

function websocketServer() {
  return require("websocket").server;
}

class WebSocketPushRouter {
  constructor({ httpServer, sessionManager, socketStore, redisStore, WebSocketServer, logger = console, clock = Date, watchdogInterval = WATCHDOG_INTERVAL, allowedOrigins = [], allowMissingOrigin = false } = {}) {
    if (!httpServer || typeof httpServer.on !== "function") {
      throw new RuntimeError("WEBSOCKET_HTTP_SERVER_REQUIRED", "An HTTP server is required for WebSocket transport");
    }
    if (!sessionManager || typeof sessionManager.fromOtak !== "function") {
      throw new RuntimeError("WEBSOCKET_SESSION_REQUIRED", "An OTAK-aware session manager is required for WebSocket transport");
    }
    if (!socketStore || typeof socketStore.bindSocket !== "function" || typeof socketStore.freeSocket !== "function") {
      throw new RuntimeError("SOCKET_STORE_REQUIRED", "A socket/session store is required");
    }
    if (!redisStore || typeof redisStore.getSubscribe !== "function" || typeof redisStore.getLiveUpdateChannel !== "function") {
      throw new RuntimeError("REDIS_PUSH_REQUIRED", "A RedisStore-compatible subscriber is required");
    }
    this.httpServer = httpServer;
    this.sessionManager = sessionManager;
    this.socketStore = socketStore;
    this.redisStore = redisStore;
    this.WebSocketServer = WebSocketServer;
    this.logger = logger;
    this.clock = clock;
    this.watchdogInterval = watchdogInterval;
    this.allowedOrigins = allowedOrigins;
    this.allowMissingOrigin = allowMissingOrigin;
    this.connections = new Map();
    this.subscriber = null;
    this.server = null;
    this.watchdog = null;
  }

  async start() {
    if (this.server) return this;
    const redis = new this.redisStore();
    if (typeof redis.init !== "function") throw new RuntimeError("REDIS_PUSH_REQUIRED", "RedisStore.init() is required");
    await redis.init();
    this.subscriber = await this.redisStore.getSubscribe();
    await this.subscriber.subscribe(this.redisStore.getLiveUpdateChannel(), (message) => {
      Promise.resolve(this.routeDownstream(message)).catch((error) => this._warn("downstream message ignored", error));
    });

    const Server = this.WebSocketServer || websocketServer();
    this.server = new Server({ httpServer: this.httpServer, autoAcceptConnections: false });
    this.server.on("request", (request) => {
      Promise.resolve(this.createConnection(request)).catch((error) => {
        this._warn("connection refused", error);
        try { request.reject(500, "WebSocket connection failed"); } catch (_) {}
      });
    });
    this.server.on("error", (error) => this._warn("server error", error));
    this.watchdog = setInterval(() => {
      Promise.resolve(this.updateConnectionsState()).catch((error) => this._warn("watchdog failed", error));
    }, this.watchdogInterval);
    return this;
  }

  async createConnection(request) {
    if (requestedProtocol(request) !== SERVICE_PROTOCOL) {
      request.reject(400, "Unsupported WebSocket protocol");
      return null;
    }
    if (!originAllowed(request, this)) {
      request.reject(403, "WebSocket origin is not allowed");
      return null;
    }

    const token = otakFromRequest(request);
    if (!token) {
      request.reject(401, "WebSocket OTAK is required");
      return null;
    }
    const session = await this.sessionManager.fromOtak(token);
    if (!session || !session.sid) {
      request.reject(401, "WebSocket OTAK is invalid");
      return null;
    }

    const connection = request.accept(SERVICE_PROTOCOL, request.origin);
    const id = socketId();
    const bound = await this.socketStore.bindSocket({ id, token });
    if (!bound || bound.failed || !bound.socket_id || bound.session_id !== session.sid) {
      connection.drop(4001, "WebSocket session binding failed");
      return null;
    }

    const identity = typeof session.identity === "function" ? session.identity() : session.identity;
    const authenticated = typeof session.isAuthenticated === "function"
      ? session.isAuthenticated()
      : !(typeof session.isAnonymous === "function" ? session.isAnonymous() : session.isAnonymous);
    const record = { connection, id, sessionId: session.sid, identity, lastSent: 0 };
    this.connections.set(id, record);
    connection.on("message", (message) => {
      Promise.resolve(this.routeUpstream(record, message)).catch((error) => this._warn("upstream message ignored", error));
    });
    connection.once("close", () => {
      Promise.resolve(this.close(id)).catch((error) => this._warn("socket cleanup failed", error));
    });
    this.send(record, {
      service: "sys.hello",
      data: {
        socket_id: id,
        user: authenticated && identity && identity.id ? { id: identity.id } : {}
      }
    });
    this._info(`kernel websocket bound socket=${id}`);
    return record;
  }

  async routeUpstream(record, message) {
    if (!message || message.type !== "utf8") return false;
    let value;
    try {
      value = JSON.parse(message.utf8Data);
    } catch (_) {
      return false;
    }
    const service = Array.isArray(value) ? value[0] : value && value.service;
    const data = Array.isArray(value) ? value[value.length - 1] : value && value.data;
    if (service !== "sys.ping") return false;
    this.send(record, { service: "sys.ping", data: { ...(data && typeof data === "object" ? data : {}), ok: true } });
    return true;
  }

  async routeDownstream(raw) {
    let message;
    try {
      message = typeof raw === "string" ? JSON.parse(raw) : raw;
    } catch (_) {
      return 0;
    }
    if (!message || !message.payload) return 0;
    let delivered = 0;
    for (const id of destinationIds(message.dest)) {
      if (this.sendToId(id, message.payload)) delivered++;
    }
    if (delivered) this._info(`kernel push delivered ${message.payload.service || "unknown"} sockets=${delivered}`);
    return delivered;
  }

  sendToId(id, payload) {
    const record = this.connections.get(id);
    return record ? this.send(record, payload) : false;
  }

  send(record, payload) {
    const connection = record && record.connection;
    if (!connection || connection.connected === false) return false;
    const encoded = JSON.stringify(payload);
    if (typeof connection.sendUTF === "function") connection.sendUTF(encoded);
    else if (typeof connection.send === "function") connection.send(encoded);
    else return false;
    record.lastSent = this.clock.now();
    return true;
  }

  async updateConnectionsState() {
    const ids = [];
    const now = this.clock.now();
    for (const [id, record] of this.connections) {
      if (!record.connection || record.connection.connected === false) {
        await this.close(id);
        continue;
      }
      ids.push(id);
      if (!record.lastSent || now - record.lastSent >= this.watchdogInterval / 2) {
        this.send(record, { service: "sys.keepalive", data: { timestamp: now } });
      }
    }
    if (ids.length && typeof this.socketStore.refreshSockets === "function") await this.socketStore.refreshSockets(ids);
    return ids;
  }

  async close(id) {
    const record = this.connections.get(id);
    if (!record) return false;
    this.connections.delete(id);
    await this.socketStore.freeSocket(id);
    this._info(`kernel websocket closed socket=${id}`);
    return true;
  }

  async stop() {
    if (this.watchdog) clearInterval(this.watchdog);
    this.watchdog = null;
    for (const id of [...this.connections.keys()]) await this.close(id);
    if (this.subscriber) {
      try { await this.subscriber.unsubscribe(this.redisStore.getLiveUpdateChannel()); } catch (_) {}
      try { await this.subscriber.quit(); } catch (_) {}
    }
    this.subscriber = null;
    if (this.server && typeof this.server.shutDown === "function") this.server.shutDown();
    this.server = null;
  }

  _info(message) {
    if (this.logger && typeof this.logger.info === "function") this.logger.info(message);
  }

  _warn(message, error) {
    if (this.logger && typeof this.logger.warn === "function") this.logger.warn(`kernel websocket ${message}: ${error && error.message ? error.message : error}`);
  }
}

function createPushServer(options = {}) {
  const httpServer = options.httpServer || http.createServer((request, response) => {
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ status: "error", code: "WEBSOCKET_ONLY" }));
  });
  const router = new WebSocketPushRouter({ ...options, httpServer });
  return { httpServer, router };
}

module.exports = {
  SERVICE_PROTOCOL,
  WATCHDOG_INTERVAL,
  WebSocketPushRouter,
  createPushServer,
  destinationIds,
  originAllowed,
  otakFromRequest,
  requestedProtocol
};
