const { RuntimeError } = require("./errors");

function recipients(value) {
  if (!value) return [];
  const list = Array.isArray(value) ? value : [value];
  return list.filter((entry) => {
    if (typeof entry === "string") return Boolean(entry);
    return entry && typeof entry === "object" && typeof (entry.socket_id || entry.id) === "string";
  });
}

class PushBus {
  constructor({ redisStore, socketStore, logger = console } = {}) {
    if (!redisStore || typeof redisStore.sendData !== "function") {
      throw new RuntimeError("REDIS_PUSH_REQUIRED", "A RedisStore-compatible push transport is required");
    }
    if (!socketStore || typeof socketStore.socketRecipients !== "function") {
      throw new RuntimeError("SOCKET_STORE_REQUIRED", "A socket/session store is required");
    }
    this.redisStore = redisStore;
    this.socketStore = socketStore;
    this.logger = logger;
  }

  async publish({ service, data = {}, dest, sessionId, options, model } = {}) {
    if (typeof service !== "string" || !/^[a-z0-9_-]+\.[a-z0-9_.-]+$/i.test(service)) {
      throw new RuntimeError("PUSH_SERVICE_INVALID", "A push service must be a module.method string");
    }

    const targets = recipients(dest).length
      ? recipients(dest)
      : recipients(sessionId && await this.socketStore.socketRecipients(sessionId));
    if (!targets.length) {
      return { published: false, service, recipients: 0 };
    }

    const payload = { service, data };
    if (options !== undefined) payload.options = options;
    if (model !== undefined) payload.model = model;
    await this.redisStore.sendData(payload, targets.length === 1 ? targets[0] : targets);
    if (this.logger && typeof this.logger.info === "function") {
      this.logger.info(`kernel push published ${service} recipients=${targets.length}`);
    }
    return { published: true, service, recipients: targets.length };
  }
}

module.exports = { PushBus, recipients };
