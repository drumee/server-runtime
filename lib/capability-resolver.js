const { RuntimeError } = require("./errors");

class CapabilityResolver {
  constructor({ providers = {} } = {}) {
    this.providers = providers instanceof Map ? new Map(providers) : new Map(Object.entries(providers));
  }

  register(name, provider) {
    if (typeof name !== "string" || !name || typeof provider !== "function") throw new RuntimeError("INVALID_CAPABILITY_PROVIDER", "A capability provider requires a non-empty name and function");
    this.providers.set(name, provider);
  }

  async requireAll(required = [], context = {}) {
    for (const name of [...new Set(required)]) {
      const provider = this.providers.get(name);
      if (!provider) throw new RuntimeError("CAPABILITY_UNAVAILABLE", `Required capability '${name}' is unavailable`, { capability: name, status: "unavailable" });
      const result = await provider({ ...context, capability: name, hub_context: context.hub_context || null, hub_contexts: context.hub_contexts || null });
      if (result !== true && (!result || result.available !== true)) {
        throw new RuntimeError("CAPABILITY_UNAVAILABLE", `Required capability '${name}' is unavailable for this context`, { capability: name, status: result && result.status || "unavailable" });
      }
    }
  }
}

module.exports = { CapabilityResolver };
