/*
 * Generic worker behind the historical `bootstrap.plugin` service.
 *
 * It deliberately knows only a FrontendPluginResolver injected by the runtime
 * host. It contains no Team endpoint, UI layout or application policy.
 */
module.exports = class BootstrapWorker {
  constructor({ pluginResolver, session } = {}) {
    this.pluginResolver = pluginResolver;
    this.session = session;
  }

  async plugin(input = {}) {
    if (!this.pluginResolver || typeof this.pluginResolver.resolve !== "function") {
      throw new Error("Frontend plugin resolver is not configured");
    }
    return this.pluginResolver.resolve(input.name);
  }

  async authn() {
    if (!this.session || typeof this.session.authn !== "function") {
      throw new Error("Runtime session transport authorization is not configured");
    }
    return this.session.authn();
  }
};
