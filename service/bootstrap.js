/*
 * Generic worker behind the historical `bootstrap.plugin` service.
 *
 * It deliberately knows only a FrontendPluginResolver injected by the runtime
 * host. It contains no Team endpoint, UI layout or application policy.
 */
module.exports = class BootstrapWorker {
  constructor({ pluginResolver } = {}) {
    this.pluginResolver = pluginResolver;
  }

  async plugin(input = {}) {
    if (!this.pluginResolver || typeof this.pluginResolver.resolve !== "function") {
      throw new Error("Frontend plugin resolver is not configured");
    }
    return this.pluginResolver.resolve(input.name);
  }
};
