"use strict";

const { RuntimeError } = require("./errors");

const HUB_ID = /^[a-f0-9]{16}$/i;

class HubAuthorizer {
  constructor({ resolver, permissionValue } = {}) {
    if (!resolver || typeof resolver.resolveAuthorized !== "function") throw new RuntimeError("HUB_RESOLVER_REQUIRED", "Hub authorization requires an injected lifecycle resolver");
    if (typeof permissionValue !== "function") throw new RuntimeError("PERMISSION_CONVERTER_REQUIRED", "Hub authorization requires the current server-essentials permissionValue converter");
    this.resolver = resolver;
    this.permission_bits = new Set(["read", "write", "delete", "admin", "owner"].map((name) => Number(permissionValue(name))));
    if (this.permission_bits.size !== 5 || [...this.permission_bits].some((value) => !Number.isInteger(value) || value <= 0)) {
      throw new RuntimeError("PERMISSION_CONVERTER_INVALID", "Hub authorization received invalid canonical permission values");
    }
  }

  principal(session) {
    if (!session || typeof session.isAuthenticated !== "function" || !session.isAuthenticated()) return { error: "HUB_AUTHENTICATION_REQUIRED" };
    const principal = typeof session.identity === "function" ? session.identity() : typeof session.principal === "function" ? session.principal() : null;
    const uid = typeof session.uid === "function" ? session.uid() : principal && principal.id;
    if (!principal || !uid || ["nobody", "guest"].includes(principal.kind) || !principal.domainId) return { error: "HUB_PRINCIPAL_INVALID" };
    return { principal, uid };
  }

  async authorizeResource({ session, hub_id, asked_permission, capabilities = [] } = {}) {
    const identity = this.principal(session);
    if (identity.error) return { granted: false, mode: "hub", reason: identity.error };
    if (typeof hub_id !== "string" || !HUB_ID.test(hub_id)) return { granted: false, mode: "hub", reason: "HUB_SELECTION_REQUIRED" };
    const asked = Number(asked_permission);
    if (!this.permission_bits.has(asked)) return { granted: false, mode: "hub", reason: "HUB_PERMISSION_INVALID" };
    try {
      const hub_context = await this.resolver.resolveAuthorized({
        hub_id: hub_id.toLowerCase(),
        uid: identity.uid,
        organisation_id: Number(identity.principal.domainId),
        asked_permission: asked,
        capabilities: Array.isArray(capabilities) ? capabilities : []
      });
      return { granted: true, mode: "hub", uid: identity.uid, hub_context };
    } catch (error) {
      return { granted: false, mode: "hub", reason: error.code || "HUB_PERMISSION_DENIED" };
    }
  }

  authorize(resolved = {}) {
    const selector = resolved.permission && resolved.permission.selector || "hub_id";
    return this.authorizeResource({
      session: resolved.session,
      hub_id: resolved.input && resolved.input[selector],
      asked_permission: resolved.permission && resolved.permission.src,
      capabilities: resolved.permission && resolved.permission.capabilities
    });
  }
}

module.exports = { HUB_ID, HubAuthorizer };
