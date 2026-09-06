const { RuntimeError } = require("./errors");

function sessionIdentity(session) {
  if (!session) return null;
  if (typeof session.identity === "function") return session.identity();
  return session.identity || null;
}

class DomainAuthorizer {
  constructor({ store } = {}) {
    if (!store || typeof store.domainPermission !== "function") {
      throw new RuntimeError("DOMAIN_STORE_REQUIRED", "A Yellow Page Domain permission store is required");
    }
    this.store = store;
  }

  async authorize({ permission, session }) {
    if (!permission || permission.scope !== "domain") {
      return { granted: false, mode: "domain", reason: "DOMAIN_SCOPE_REQUIRED" };
    }
    if (!session || (typeof session.isAnonymous === "function" ? session.isAnonymous() : session.isAnonymous)) {
      return { granted: false, mode: "domain", reason: "AUTHENTICATION_REQUIRED" };
    }

    const identity = sessionIdentity(session);
    if (!identity || !identity.id || !identity.domainId) {
      return { granted: false, mode: "domain", reason: "DOMAIN_IDENTITY_REQUIRED" };
    }

    const required = [permission.src, permission.dest].filter((value) => value != null);
    for (const requested of required) {
      const grant = await this.store.domainPermission(identity.id, identity.domainId, requested);
      if (!(Number(grant) > 0)) {
        return {
          granted: false,
          mode: "domain",
          procedure: "domain_permission",
          reason: "DOMAIN_PERMISSION_DENIED"
        };
      }
    }

    return { granted: true, mode: "domain", procedure: "domain_permission" };
  }
}

module.exports = { DomainAuthorizer };
