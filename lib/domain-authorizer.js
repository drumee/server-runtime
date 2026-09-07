const { RuntimeError } = require("./errors");

function sessionIdentity(session) {
  if (!session) return null;
  if (typeof session.identity === "function") return session.identity();
  return session.identity || null;
}

function isGranted(grant) {
  const value = Number(grant);
  return Number.isFinite(value) && value !== 0;
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

    // Historical Acl.check_domain() starts with a failed source check and a
    // satisfied destination check. A Domain descriptor therefore cannot grant
    // without a source privilege, while destination remains an optional second
    // bitmask check.
    if (permission.src == null) {
      return { granted: false, mode: "domain", reason: "DOMAIN_SOURCE_REQUIRED" };
    }

    const sourceGrant = await this.store.domainPermission(identity.id, identity.domainId, permission.src);
    if (!isGranted(sourceGrant)) {
      return {
        granted: false,
        mode: "domain",
        procedure: "domain_permission",
        reason: "DOMAIN_PERMISSION_DENIED"
      };
    }

    if (permission.dest != null) {
      const destinationGrant = await this.store.domainPermission(identity.id, identity.domainId, permission.dest);
      if (!isGranted(destinationGrant)) {
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
