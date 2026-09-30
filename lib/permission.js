const { RuntimeError } = require("./errors");

function resolvePermission(permission, permissionValue) {
  if (!permission || typeof permission !== "object" || Array.isArray(permission)) {
    throw new RuntimeError("INVALID_PERMISSION", "A service permission object is required");
  }

  const resolved = { ...permission };
  for (const key of ["src", "dest"]) {
    if (typeof resolved[key] === "string") {
      if (typeof permissionValue !== "function") {
        throw new RuntimeError(
          "PERMISSION_CONVERTER_REQUIRED",
          "String permissions require the current server-essentials permissionValue converter"
        );
      }
      const value = permissionValue(resolved[key]);
      if (value == null) {
        throw new RuntimeError("INVALID_PERMISSION", `Unknown permission ${resolved[key]}`);
      }
      resolved[key] = value;
    }
  }
  return resolved;
}

function fastCheckName(permission) {
  if (!permission || typeof permission !== "object") return undefined;
  return permission.fast_check || (permission.preproc && permission.preproc.fast_check);
}

async function authorizeFastPath({ permission }) {
  if (fastCheckName(permission) === "public-api") return { granted: true, mode: "public-api" };
  return { granted: false, mode: "unconfigured" };
}

async function authorizeMfs(resolved, backend) {
  if (!backend || typeof backend.resources !== "function" || typeof backend.effectivePermission !== "function") {
    return { granted: false, mode: "mfs", reason: "MFS_PERMISSION_BACKEND_REQUIRED" };
  }
  const session = resolved && resolved.session;
  const uid = session && typeof session.uid === "function" ? session.uid() : null;
  if (!uid) return { granted: false, mode: "mfs", reason: "TRUSTED_SESSION_UID_REQUIRED" };
  const resources = await backend.resources(resolved);
  for (const side of ["src", "dest"]) {
    const asked = Number(resolved.permission[side] || 0);
    if (!asked) continue;
    const nodes = resources && Array.isArray(resources[side]) ? resources[side] : [];
    if (!nodes.length) return { granted: false, mode: "mfs", side, reason: "RESOURCE_REQUIRED" };
    for (const node of nodes) {
      if (!node || !node.hub_id || !node.nid) {
        return { granted: false, mode: "mfs", side, reason: "RESOURCE_IDENTITY_REQUIRED" };
      }
      const effective = Number(await backend.effectivePermission(uid, node) || 0);
      if ((effective & asked) !== asked) return { granted: false, mode: "mfs", side, node, asked, effective };
    }
  }
  return { granted: true, mode: "mfs", uid };
}

function createAuthorizer({ domainAuthorizer, mfsPermissionBackend } = {}) {
  return async function authorize(resolved) {
    const fastPath = await authorizeFastPath(resolved);
    if (fastPath.granted) return fastPath;

    if (resolved && resolved.permission && resolved.permission.scope === "domain") {
      if (!domainAuthorizer || typeof domainAuthorizer.authorize !== "function") {
        return { granted: false, mode: "domain", reason: "DOMAIN_AUTHORIZER_REQUIRED" };
      }
      return domainAuthorizer.authorize(resolved);
    }

    if (resolved && resolved.permission && resolved.permission.scope === "mfs") {
      return authorizeMfs(resolved, mfsPermissionBackend);
    }

    return { granted: false, mode: "unsupported", reason: "UNSUPPORTED_PERMISSION_SCOPE" };
  };
}

module.exports = { resolvePermission, fastCheckName, authorizeFastPath, authorizeMfs, createAuthorizer };
