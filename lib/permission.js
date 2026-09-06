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

function createAuthorizer({ domainAuthorizer } = {}) {
  return async function authorize(resolved) {
    const fastPath = await authorizeFastPath(resolved);
    if (fastPath.granted) return fastPath;

    if (resolved && resolved.permission && resolved.permission.scope === "domain") {
      if (!domainAuthorizer || typeof domainAuthorizer.authorize !== "function") {
        return { granted: false, mode: "domain", reason: "DOMAIN_AUTHORIZER_REQUIRED" };
      }
      return domainAuthorizer.authorize(resolved);
    }

    return fastPath;
  };
}

module.exports = { resolvePermission, fastCheckName, authorizeFastPath, createAuthorizer };
