const fs = require("fs");
const path = require("path");
const { RuntimeError } = require("./errors");
const { resolvePermission } = require("./permission");

function parseService(service) {
  if (typeof service !== "string") {
    throw new RuntimeError("WRONG_SERVICE_FORMAT", "Service must be a module.method string");
  }
  const value = service.replace(/[?&].*$/, "");
  const parts = value.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new RuntimeError("WRONG_SERVICE_FORMAT", `<${service}> is not a valid service format`);
  }
  return { module: parts[0], method: parts[1], service: value };
}

function isAnonymous(session) {
  if (!session) return true;
  if (typeof session.isAnonymous === "function") return Boolean(session.isAnonymous());
  return Boolean(session.isAnonymous);
}

class DescriptorRegistry {
  constructor({ permissionValue } = {}) {
    this.permissionValue = permissionValue;
    this.modules = new Map();
  }

  registerDescriptor(name, descriptor, { workdir } = {}) {
    if (!name || typeof name !== "string") {
      throw new RuntimeError("INVALID_DESCRIPTOR", "Descriptor name is required");
    }
    if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) {
      throw new RuntimeError("INVALID_DESCRIPTOR", `${name} must be an object`);
    }
    if (!descriptor.modules || typeof descriptor.modules !== "object") {
      throw new RuntimeError("INVALID_DESCRIPTOR", `${name} must declare modules`);
    }
    if (!descriptor.services || typeof descriptor.services !== "object") {
      throw new RuntimeError("INVALID_DESCRIPTOR", `${name} must declare services`);
    }

    const services = {};
    for (const [method, service] of Object.entries(descriptor.services)) {
      if (!service || typeof service !== "object" || Array.isArray(service)) {
        throw new RuntimeError("INVALID_DESCRIPTOR", `${name}.${method} must be an object`);
      }
      services[method] = {
        ...service,
        permission: resolvePermission(service.permission, this.permissionValue)
      };
    }
    const normalized = {
      ...descriptor,
      modules: { ...descriptor.modules },
      services,
      workdir: workdir || descriptor.workdir
    };
    this.modules.set(name, normalized);
    return normalized;
  }

  registerDirectory(directory, { force = false } = {}) {
    if (!fs.existsSync(directory)) {
      throw new RuntimeError("ACL_DIRECTORY_NOT_FOUND", `ACL directory does not exist: ${directory}`);
    }
    const registered = [];
    for (const entry of fs.readdirSync(directory).sort()) {
      if (!entry.endsWith(".json")) continue;
      const name = entry.replace(/\.json$/i, "");
      if (this.modules.has(name) && !force) {
        throw new RuntimeError("DUPLICATE_MODULE", `Module ${name} is already registered`);
      }
      const file = path.join(directory, entry);
      let descriptor;
      try {
        descriptor = JSON.parse(fs.readFileSync(file, "utf8"));
      } catch (error) {
        throw new RuntimeError("INVALID_DESCRIPTOR", `Could not parse ${file}`, error.message);
      }
      this.registerDescriptor(name, descriptor, { workdir: path.dirname(directory) });
      registered.push(name);
    }
    return registered;
  }

  resolve(service, session) {
    const parsed = parseService(service);
    const descriptor = this.modules.get(parsed.module);
    if (!descriptor) {
      throw new RuntimeError("MODULE_NOT_FOUND", `Could not find module '${parsed.module}'`);
    }
    const definition = descriptor.services[parsed.method];
    if (!definition) {
      throw new RuntimeError("SERVICE_NOT_FOUND", `Service ${parsed.service} is not registered`);
    }
    const access = isAnonymous(session) ? "public" : "private";
    const implementation = descriptor.modules[access];
    if (!implementation) {
      throw new RuntimeError("MODULE_NOT_FOUND", `${parsed.module} has no ${access} implementation`);
    }
    if (!descriptor.workdir && !path.isAbsolute(implementation)) {
      throw new RuntimeError("WORKDIR_REQUIRED", `${parsed.module} requires a workdir for a relative implementation`);
    }
    const workerPath = path.resolve(descriptor.workdir || "/", implementation.replace(/\.js$/i, "")) + ".js";
    return {
      access,
      descriptor,
      method: definition.method || parsed.method,
      permission: { ...definition.permission, scope: definition.scope },
      service: parsed.service,
      logService: Boolean(definition.log),
      workerPath
    };
  }
}

module.exports = { DescriptorRegistry, parseService };
