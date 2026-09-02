const fs = require("fs");
const path = require("path");
const { RuntimeError } = require("./errors");

function logicalPluginName(name) {
  if (typeof name !== "string" || !name.trim()) {
    throw new RuntimeError("PLUGIN_NAME_REQUIRED", "A plugin logical name is required");
  }
  const normalized = name.trim().replace(path.extname(name.trim()), "");
  if (normalized.includes("/") || normalized.includes("\\") || normalized === "." || normalized === "..") {
    throw new RuntimeError("INVALID_PLUGIN_NAME", `Invalid plugin name ${name}`);
  }
  return normalized;
}

class FrontendPluginResolver {
  constructor({ roots = [] } = {}) {
    this.roots = roots.map((root) => ({
      directory: root.directory,
      publicPrefix: root.publicPrefix || "/-/plugins"
    }));
  }

  resolve(name) {
    const plugin = logicalPluginName(name);
    for (const root of this.roots) {
      const indexFile = path.join(root.directory, plugin, "index.json");
      if (!fs.existsSync(indexFile)) continue;
      let metadata;
      try {
        metadata = JSON.parse(fs.readFileSync(indexFile, "utf8"));
      } catch (error) {
        throw new RuntimeError("PLUGIN_INDEX_INVALID", `Invalid plugin index ${indexFile}`, error.message);
      }
      if (!metadata || typeof metadata.entry !== "string" || !metadata.entry) {
        throw new RuntimeError("PLUGIN_ENTRY_MISSING", `Plugin ${plugin} has no entry in ${indexFile}`);
      }
      if (metadata.entry.includes("..") || path.isAbsolute(metadata.entry)) {
        throw new RuntimeError("PLUGIN_ENTRY_INVALID", `Plugin ${plugin} has an invalid entry`);
      }
      return { path: path.posix.join(root.publicPrefix.replace(/\\/g, "/"), plugin, metadata.entry) };
    }
    throw new RuntimeError("PLUGIN_NOT_FOUND", `Plugin ${plugin} was not found`);
  }
}

module.exports = { FrontendPluginResolver, logicalPluginName };
