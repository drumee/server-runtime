"use strict";

const fs = require("fs");
const path = require("path");

function fail(message) {
  throw new Error(`Invalid runtime schema manifest: ${message}`);
}

function readJson(filename, label) {
  try {
    return JSON.parse(fs.readFileSync(filename, "utf8"));
  } catch (error) {
    fail(`${label} cannot be read: ${error.message}`);
  }
}

function validateSchemaPath(packageRoot, entryPath, label) {
  if (typeof entryPath !== "string" || entryPath.trim() === "") fail(`${label} path must be a non-empty string`);
  if (entryPath !== entryPath.trim() || /[\0\r\n]/.test(entryPath)) fail(`${label} path contains invalid characters`);
  if (path.isAbsolute(entryPath) || /^[A-Za-z]:[\\/]/.test(entryPath)) fail(`${label} path must be package-relative: ${entryPath}`);

  const segments = entryPath.split(/[\\/]+/);
  if (segments.includes("..")) fail(`${label} path traverses outside the package: ${entryPath}`);
  if (segments[0] === "sources" || segments[0] === "target") fail(`${label} path references a repository tree: ${entryPath}`);

  const resolved = path.resolve(packageRoot, entryPath);
  const prefix = `${packageRoot}${path.sep}`;
  if (!resolved.startsWith(prefix)) fail(`${label} path resolves outside the package: ${entryPath}`);
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) fail(`${label} file is missing: ${entryPath}`);
  const real = fs.realpathSync(resolved);
  if (!real.startsWith(prefix)) fail(`${label} file resolves outside the package: ${entryPath}`);
  return resolved;
}

function loadSchemaEntries(packageDirectory, section) {
  const packageRoot = fs.realpathSync(packageDirectory);
  const packageJson = readJson(path.join(packageRoot, "package.json"), "package.json");
  const manifest = readJson(path.join(packageRoot, "schemas", "SCHEMA_MANIFEST.json"), "schemas/SCHEMA_MANIFEST.json");

  if (manifest.owner !== packageJson.name) fail(`owner ${JSON.stringify(manifest.owner)} does not match package name ${JSON.stringify(packageJson.name)}`);
  if (manifest.packageVersion !== packageJson.version) {
    fail(`packageVersion ${JSON.stringify(manifest.packageVersion)} does not match package version ${JSON.stringify(packageJson.version)}`);
  }

  let entries;
  if (section === "install") {
    if (!Array.isArray(manifest.install) || manifest.install.length === 0) fail("install must be a non-empty array");
    const orders = new Set();
    const paths = new Set();
    entries = manifest.install.map((entry, index) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) fail(`install[${index}] must be an object`);
      if (!Number.isInteger(entry.order)) fail(`install[${index}].order must be an integer`);
      if (orders.has(entry.order)) fail(`install order is duplicated: ${entry.order}`);
      if (paths.has(entry.path)) fail(`install path is duplicated: ${entry.path}`);
      orders.add(entry.order);
      paths.add(entry.path);
      return { order: entry.order, path: entry.path };
    }).sort((left, right) => left.order - right.order);
  } else if (section === "upgrade") {
    if (!manifest.upgrade || !Array.isArray(manifest.upgrade.entrypoints) || manifest.upgrade.entrypoints.length === 0) {
      fail("upgrade.entrypoints must be a non-empty array");
    }
    const paths = new Set();
    entries = manifest.upgrade.entrypoints.map((entryPath) => {
      if (paths.has(entryPath)) fail(`upgrade entrypoint is duplicated: ${entryPath}`);
      paths.add(entryPath);
      return { path: entryPath };
    });
  } else {
    fail(`unknown section ${JSON.stringify(section)}; expected install or upgrade`);
  }

  const resolved = entries.map((entry, index) => validateSchemaPath(packageRoot, entry.path, `${section}[${index}]`));
  return { packageRoot, packageJson, manifest, paths: resolved };
}

module.exports = { loadSchemaEntries };
