const assert = require("assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const test = require("node:test");

const {
  DescriptorRegistry,
  FrontendPluginResolver,
  RuntimeError,
  ServiceDispatcher,
  authorizeFastPath,
  parseService
} = require("../lib");
const { permissionValue } = require("../../../../sources/server-essentials/lib/lex/permission");
const { privilegeValue } = require("../../../../sources/server-essentials/lib/lex/privilege");

const fixture = (...parts) => path.join(__dirname, "fixtures", ...parts);

function registry() {
  const value = new DescriptorRegistry({ permissionValue });
  value.registerDirectory(fixture("acl"));
  return value;
}

test("current server-essentials permission and privilege semantics are used", () => {
  assert.equal(permissionValue("write"), 0b0000100);
  assert.equal(privilegeValue("write"), 0b0000111);
  // `get` is not a named alias in either current table. The current Essentials
  // helper deliberately returns its zero sentinel rather than throwing.
  assert.equal(permissionValue("get"), 0);
  assert.equal(privilegeValue("get"), 0);
});

test("descriptor registration validates malformed ACL data", () => {
  const value = new DescriptorRegistry({ permissionValue });
  assert.throws(
    () => value.registerDirectory(fixture("acl")),
    (error) => error instanceof RuntimeError && error.code === "INVALID_PERMISSION"
  );
  assert.throws(
    () => value.registerDescriptor("broken", { services: {} }),
    (error) => error.code === "INVALID_DESCRIPTOR"
  );
});

test("module.method parsing and public/private resolution follow ACL descriptors", () => {
  const value = new DescriptorRegistry({ permissionValue });
  value.registerDescriptor("probe", JSON.parse(fs.readFileSync(fixture("acl", "probe.json"))), {
    workdir: fixture("acl")
  });
  assert.deepEqual(parseService("probe.public_status?x=1"), {
    module: "probe", method: "public_status", service: "probe.public_status"
  });
  assert.equal(value.resolve("probe.public_status", { isAnonymous: () => true }).access, "public");
  assert.equal(value.resolve("probe.private_status", { isAnonymous: () => false }).access, "private");
  assert.throws(() => parseService("probe"), (error) => error.code === "WRONG_SERVICE_FORMAT");
  assert.throws(() => value.resolve("absent.status", {}), (error) => error.code === "MODULE_NOT_FOUND");
  assert.throws(() => value.resolve("probe.absent", {}), (error) => error.code === "SERVICE_NOT_FOUND");
});

test("lazy worker loading caches the class and dispatches without Team policy", async () => {
  const value = new DescriptorRegistry({ permissionValue });
  value.registerDescriptor("probe", JSON.parse(fs.readFileSync(fixture("acl", "probe.json"))), {
    workdir: fixture("acl")
  });
  const workerFile = fixture("workers", "public-worker.js");
  delete require.cache[require.resolve(workerFile)];
  delete global.__phase2PublicWorkerLoads;
  const dispatcher = new ServiceDispatcher({ registry: value, authorize: authorizeFastPath });
  const session = { isAnonymous: () => true };
  const first = await dispatcher.dispatch({ service: "probe.public_status", session, input: { sequence: "one" } });
  const second = await dispatcher.dispatch({ service: "probe.public_status", session, input: { sequence: "two" } });
  assert.equal(first.implementation, "public");
  assert.equal(second.input.sequence, "two");
  assert.equal(global.__phase2PublicWorkerLoads, 1);
  for (const file of ["../lib/dispatcher.js", "../lib/descriptor-registry.js"]) {
    assert.doesNotMatch(fs.readFileSync(path.join(__dirname, file), "utf8"), /secure-share|over-limit|billing/i);
  }
});

test("private resolution is selected for a non-anonymous session", async () => {
  const value = new DescriptorRegistry({ permissionValue });
  value.registerDescriptor("probe", JSON.parse(fs.readFileSync(fixture("acl", "probe.json"))), {
    workdir: fixture("acl")
  });
  const dispatcher = new ServiceDispatcher({
    registry: value,
    authorize: async () => ({ granted: true, mode: "test" })
  });
  const result = await dispatcher.dispatch({
    service: "probe.private_status",
    session: { isAnonymous: () => false },
    input: { source: "test" }
  });
  assert.equal(result.implementation, "private");
});

test("frontend plugin resolver preserves the index.json to public path contract", () => {
  const resolver = new FrontendPluginResolver({
    roots: [{ directory: fixture("plugins"), publicPrefix: "/-/plugins" }]
  });
  assert.deepEqual(resolver.resolve("valid.js"), { path: "/-/plugins/valid/main-fixture.js" });
  assert.throws(() => resolver.resolve("missing"), (error) => error.code === "PLUGIN_NOT_FOUND");
  assert.throws(() => resolver.resolve("invalid"), (error) => error.code === "PLUGIN_INDEX_INVALID");
  assert.throws(() => resolver.resolve("missing-entry"), (error) => error.code === "PLUGIN_ENTRY_MISSING");
  assert.throws(() => resolver.resolve("../escape"), (error) => error.code === "INVALID_PLUGIN_NAME");
});

test("the public-api fast path is explicit and database-free", async () => {
  const decision = await authorizeFastPath({ permission: { src: permissionValue("anonymous"), fast_check: "public-api" } });
  assert.deepEqual(decision, { granted: true, mode: "public-api" });
  const denied = await authorizeFastPath({ permission: { src: permissionValue("read") } });
  assert.deepEqual(denied, { granted: false, mode: "unconfigured" });
  assert.equal(fs.existsSync(path.join(os.tmpdir(), "phase2-no-schema-marker")), false);
});
