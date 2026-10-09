"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { CapabilityResolver, DescriptorRegistry, HubAuthorizer, ServiceDispatcher, createAuthorizer } = require("../lib");

const bits = { read: 2, write: 4, delete: 8, admin: 16, owner: 32 };
const permissionValue = (name) => bits[name];
const session = () => ({
  isAuthenticated: () => true,
  uid: () => "a000000000000001",
  identity: () => ({ id: "a000000000000001", domainId: 41, kind: "drumate" })
});

test("Hub scope injects only the server-resolved authorized context", async () => {
  const registry = new DescriptorRegistry({ permissionValue });
  registry.registerDescriptor("fixture", {
    modules: { private: "fixture.js" },
    requires: ["fixture"],
    services: { read: { scope: "hub", permission: { src: "read", capabilities: ["fixture"] } } }
  }, { workdir: "/trusted" });
  const resolver = { async resolveAuthorized(request) { return Object.freeze({ ...request, type: "hub", database_name: "trusted_shard", authorized: true }); } };
  class Worker {
    constructor(options) { this.hub_context = options.hub_context; }
    read(input) { return { hub_context: this.hub_context, client_database: input.database_name }; }
  }
  const dispatcher = new ServiceDispatcher({
    registry,
    authorize: createAuthorizer({ hubAuthorizer: new HubAuthorizer({ resolver, permissionValue }) }),
    capability_resolver: new CapabilityResolver({ providers: { fixture: async () => true } }),
    requireWorker: () => Worker
  });
  const result = await dispatcher.dispatch({ service: "fixture.read", session: session(), input: { hub_id: "b000000000000002", database_name: "attacker" } });
  assert.equal(result.hub_context.database_name, "trusted_shard");
  assert.equal(result.client_database, "attacker");
});

test("cross-Hub MFS authorizes source and destination independently before construction", async () => {
  const registry = new DescriptorRegistry({ permissionValue });
  registry.registerDescriptor("mfs", {
    modules: { private: "mfs.js" },
    requires: ["system-mfs"],
    services: { copy: { scope: "mfs", permission: { src: "read", dest: "write" } } }
  }, { workdir: "/trusted" });
  const source = { hub_id: "b000000000000002", nid: "c000000000000003" };
  const destination = { hub_id: "d000000000000004", nid: "e000000000000005" };
  const calls = [];
  const resolver = {
    async resolveAuthorized(request) {
      calls.push(request);
      if (request.hub_id === destination.hub_id && request.asked_permission === bits.write) throw Object.assign(new Error("denied"), { code: "HUB_PERMISSION_DENIED" });
      return { hub_id: request.hub_id, database_name: `trusted_${request.hub_id}` };
    }
  };
  let constructions = 0;
  class Worker { constructor() { constructions++; } copy() {} }
  const dispatcher = new ServiceDispatcher({
    registry,
    authorize: createAuthorizer({
      hubAuthorizer: new HubAuthorizer({ resolver, permissionValue }),
      mfsPermissionBackend: { async resources() { return { src: [source], dest: [destination] }; }, async effectivePermission() { return 63; } }
    }),
    capability_resolver: new CapabilityResolver({ providers: { "system-mfs": async () => true } }),
    requireWorker: () => Worker
  });
  await assert.rejects(() => dispatcher.dispatch({ service: "mfs.copy", session: session(), input: { sources: [source], destination } }), (error) => error.code === "PERMISSION_DENIED");
  assert.equal(constructions, 0);
  assert.deepEqual(calls.map(({ hub_id, asked_permission, capabilities }) => ({ hub_id, asked_permission, capabilities })), [
    { hub_id: source.hub_id, asked_permission: bits.read, capabilities: ["system-mfs"] },
    { hub_id: destination.hub_id, asked_permission: bits.write, capabilities: ["system-mfs"] }
  ]);
});

test("anonymous, intermediate, nobody and unknown Hub permission fail closed", async () => {
  const authorizer = new HubAuthorizer({ resolver: { async resolveAuthorized() { return {}; } }, permissionValue });
  const request = { hub_id: "b000000000000002", asked_permission: bits.read };
  assert.equal((await authorizer.authorizeResource({ ...request, session: { isAuthenticated: () => false } })).reason, "HUB_AUTHENTICATION_REQUIRED");
  assert.equal((await authorizer.authorizeResource({ ...request, session: { ...session(), identity: () => ({ id: "ffffffffffffffff", domainId: 41, kind: "nobody" }) } })).reason, "HUB_PRINCIPAL_INVALID");
  assert.equal((await authorizer.authorizeResource({ ...request, asked_permission: 64, session: session() })).reason, "HUB_PERMISSION_INVALID");
});

test("Hub service requirements are checked per Hub before global providers and Worker construction", async () => {
  const registry = new DescriptorRegistry({ permissionValue });
  registry.registerDescriptor("fixture", {
    modules: { private: "service/fixture.js" },
    requires: ["platform-only"],
    services: { probe: { scope: "hub", requires: ["hub-schema"], permission: { src: "read", capabilities: ["permission-schema"] } } }
  }, { workdir: "/trusted" });
  const readiness = new Map([["b000000000000002", false], ["c000000000000003", true]]);
  const resolver = {
    async resolveAuthorized(request) {
      assert.deepEqual(request.capabilities, ["permission-schema", "platform-only", "hub-schema"]);
      if (!readiness.get(request.hub_id)) throw Object.assign(new Error("not ready"), { code: "HUB_CAPABILITY_NOT_READY" });
      return { hub_id: request.hub_id, authorized: true };
    }
  };
  let provider_calls = 0;
  let constructions = 0;
  class Worker { constructor() { constructions++; } probe() { return "ok"; } }
  const dispatcher = new ServiceDispatcher({
    registry,
    authorize: createAuthorizer({ hubAuthorizer: new HubAuthorizer({ resolver, permissionValue }) }),
    capability_resolver: new CapabilityResolver({ providers: { "platform-only": async () => (provider_calls++, true), "hub-schema": async () => (provider_calls++, true) } }),
    requireWorker: () => Worker
  });
  await assert.rejects(() => dispatcher.dispatch({ service: "fixture.probe", session: session(), input: { hub_id: "b000000000000002" } }), (error) => error.code === "PERMISSION_DENIED");
  assert.equal(provider_calls, 0);
  assert.equal(constructions, 0);
  readiness.set("b000000000000002", true);
  assert.equal(await dispatcher.dispatch({ service: "fixture.probe", session: session(), input: { hub_id: "b000000000000002" } }), "ok");
  assert.equal(await dispatcher.dispatch({ service: "fixture.probe", session: session(), input: { hub_id: "c000000000000003" } }), "ok");
  assert.equal(constructions, 2);
});
