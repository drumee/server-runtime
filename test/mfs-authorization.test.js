"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { RuntimeOutput, createAuthorizer, videoRequest } = require("../lib");

const uid = "a000000000000001";
const source = { hub_id: "b000000000000002", nid: "c000000000000003" };
const destination = { hub_id: "d000000000000004", nid: "e000000000000005" };

test("runtime owns MFS permission comparison and fails closed", async () => {
  const calls = [];
  const backend = {
    resources({ input }) { return { src: input.sources || [input.node], dest: input.destination ? [input.destination] : [] }; },
    effectivePermission(actor, node) { calls.push([actor, node]); return node === destination ? 4 : 9; }
  };
  const authorize = createAuthorizer({ mfsPermissionBackend: backend });
  const resolved = { service: "mfs.move", permission: { scope: "mfs", src: 8, dest: 4 }, input: { sources: [source], destination }, session: { uid: () => uid } };
  assert.equal((await authorize(resolved)).granted, true);
  assert.deepEqual(calls.map(([actor]) => actor), [uid, uid]);
  assert.equal((await createAuthorizer()(resolved)).granted, false);
  assert.equal((await authorize({ ...resolved, session: {}, input: { ...resolved.input, uid } })).granted, false);
  assert.equal((await authorize({ permission: { scope: "unknown" } })).reason, "UNSUPPORTED_PERMISSION_SCOPE");
});

test("public and domain authorization branches remain intact", async () => {
  const domainAuthorizer = { authorize: async () => ({ granted: true, mode: "domain" }) };
  const authorize = createAuthorizer({ domainAuthorizer });
  assert.equal((await authorize({ permission: { fast_check: "public-api" } })).mode, "public-api");
  assert.equal((await authorize({ permission: { scope: "domain" } })).mode, "domain");
  assert.equal((await createAuthorizer()({ permission: { scope: "domain" } })).granted, false);
});

test("Input-compatible video route normalization selects only known services", () => {
  assert.deepEqual(videoRequest("/-/vdo/c000000000000003/b000000000000002/master.m3u8"), { service: "video.master", input: { nid: source.nid, hub_id: source.hub_id } });
  assert.deepEqual(videoRequest("/-/vdo/c000000000000003/b000000000000002/stream-2/playlist.m3u8"), { service: "video.stream", input: { nid: source.nid, hub_id: source.hub_id, serial: 2 } });
  assert.deepEqual(videoRequest("/-/vdo/c000000000000003/b000000000000002/stream-2/segment-7.ts"), { service: "video.segment", input: { nid: source.nid, hub_id: source.hub_id, serial: 2, segment: 7 } });
  assert.equal(videoRequest("/-/vdo/c000000000000003/b000000000000002/arbitrary-generator"), null);
});

test("RuntimeOutput limits byte writes to small control artifacts", () => {
  const response = { headersSent: false, writableEnded: false, writeHead(status, headers) { this.status = status; this.headers = headers; this.headersSent = true; }, end(body) { this.body = body; this.writableEnded = true; } };
  new RuntimeOutput({ response }).write("#EXTM3U", "application/x-mpegURL");
  assert.equal(response.body.toString(), "#EXTM3U");
  const large = { headersSent: false, writableEnded: false, writeHead() {}, end() {} };
  assert.throws(() => new RuntimeOutput({ response: large }).write(Buffer.alloc(1024 * 1024 + 1)), (error) => error.code === "OUTPUT_CONTROL_ARTIFACT_TOO_LARGE");
});
