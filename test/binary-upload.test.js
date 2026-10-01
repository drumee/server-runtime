"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { RuntimeError, createServiceServer } = require("../lib");

async function fixture(t, maximum = 128 * 1024) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "runtime-binary-upload-"));
  const calls = { authorize: 0, before: 0, dispatch: 0, inputs: [] };
  const dispatcher = {
    async authorizeRequest({ input }) { calls.authorize += 1; if (input.transfer_id === "denied") throw new RuntimeError("PERMISSION_DENIED", "denied"); },
    async dispatch({ input }) { calls.dispatch += 1; calls.inputs.push(input); assert.equal(fs.existsSync(input.uploaded_file), true); return { size: fs.statSync(input.uploaded_file).size }; }
  };
  const server = createServiceServer({ dispatcher, binary_uploads: { "mfs-transfer.upload_chunk": { directory, max_bytes: maximum, before_receive({ input }) { calls.before += 1; if (input.transfer_id === "wrong-owner") throw new RuntimeError("MFS_TRANSFER_FORBIDDEN", "wrong owner"); } } } });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); fs.rmSync(directory, { recursive: true, force: true }); });
  return { base: `http://127.0.0.1:${server.address().port}`, calls, directory };
}

test("binary service bypasses JSON parsing, stages a bounded tempfile and never exposes its path", async (t) => {
  const env = await fixture(t);
  const body = Buffer.alloc(96 * 1024, 0x7b);
  const response = await fetch(`${env.base}/-/svc/mfs-transfer.upload_chunk?transfer_id=allowed&index=2`, { method: "POST", headers: { "content-type": "application/octet-stream" }, body });
  const envelope = await response.json();
  assert.equal(response.status, 200); assert.equal(envelope.data.size, body.length);
  assert.equal(env.calls.authorize, 1); assert.equal(env.calls.before, 1); assert.equal(env.calls.dispatch, 1);
  assert.equal(JSON.stringify(envelope).includes(env.directory), false);
  assert.deepEqual(fs.readdirSync(env.directory), []);
});

test("structured JSON remains limited to 64 KiB", async (t) => {
  const env = await fixture(t);
  const response = await fetch(`${env.base}/-/svc/probe.echo`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ value: "x".repeat(70 * 1024) }) });
  assert.equal(response.status, 400); assert.equal((await response.json()).code, "REQUEST_BODY_INVALID");
  assert.equal(env.calls.dispatch, 0);
});

test("oversized and unauthorized binary bodies are rejected before worker execution", async (t) => {
  const env = await fixture(t, 64 * 1024);
  const oversized = await fetch(`${env.base}/-/svc/mfs-transfer.upload_chunk?transfer_id=allowed&index=0`, { method: "POST", headers: { "content-type": "application/octet-stream" }, body: Buffer.alloc(64 * 1024 + 1) });
  assert.equal(oversized.status, 413); assert.equal((await oversized.json()).code, "UPLOAD_CHUNK_TOO_LARGE");
  const denied = await fetch(`${env.base}/-/svc/mfs-transfer.upload_chunk?transfer_id=denied&index=0`, { method: "POST", headers: { "content-type": "application/octet-stream" }, body: Buffer.alloc(32 * 1024) });
  assert.equal(denied.status, 403); assert.equal(env.calls.dispatch, 0); assert.deepEqual(fs.readdirSync(env.directory), []);
  const wrong_owner = await fetch(`${env.base}/-/svc/mfs-transfer.upload_chunk?transfer_id=wrong-owner&index=0`, { method: "POST", headers: { "content-type": "application/octet-stream" }, body: Buffer.alloc(32 * 1024) });
  assert.equal(wrong_owner.status, 403); assert.equal(env.calls.dispatch, 0); assert.deepEqual(fs.readdirSync(env.directory), []);
});

test("an interrupted binary request removes its partial tempfile", async (t) => {
  const env = await fixture(t);
  const url = new URL(`${env.base}/-/svc/mfs-transfer.upload_chunk?transfer_id=allowed&index=0`);
  await new Promise((resolve) => {
    const request = http.request(url, { method: "POST", headers: { "content-type": "application/octet-stream", "content-length": 100000 } });
    request.on("error", resolve); request.write(Buffer.alloc(1024)); request.destroy();
  });
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(env.calls.dispatch, 0); assert.deepEqual(fs.readdirSync(env.directory), []);
});
