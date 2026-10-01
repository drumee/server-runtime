const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");
const { RuntimeError } = require("./errors");
const { RuntimeOutput } = require("./output");

function statusFor(error) {
  if (!error || !error.code) return 500;
  if (/AUTHENTICATION_FAILED|SESSION(?:_|$)/.test(error.code)) return 401;
  if (error.code === "PERMISSION_DENIED" || /_FORBIDDEN$/.test(error.code)) return 403;
  if (error.code === "UPLOAD_CHUNK_TOO_LARGE") return 413;
  if (/NOT_FOUND/.test(error.code)) return 404;
  if (/FORMAT|INVALID|REQUIRED/.test(error.code)) return 400;
  return 500;
}

function serviceFromPath(pathname) {
  const video = videoRequest(pathname);
  if (video) return video.service;
  const match = pathname.match(/\/(?:svc|vdo|service)\/([^/]+)$/);
  if (!match) throw new RuntimeError("WRONG_SERVICE_FORMAT", `No Drumee service in ${pathname}`);
  return decodeURIComponent(match[1]);
}

function videoRequest(pathname) {
  const match = String(pathname || "").match(/\/(?:-|api\/[^/]+)?\/?vdo\/([a-f0-9]{16})(?:\/([a-f0-9]{16}))?\/(master\.m3u8|stream-(\d+)\/playlist\.m3u8|stream-(\d+)\/segment-(\d+)\.ts)$/i);
  if (!match) return null;
  const input = { nid: match[1].toLowerCase() };
  if (match[2]) input.hub_id = match[2].toLowerCase();
  if (match[3] === "master.m3u8") return { service: "video.master", input };
  input.serial = Number(match[4] || match[5]);
  if (match[6] !== undefined) { input.segment = Number(match[6]); return { service: "video.segment", input }; }
  return { service: "video.stream", input };
}

function normalizedOrigin(value) {
  if (typeof value !== "string" || !value) return "";
  try {
    return new URL(value).origin;
  } catch (_) {
    return "";
  }
}

function corsHeaders(request, allowedOrigins = []) {
  const origin = normalizedOrigin(request && request.headers && request.headers.origin);
  const entries = Array.isArray(allowedOrigins) ? allowedOrigins : [allowedOrigins];
  if (!origin || !entries.some((entry) => normalizedOrigin(entry) === origin)) return {};
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-credentials": "true",
    // `server-core/lib/output.js::cookie` historically emits the selected
    // session value in a response header named by keysel.  The minimal
    // runtime only owns `regsid`; expose precisely that existing hand-off to
    // an allowlisted external bootstrap transport so it can retain it in its
    // private state for the next historical x-param request.
    "access-control-expose-headers": "regsid",
    // x-param-keysel/x-param-regsid is the pinned historical Input
    // authorization bridge. Keep Authorization allowed for generic callers,
    // but it is not interpreted as a session credential by this runtime.
    "access-control-allow-headers": "accept, authorization, content-type, x-param-keysel, x-param-regsid",
    "access-control-allow-methods": "GET, POST, PUT, PATCH, OPTIONS",
    vary: "Origin"
  };
}

function requestBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    let rejected = false;
    request.on("data", (chunk) => {
      if (rejected) return;
      length += chunk.length;
      if (length > 65536) {
        rejected = true;
        chunks.length = 0;
        reject(new RuntimeError("REQUEST_BODY_INVALID", "Service input exceeds 64 KiB"));
        request.resume();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (rejected) return;
      if (!chunks.length) return resolve({});
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          throw new Error("Service input must be an object");
        }
        resolve(parsed);
      } catch (error) {
        reject(new RuntimeError("REQUEST_BODY_INVALID", "Invalid JSON service input", error.message));
      }
    });
    request.on("error", reject);
  });
}

async function requestInput(request, url) {
  const query = { ...(videoRequest(url.pathname) || {}).input, ...Object.fromEntries(url.searchParams.entries()) };
  if (request.method === "POST" || request.method === "PUT" || request.method === "PATCH") {
    return { ...query, ...await requestBody(request) };
  }
  return query;
}

function binaryContentType(request) {
  return /^application\/octet-stream(?:\s*;|$)/i.test(String(request && request.headers && request.headers["content-type"] || ""));
}

function receiveBinary(request, { directory, max_bytes } = {}) {
  const maximum = Number(max_bytes);
  if (!directory || !Number.isInteger(maximum) || maximum < 1) throw new RuntimeError("BINARY_UPLOAD_CONFIG_INVALID", "Binary upload requires a tempfile directory and positive byte limit");
  fs.mkdirSync(directory, { recursive: true });
  const filename = path.join(directory, crypto.randomUUID());
  const declared = Number(request.headers && request.headers["content-length"]);
  if (Number.isFinite(declared) && declared > maximum) {
    request.resume();
    throw new RuntimeError("UPLOAD_CHUNK_TOO_LARGE", "Binary upload exceeds the configured chunk limit");
  }
  return new Promise((resolve, reject) => {
    let received = 0;
    let settled = false;
    const output = fs.createWriteStream(filename, { flags: "wx" });
    const cleanup = (error) => {
      if (settled) return;
      settled = true;
      output.destroy();
      fs.rmSync(filename, { force: true });
      reject(error);
    };
    output.on("error", (error) => cleanup(new RuntimeError("BINARY_UPLOAD_FAILED", "Could not stage binary upload", error.message)));
    output.on("drain", () => request.resume());
    request.on("data", (chunk) => {
      if (settled) return;
      received += chunk.length;
      if (received > maximum) {
        request.resume();
        cleanup(new RuntimeError("UPLOAD_CHUNK_TOO_LARGE", "Binary upload exceeds the configured chunk limit"));
        return;
      }
      if (!output.write(chunk)) request.pause();
    });
    request.once("aborted", () => cleanup(new RuntimeError("BINARY_UPLOAD_ABORTED", "Binary upload was interrupted")));
    request.once("error", (error) => cleanup(new RuntimeError("BINARY_UPLOAD_FAILED", "Binary upload failed", error.message)));
    request.once("end", () => {
      if (settled) return;
      output.end(() => {
        if (settled) return;
        settled = true;
        resolve({ uploaded_file: filename, uploaded_size: received });
      });
    });
  });
}

function createServiceServer({ dispatcher, sessionFactory = () => ({ isAnonymous: () => true }), onDispatch, allowedOrigins = [], sanitize, binary_uploads = {} } = {}) {
  if (!dispatcher) throw new RuntimeError("DISPATCHER_REQUIRED", "A service dispatcher is required");
  return http.createServer(async (request, response) => {
    let input;
    const originHeaders = corsHeaders(request, allowedOrigins);
    if (request.method === "OPTIONS" && Object.keys(originHeaders).length) {
      response.writeHead(204, originHeaders);
      response.end();
      return;
    }
    try {
      const url = new URL(request.url, "http://kernel.invalid");
      const service = serviceFromPath(url.pathname);
      const session = await sessionFactory(request);
      const output = session.output || new RuntimeOutput({
        response,
        sanitize,
        headers: () => ({ ...originHeaders, ...(typeof session.responseHeaders === "function" ? session.responseHeaders() : {}) })
      });
      if (!session.output) session.output = output;
      const query = { ...(videoRequest(url.pathname) || {}).input, ...Object.fromEntries(url.searchParams.entries()) };
      const binary = binary_uploads[service];
      if (binary && binaryContentType(request)) {
        if (typeof dispatcher.authorizeRequest !== "function") throw new RuntimeError("BINARY_UPLOAD_AUTHORIZER_REQUIRED", "Binary upload requires runtime authorization preflight");
        await dispatcher.authorizeRequest({ service, input: query, session });
        if (typeof binary.before_receive === "function") await binary.before_receive({ service, input: query, session });
        input = { ...query, ...await receiveBinary(request, binary) };
      } else input = await requestInput(request, url);
      if (typeof onDispatch === "function") await onDispatch({ service, input, request, session });
      const data = await dispatcher.dispatch({ service, input, session });
      if (!response.writableEnded && !response.headersSent) output.data(data);
    } catch (error) {
      request.resume();
      response.writeHead(statusFor(error), { "content-type": "application/json", ...originHeaders });
      response.end(JSON.stringify({ status: "error", code: error.code || "SERVICE_FAILED" }));
    } finally {
      if (input && input.uploaded_file) fs.rmSync(input.uploaded_file, { force: true });
    }
  });
}

module.exports = { binaryContentType, corsHeaders, createServiceServer, receiveBinary, requestInput, serviceFromPath, videoRequest };
