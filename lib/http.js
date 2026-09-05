const http = require("http");
const { URL } = require("url");
const { RuntimeError } = require("./errors");

function statusFor(error) {
  if (!error || !error.code) return 500;
  if (error.code === "PERMISSION_DENIED") return 403;
  if (/NOT_FOUND/.test(error.code)) return 404;
  if (/FORMAT|INVALID|REQUIRED/.test(error.code)) return 400;
  return 500;
}

function serviceFromPath(pathname) {
  const match = pathname.match(/\/(?:svc|vdo|service)\/([^/]+)$/);
  if (!match) throw new RuntimeError("WRONG_SERVICE_FORMAT", `No Drumee service in ${pathname}`);
  return decodeURIComponent(match[1]);
}

function requestBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    request.on("data", (chunk) => {
      length += chunk.length;
      if (length > 65536) {
        reject(new RuntimeError("REQUEST_BODY_INVALID", "Service input exceeds 64 KiB"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
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
  const query = Object.fromEntries(url.searchParams.entries());
  if (request.method === "POST" || request.method === "PUT" || request.method === "PATCH") {
    return { ...query, ...await requestBody(request) };
  }
  return query;
}

function createServiceServer({ dispatcher, sessionFactory = () => ({ isAnonymous: () => true }), onDispatch } = {}) {
  if (!dispatcher) throw new RuntimeError("DISPATCHER_REQUIRED", "A service dispatcher is required");
  return http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url, "http://kernel.invalid");
      const service = serviceFromPath(url.pathname);
      const input = await requestInput(request, url);
      if (typeof onDispatch === "function") await onDispatch({ service, input, request });
      const data = await dispatcher.dispatch({ service, input, session: sessionFactory(request) });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ status: "ok", data }));
    } catch (error) {
      response.writeHead(statusFor(error), { "content-type": "application/json" });
      response.end(JSON.stringify({ status: "error", code: error.code || "SERVICE_FAILED" }));
    }
  });
}

module.exports = { createServiceServer, requestInput, serviceFromPath };
