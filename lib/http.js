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

function createServiceServer({ dispatcher, sessionFactory = () => ({ isAnonymous: () => true }) } = {}) {
  if (!dispatcher) throw new RuntimeError("DISPATCHER_REQUIRED", "A service dispatcher is required");
  return http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url, "http://kernel.invalid");
      const service = serviceFromPath(url.pathname);
      const input = Object.fromEntries(url.searchParams.entries());
      const data = await dispatcher.dispatch({ service, input, session: sessionFactory(request) });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ status: "ok", data }));
    } catch (error) {
      response.writeHead(statusFor(error), { "content-type": "application/json" });
      response.end(JSON.stringify({ status: "error", code: error.code || "SERVICE_FAILED" }));
    }
  });
}

module.exports = { createServiceServer, serviceFromPath };
