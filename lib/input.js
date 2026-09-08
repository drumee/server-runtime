const { RuntimeError } = require("./errors");

// This is the small HTTP-session portion of the historical Input class.  The
// historical ui-essentials client calls it "authorization", but it does not
// use the standard HTTP Authorization scheme: it sends x-param-keysel plus
// x-param-<keysel>.  The kernel owns only regsid and deliberately excludes
// historical Hub/DMZ selectors.
const SESSION_COOKIE = "regsid";
const SESSION_SELECTOR_HEADER = "x-param-keysel";

function validSessionId(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{16,64}$/.test(value) ? value : undefined;
}

function headerValue(headers, name) {
  if (!headers || typeof headers !== "object") return undefined;
  const value = headers[String(name).toLowerCase()];
  if (typeof value !== "string" || !value) return undefined;
  try {
    // Input._parseHeader() applies decodeURI before Input.authorization()
    // reads x-param-* values. Keep that wire behavior at this narrow seam.
    return decodeURI(value);
  } catch (_) {
    return undefined;
  }
}

function sessionAuthorization(request) {
  const headers = request && request.headers;
  const selector = headerValue(headers, SESSION_SELECTOR_HEADER);
  const directSid = headerValue(headers, `x-param-${SESSION_COOKIE}`);
  const present = selector !== undefined || directSid !== undefined;
  if (!present) return { present: false };

  if (selector !== undefined && selector !== SESSION_COOKIE) {
    throw new RuntimeError("SESSION_CONTEXT_INVALID", "Unsupported runtime session selector");
  }
  if (!validSessionId(directSid)) {
    throw new RuntimeError("SESSION_CONTEXT_INVALID", "Invalid runtime session authorization");
  }
  return { present: true, keysel: SESSION_COOKIE, sid: directSid };
}

module.exports = {
  SESSION_COOKIE,
  SESSION_SELECTOR_HEADER,
  headerValue,
  sessionAuthorization,
  validSessionId
};
