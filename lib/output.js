"use strict";

const { RuntimeError } = require("./errors");

class RuntimeOutput {
  constructor({ response, sanitize = (value) => value, headers = () => ({}) } = {}) {
    if (!response) throw new RuntimeError("OUTPUT_RESPONSE_REQUIRED", "Runtime output requires an HTTP response");
    this.response = response;
    this.sanitize = sanitize;
    this.headers = headers;
  }

  done() { return this.response.writableEnded || this.response.headersSent; }

  data(data) {
    if (this.done()) return null;
    const clean = this.sanitize(data);
    this.response.writeHead(200, { "content-type": "application/json", ...this.headers() });
    this.response.end(JSON.stringify({ status: "ok", data: clean }));
    return null;
  }

  head(headers = {}, status = 200) {
    if (this.done()) return null;
    this.response.writeHead(status, { ...this.headers(), ...headers });
    this.response.end();
    return null;
  }

  write(content, content_type = "text/plain; charset=utf-8", status = 200) {
    if (this.done()) return null;
    const body = Buffer.isBuffer(content) ? content : Buffer.from(String(content));
    if (body.length > 1024 * 1024) throw new RuntimeError("OUTPUT_CONTROL_ARTIFACT_TOO_LARGE", "Runtime output.write is limited to small control-plane artifacts");
    this.response.writeHead(status, { "content-type": content_type, "content-length": body.length, ...this.headers() });
    this.response.end(body);
    return null;
  }
}

module.exports = { RuntimeOutput };
