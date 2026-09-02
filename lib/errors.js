class RuntimeError extends Error {
  constructor(code, message, details) {
    super(message || code);
    this.name = "RuntimeError";
    this.code = code;
    this.details = details;
  }
}

module.exports = { RuntimeError };
