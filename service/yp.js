/*
 * Selective generic authentication worker. Historical yp.login delegates to
 * Session.signin; this no-Team kernel worker keeps only credential submission
 * and the real Yellow Page session_signin/cookie binding.
 */
module.exports = class YellowPageWorker {
  constructor({ session } = {}) {
    this.session = session;
  }

  async signin(input = {}) {
    if (!this.session || typeof this.session.signin !== "function") {
      throw new Error("Yellow Page session authentication is not configured");
    }
    return this.session.signin(input);
  }
};
