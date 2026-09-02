global.__phase2PublicWorkerLoads = (global.__phase2PublicWorkerLoads || 0) + 1;

module.exports = class PublicWorker {
  constructor({ session, permission }) {
    this.session = session;
    this.permission = permission;
  }

  async public_status(input) {
    return { implementation: "public", input, permission: this.permission.src };
  }
};
