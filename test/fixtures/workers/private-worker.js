module.exports = class PrivateWorker {
  constructor({ session, permission }) {
    this.session = session;
    this.permission = permission;
  }

  async private_status(input) {
    return { implementation: "private", input, permission: this.permission.src };
  }
};
