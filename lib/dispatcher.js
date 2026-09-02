const { RuntimeError } = require("./errors");
const { authorizeFastPath } = require("./permission");

class ServiceDispatcher {
  constructor({ registry, authorize = authorizeFastPath, requireWorker = require } = {}) {
    if (!registry) throw new RuntimeError("REGISTRY_REQUIRED", "A descriptor registry is required");
    this.registry = registry;
    this.authorize = authorize;
    this.requireWorker = requireWorker;
    this.workers = new Map();
  }

  getWorkerClass(workerPath) {
    let WorkerClass = this.workers.get(workerPath);
    if (!WorkerClass) {
      WorkerClass = this.requireWorker(workerPath);
      if (WorkerClass && WorkerClass.default) WorkerClass = WorkerClass.default;
      if (typeof WorkerClass !== "function") {
        throw new RuntimeError("WORKER_INVALID", `Worker at ${workerPath} does not export a class`);
      }
      this.workers.set(workerPath, WorkerClass);
    }
    return WorkerClass;
  }

  async dispatch({ service, session, input } = {}) {
    const resolved = this.registry.resolve(service, session);
    const decision = await this.authorize({ ...resolved, input, session });
    if (!decision || !decision.granted) {
      throw new RuntimeError("PERMISSION_DENIED", `Access denied to ${resolved.service}`, decision);
    }
    const WorkerClass = this.getWorkerClass(resolved.workerPath);
    const worker = new WorkerClass({ session, permission: resolved.permission });
    if (!worker || typeof worker[resolved.method] !== "function") {
      if (worker && typeof worker.stop === "function") worker.stop();
      throw new RuntimeError("SERVICE_NOT_FOUND", `Worker does not implement ${resolved.service}`);
    }
    try {
      return await worker[resolved.method](input);
    } finally {
      if (typeof worker.stop === "function") worker.stop();
    }
  }
}

module.exports = { ServiceDispatcher };
