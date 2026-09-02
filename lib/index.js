const { DescriptorRegistry, parseService } = require("./descriptor-registry");
const { ServiceDispatcher } = require("./dispatcher");
const { FrontendPluginResolver } = require("./plugin-resolver");
const { createServiceServer } = require("./http");
const { RuntimeError } = require("./errors");
const { authorizeFastPath, fastCheckName } = require("./permission");

module.exports = {
  DescriptorRegistry,
  FrontendPluginResolver,
  RuntimeError,
  ServiceDispatcher,
  authorizeFastPath,
  createServiceServer,
  fastCheckName,
  parseService
};
