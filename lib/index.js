const { DescriptorRegistry, parseService } = require("./descriptor-registry");
const { ServiceDispatcher } = require("./dispatcher");
const { FrontendPluginResolver } = require("./plugin-resolver");
const { createServiceServer } = require("./http");
const { RuntimeError } = require("./errors");
const { authorizeFastPath, createAuthorizer, fastCheckName } = require("./permission");
const { DomainAuthorizer } = require("./domain-authorizer");
const { KernelSession, SESSION_COOKIE, SessionManager } = require("./session");
const { YellowPageStore } = require("./yellow-page-store");

module.exports = {
  DescriptorRegistry,
  DomainAuthorizer,
  FrontendPluginResolver,
  KernelSession,
  RuntimeError,
  SESSION_COOKIE,
  SessionManager,
  ServiceDispatcher,
  YellowPageStore,
  authorizeFastPath,
  createAuthorizer,
  createServiceServer,
  fastCheckName,
  parseService
};
