const { DescriptorRegistry, parseService } = require("./descriptor-registry");
const { ServiceDispatcher } = require("./dispatcher");
const { FrontendPluginResolver } = require("./plugin-resolver");
const { createServiceServer } = require("./http");
const { RuntimeError } = require("./errors");
const { authorizeFastPath, createAuthorizer, fastCheckName } = require("./permission");
const { DomainAuthorizer } = require("./domain-authorizer");
const { KernelSession, SESSION_COOKIE, SessionManager } = require("./session");
const { YellowPageStore } = require("./yellow-page-store");
const { PushBus } = require("./push-bus");
const { WebSocketPushRouter, createPushServer } = require("./websocket-router");

module.exports = {
  DescriptorRegistry,
  DomainAuthorizer,
  FrontendPluginResolver,
  KernelSession,
  RuntimeError,
  PushBus,
  SESSION_COOKIE,
  SessionManager,
  ServiceDispatcher,
  YellowPageStore,
  WebSocketPushRouter,
  authorizeFastPath,
  createAuthorizer,
  createPushServer,
  createServiceServer,
  fastCheckName,
  parseService
};
