#pragma once

#include "api/controlplane-api.grpc.pb.h"
#include "configmanager.h"
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>
#include <grpcpp/server.h>

#include <memory>
#include <thread>

namespace blncr::server {

inline std::string GRPC_SERVER_ADDRESS = "0.0.0.0:52001";

class ControlplaneApiServerImpl : public api::L4BalancerApi::Service {
public:
    ControlplaneApiServerImpl(std::shared_ptr<blncr::manager::ConfigManager>);

    grpc::Status GetConfig(grpc::ServerContext *, const api::GetConfigRequest*, api::GetConfigResponse*) override;
    grpc::Status UpdateConfig(grpc::ServerContext *,const api::UpdateConfigRequest*, api::UpdateConfigResponse*) override;
    grpc::Status ListServices(grpc::ServerContext *,const api::ListServicesRequest*, api::ListServicesResponse*) override;
    grpc::Status ListBackends(grpc::ServerContext *,const api::ListBackendsRequest*, api::ListBackendsResponse*) override;
    grpc::Status SetBackendStatus(grpc::ServerContext *,const api::SetBackendStatusRequest*, api::SetBackendStatusResponse*) override;
    grpc::Status Ping(grpc::ServerContext *,const api::EmptyMessage*, api::EmptyMessage*) override;
private:
    std::shared_ptr<blncr::manager::ConfigManager> m_cpManager;
};

class GrpcServer {
public:
    GrpcServer() = default;
    void init(std::shared_ptr<blncr::manager::ConfigManager>);
    void stop();
    ~GrpcServer();
private:
    std::thread m_serverThread;
    std::unique_ptr<ControlplaneApiServerImpl> m_impl;
    std::unique_ptr<grpc::Server> m_server;
};

}