#include "grpc_server.h"
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>

using blncr::server::ControlplaneApiServerImpl;
using blncr::server::GrpcServer;

ControlplaneApiServerImpl::ControlplaneApiServerImpl(std::shared_ptr<blncr::manager::ConfigManager> manager) :
    m_cpManager(manager) {}

grpc::Status ControlplaneApiServerImpl::GetConfig(grpc::ServerContext *ctx, 
                                                    const api::GetConfigRequest *request, 
                                                    api::GetConfigResponse *response) 
{
    return grpc::Status::OK;
}

grpc::Status ControlplaneApiServerImpl::UpdateConfig(grpc::ServerContext *ctx,
                                                        const api::UpdateConfigRequest *request, 
                                                        api::UpdateConfigResponse *response) 
{
    return grpc::Status::OK;
}

grpc::Status ControlplaneApiServerImpl::ListServices(grpc::ServerContext *ctx,
                                                        const api::ListServicesRequest *request, 
                                                        api::ListServicesResponse *response) 
{
    return grpc::Status::OK;
}

grpc::Status ControlplaneApiServerImpl::ListBackends(grpc::ServerContext *ctx,
                                                        const api::ListBackendsRequest *request,
                                                        api::ListBackendsResponse *response) 
{
    return grpc::Status::OK;
}

grpc::Status ControlplaneApiServerImpl::SetBackendStatus(grpc::ServerContext *ctx, 
                                                        const api::SetBackendStatusRequest *request,
                                                        api::SetBackendStatusResponse *response) 
{
    return grpc::Status::OK;
}

void GrpcServer::init(std::shared_ptr<blncr::manager::ConfigManager> manager) {
    m_serverThread = std::thread([this, &manager]() {
		m_impl = std::make_unique<ControlplaneApiServerImpl>(manager);
		grpc::ServerBuilder builder;
		builder.AddListeningPort(blncr::server::GRPC_SERVER_ADDRESS, grpc::InsecureServerCredentials());
		builder.RegisterService(m_impl.get());
		m_server = builder.BuildAndStart();
		m_server->Wait();
	});
}
    
void GrpcServer::stop() {
    m_server->Shutdown();
    if(m_serverThread.joinable()) {
        m_serverThread.join();
    }
}

GrpcServer::~GrpcServer() {
    stop();
}