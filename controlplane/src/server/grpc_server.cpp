#include "grpc_server.h"
#include "grpc_mappers.h"
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/support/status.h>

using blncr::server::ControlplaneApiServerImpl;
using blncr::server::GrpcServer;
using namespace blncr::server::mappers;

// TODO: Прокинуть интерфейс для метрик

ControlplaneApiServerImpl::ControlplaneApiServerImpl(std::shared_ptr<blncr::manager::ConfigManager> manager) :
    m_cpManager(manager) {}


grpc::Status ControlplaneApiServerImpl::Ping(grpc::ServerContext *,const api::EmptyMessage*, api::EmptyMessage*) { return grpc::Status::OK; }

grpc::Status ControlplaneApiServerImpl::GetConfig(grpc::ServerContext *ctx, 
                                                    const api::GetConfigRequest *request, 
                                                    api::GetConfigResponse *response) 
{
    try {
        auto services = m_cpManager->ListServices();
        *response->mutable_config() = ToProtoConfiguration(services);
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

grpc::Status ControlplaneApiServerImpl::UpdateConfig(grpc::ServerContext *ctx,
                                                        const api::UpdateConfigRequest *request, 
                                                        api::UpdateConfigResponse *response) 
{
     try {
        auto [newConfig, errors] = FromProtoConfiguration(request->config());
 
        if (!errors.empty()) {
            response->set_success(false);
            for (const auto& err : errors) {
                response->add_errors(err);
            }
            return grpc::Status::OK;
        }
 
        m_cpManager->LoadConfig(std::move(newConfig));
        response->set_success(true);
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

grpc::Status ControlplaneApiServerImpl::ListServices(grpc::ServerContext *ctx,
                                                        const api::ListServicesRequest *request, 
                                                        api::ListServicesResponse *response) 
{
    try {
        auto services = m_cpManager->ListServices();
 
        // Получаем метрики один раз, если они были запрошены
        std::map<std::string, metrics::MetricsData> backendMetricsMap;
        std::map<std::string, metrics::MetricsData> serviceMetricsMap;
 
        const auto& filter = request->filter();
        const bool hasProtocolFilter = filter.has_protocol();
        const bool hasIpVersionFilter = filter.has_ip_version();
        const bool enabledOnly = filter.enabled_only();
 
        for (const auto& svc : services) {
            if (hasProtocolFilter && svc.protocol != filter.protocol()) {
                continue;
            }
            if (hasIpVersionFilter && svc.ip_version != filter.ip_version()) {
                continue;
            }
            if (enabledOnly) {
                bool hasEnabled = false;
                for (const auto& real : svc.reals) {
                    if (real.enabled) { hasEnabled = true; break; }
                }
                if (!hasEnabled) continue;
            }
 
            std::optional<metrics::MetricsData> svcMetrics;
 
            *response->add_services() = ToProtoServiceInfo(
                svc,
                request->include_backends(),
                request->include_metrics(),
                svcMetrics,
                backendMetricsMap);
        }
 
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

grpc::Status ControlplaneApiServerImpl::ListBackends(grpc::ServerContext *ctx,
                                                        const api::ListBackendsRequest *request,
                                                        api::ListBackendsResponse *response) 
{
    try {
        auto reals = m_cpManager->ListBackends();
 
        for (const auto& real : reals) {
            *response->add_backends() = ToProtoBackendInfo(real);
        }
 
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

grpc::Status ControlplaneApiServerImpl::SetBackendStatus(grpc::ServerContext *ctx, 
                                                        const api::SetBackendStatusRequest *request,
                                                        api::SetBackendStatusResponse *response) 
{
    try {
        std::string serviceName = request->service_name();
        if (serviceName.empty()) {
            for (const auto& svc : m_cpManager->ListServices()) {
                if (svc.vip == request->vip() && svc.port == request->service_port()) {
                    serviceName = svc.name;
                    break;
                }
            }
            if (serviceName.empty()) {
                response->set_success(false);
                response->set_error("service not found by vip=" + request->vip()
                                    + " port=" + std::to_string(request->service_port()));
                return grpc::Status::OK;
            }
        }
 
        blncr::command::SetRealStateRequest cmd{
            .serviceName = serviceName,
            .realIp      = request->backend_ip(),
            .enabled     = request->status(),
        };
 
        auto err = m_cpManager->SetRealState(cmd);
        if (err.has_value()) {
            response->set_success(false);
            response->set_error(err.value());
        } else {
            response->set_success(true);
        }
 
        return grpc::Status::OK;
    } catch (const std::exception& e) {
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
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