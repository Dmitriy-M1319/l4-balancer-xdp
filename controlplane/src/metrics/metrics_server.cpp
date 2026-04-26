#include "metrics_server.h"
#include "opentelemetry/sdk/metrics/meter_provider.h"
#include "opentelemetry/sdk/metrics/meter_provider_factory.h"
#include <format>
#include <iostream>

namespace metrics_sdk = opentelemetry::sdk::metrics;
namespace metrics_exporter = opentelemetry::exporter::metrics;

using namespace blncr::metrics;
using namespace std::chrono_literals;

MetricsServer::MetricsServer(std::shared_ptr<IMetricsProvider> provider, 
                             unsigned int port,
                             std::chrono::seconds scrape_interval) 
    : m_provider(provider)
    , m_scrapeInterval(scrape_interval)
{
    metrics_exporter::PrometheusExporterOptions opts;
    opts.url = std::format("0.0.0.0:{}", port);
    
    auto prometheus_exporter = metrics_exporter::PrometheusExporterFactory::Create(opts);
    
    auto u_provider = metrics_sdk::MeterProviderFactory::Create();
    auto *p = static_cast<metrics_sdk::MeterProvider *>(u_provider.get());
    p->AddMetricReader(std::move(prometheus_exporter));
    
    m_meterProvider = std::shared_ptr<metrics_api::MeterProvider>(std::move(u_provider));
    metrics_api::Provider::SetMeterProvider(m_meterProvider);
    
    m_meter = m_meterProvider->GetMeter("l4_balancer_xdp", "1.0.0");

    m_backend_total_packets = m_meter->CreateUInt64Counter(
        "lb_backend_packets_total",
        "Total number of packets processed by backend",
        "packets"
    );

    m_backend_tcp_syn_packets = m_meter->CreateUInt64Counter(
        "lb_backend_tcp_syn_packets_total",
        "Total number of TCP SYN packets to backend",
        "packets"
    );

    m_backend_prepared_packets = m_meter->CreateUInt64Counter(
        "lb_backend_prepared_packets_total",
        "Total number of prepared packets for backend",
        "packets"
    );

    m_backend_total_bytes = m_meter->CreateUInt64Counter(
        "lb_backend_bytes_total",
        "Total number of bytes processed by backend",
        "bytes"
    );

    m_backend_connections = m_meter->CreateInt64Gauge(
        "lb_backend_connections_active",
        "Number of active connections to backend",
        "connections"
    );

    m_backend_packets_per_sec = m_meter->CreateDoubleGauge(
        "lb_backend_packets_per_second",
        "Packets per second processed by backend",
        "pps"
    );

    m_backend_bytes_per_sec = m_meter->CreateDoubleGauge(
        "lb_backend_bytes_per_second",
        "Bytes per second processed by backend",
        "bps"
    );

    m_backend_syn_per_sec = m_meter->CreateDoubleGauge(
        "lb_backend_syn_per_second",
        "TCP SYN packets per second to backend",
        "pps"
    );

    m_service_total_packets = m_meter->CreateUInt64Counter(
        "lb_service_packets_total",
        "Total number of packets for service",
        "packets"
    );

    m_service_tcp_syn_packets = m_meter->CreateUInt64Counter(
        "lb_service_tcp_syn_packets_total",
        "Total number of TCP SYN packets for service",
        "packets"
    );

    m_service_prepared_packets = m_meter->CreateUInt64Counter(
        "lb_service_prepared_packets_total",
        "Total number of prepared packets for service",
        "packets"
    );

    m_service_total_bytes = m_meter->CreateUInt64Counter(
        "lb_service_bytes_total",
        "Total number of bytes for service",
        "bytes"
    );

    m_service_connections = m_meter->CreateInt64Gauge(
        "lb_service_connections_active",
        "Number of active connections for service",
        "connections"
    );

    m_service_packets_per_sec = m_meter->CreateDoubleGauge(
        "lb_service_packets_per_second",
        "Packets per second for service",
        "pps"
    );

    m_service_bytes_per_sec = m_meter->CreateDoubleGauge(
        "lb_service_bytes_per_second",
        "Bytes per second for service",
        "bps"
    );

    m_service_syn_per_sec = m_meter->CreateDoubleGauge(
        "lb_service_syn_per_second",
        "TCP SYN packets per second for service",
        "pps"
    );

    m_ddos_dropped_total = m_meter->CreateUInt64Counter(
        "lb_ddos_dropped_packets_total",
        "Total number of packets dropped by DDoS filter",
        "packets"
    );

    m_ddos_blacklist_size = m_meter->CreateInt64Gauge(
        "lb_ddos_blacklist_size",
        "Number of currently blocked source IPs",
        "ips"
    );

    m_prevTimestamp = std::chrono::steady_clock::now();
}

MetricsServer::~MetricsServer() {
    Stop();
    Join();
}

void MetricsServer::scrapMetrics() {
    try {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - m_prevTimestamp).count();

        auto currentBackendMetrics = m_provider->GetBackendsCurrentMetrics();

        for (const auto& [backend, currentMetric] : currentBackendMetrics) {
            std::map<std::string, std::string> labels = {
                {"backend", backend.ip_address},
                {"port", std::format("{}", backend.port)},
                {"ip_version", backend.ip_version == 4 ? "4" : "6"}
            };

            auto prevIt = m_prevBackendMetrics.find(backend);
            if (prevIt != m_prevBackendMetrics.end()) {
                const auto& prev = prevIt->second;
                m_backend_total_packets->Add(currentMetric.total_packets - prev.total_packets, labels);
                m_backend_tcp_syn_packets->Add(currentMetric.tcp_syn_packets - prev.tcp_syn_packets, labels);
                m_backend_prepared_packets->Add(currentMetric.prepared_packets - prev.prepared_packets, labels);
                m_backend_total_bytes->Add(currentMetric.total_bytes - prev.total_bytes, labels);
            } else {
                m_backend_total_packets->Add(currentMetric.total_packets, labels);
                m_backend_tcp_syn_packets->Add(currentMetric.tcp_syn_packets, labels);
                m_backend_prepared_packets->Add(currentMetric.prepared_packets, labels);
                m_backend_total_bytes->Add(currentMetric.total_bytes, labels);
            }

            m_backend_connections->Record(static_cast<int64_t>(currentMetric.connections), labels);
        }

        auto currentServiceMetrics = m_provider->GetServicesCurrentMetrics();

        for (const auto& [service, currentMetric] : currentServiceMetrics) {
            std::map<std::string, std::string> labels = {
                {"service", service.name},
                {"vip", service.vip_address},
                {"port", std::format("{}", service.port)},
                {"ip_version", service.ip_version == 4 ? "4" : "6"}
            };

            auto prevIt = m_prevServiceMetrics.find(service);
            if (prevIt != m_prevServiceMetrics.end()) {
                const auto& prev = prevIt->second;
                m_service_total_packets->Add(currentMetric.total_packets - prev.total_packets, labels);
                m_service_tcp_syn_packets->Add(currentMetric.tcp_syn_packets - prev.tcp_syn_packets, labels);
                m_service_prepared_packets->Add(currentMetric.prepared_packets - prev.prepared_packets, labels);
                m_service_total_bytes->Add(currentMetric.total_bytes - prev.total_bytes, labels);
            } else {
                m_service_total_packets->Add(currentMetric.total_packets, labels);
                m_service_tcp_syn_packets->Add(currentMetric.tcp_syn_packets, labels);
                m_service_prepared_packets->Add(currentMetric.prepared_packets, labels);
                m_service_total_bytes->Add(currentMetric.total_bytes, labels);
            }

            m_service_connections->Record(static_cast<int64_t>(currentMetric.connections), labels);
        }

        // Rates require at least one previous sample and a meaningful elapsed time
        if (!m_prevBackendMetrics.empty() && elapsed > 0.001) {
            calculateRates(currentBackendMetrics, currentServiceMetrics, elapsed);
        }

        auto ddos = m_provider->GetDdosStats();
        if (ddos.dropped_total >= m_prevDroppedTotal) {
            m_ddos_dropped_total->Add(ddos.dropped_total - m_prevDroppedTotal, {});
        }
        m_prevDroppedTotal = ddos.dropped_total;
        m_ddos_blacklist_size->Record(static_cast<int64_t>(ddos.blacklist_size), {});

        m_prevTimestamp = now;
        m_prevBackendMetrics = std::move(currentBackendMetrics);
        m_prevServiceMetrics = std::move(currentServiceMetrics);

    } catch (const std::exception& e) {
        std::cerr << "Error scraping metrics: " << e.what() << std::endl;
    }
}


void MetricsServer::calculateRates(const std::map<BackendInfo, MetricsData>& currentBackend,
                                    const std::map<ServiceInfo, MetricsData>& currentService,
                                    double elapsed)
{
    for (const auto& [backend, currentMetric] : currentBackend) {
        auto prevIt = m_prevBackendMetrics.find(backend);
        if (prevIt == m_prevBackendMetrics.end()) continue;

        const auto& prev = prevIt->second;
        std::map<std::string, std::string> labels = {
            {"backend", backend.ip_address},
            {"port", std::format("{}", backend.port)},
            {"ip_version", backend.ip_version == 4 ? "4" : "6"}
        };

        m_backend_packets_per_sec->Record(
            static_cast<double>(currentMetric.total_packets - prev.total_packets) / elapsed, labels);
        m_backend_bytes_per_sec->Record(
            static_cast<double>(currentMetric.total_bytes - prev.total_bytes) / elapsed, labels);
        m_backend_syn_per_sec->Record(
            static_cast<double>(currentMetric.tcp_syn_packets - prev.tcp_syn_packets) / elapsed, labels);
    }

    for (const auto& [service, currentMetric] : currentService) {
        auto prevIt = m_prevServiceMetrics.find(service);
        if (prevIt == m_prevServiceMetrics.end()) continue;

        const auto& prev = prevIt->second;
        std::map<std::string, std::string> labels = {
            {"service", service.name},
            {"vip", service.vip_address},
            {"port", std::format("{}", service.port)},
            {"ip_version", service.ip_version == 4 ? "4" : "6"}
        };

        m_service_packets_per_sec->Record(
            static_cast<double>(currentMetric.total_packets - prev.total_packets) / elapsed, labels);
        m_service_bytes_per_sec->Record(
            static_cast<double>(currentMetric.total_bytes - prev.total_bytes) / elapsed, labels);
        m_service_syn_per_sec->Record(
            static_cast<double>(currentMetric.tcp_syn_packets - prev.tcp_syn_packets) / elapsed, labels);
    }
}

void MetricsServer::Serve() {
    m_running = true;
    
    m_metricsThread = std::thread([this]() {
        std::cout << "MetricsServer started, scraping every " 
                  << m_scrapeInterval.count() << " seconds\n";
        
        while (m_running) {
            scrapMetrics();
            std::this_thread::sleep_for(m_scrapeInterval);
        }
        
        std::cout << "MetricsServer stopped\n";
    });
}

void MetricsServer::Stop() {
    m_running = false;
}

void MetricsServer::Join() {
    if (m_metricsThread.joinable()) {
        m_metricsThread.join();
    }
}