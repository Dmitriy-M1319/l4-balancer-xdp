#pragma once

#include "metrics_data.h"
#include <cstdint>
#include <memory>
#include <thread>
#include <atomic>
#include <chrono>

#include <opentelemetry/metrics/meter.h>
#include <opentelemetry/metrics/sync_instruments.h>
#include <opentelemetry/exporters/prometheus/exporter_factory.h>
#include <opentelemetry/exporters/prometheus/exporter_options.h>
#include <opentelemetry/metrics/provider.h>
#include <opentelemetry/sdk/metrics/meter_provider.h>

namespace metrics_api = opentelemetry::metrics;

namespace blncr {

namespace metrics {

class MetricsServer {
public:
    MetricsServer(std::shared_ptr<IMetricsProvider> provider, 
                  unsigned int port = 9464,
                  std::chrono::seconds scrape_interval = std::chrono::seconds(5));
    ~MetricsServer();
    
    void Serve();
    void Stop();
    void Join();
    
private:
    void scrapMetrics();
    void calculateRates(const std::map<BackendInfo, MetricsData>& currentBackend,
                        const std::map<ServiceInfo, MetricsData>& currentService,
                        double elapsed);
    
private:
    std::shared_ptr<IMetricsProvider> m_provider;
    std::thread m_metricsThread;
    std::atomic<bool> m_running{false};
    std::chrono::seconds m_scrapeInterval;

    opentelemetry::nostd::shared_ptr<metrics_api::MeterProvider> m_meterProvider;
    opentelemetry::nostd::shared_ptr<metrics_api::Meter> m_meter;

    opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>> m_backend_total_packets;
    opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>> m_backend_tcp_syn_packets;
    opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>> m_backend_prepared_packets;
    opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>> m_backend_total_bytes;
    
    opentelemetry::nostd::unique_ptr<metrics_api::Gauge<int64_t>> m_backend_connections;

    opentelemetry::nostd::unique_ptr<metrics_api::Gauge<double>> m_backend_packets_per_sec;
    opentelemetry::nostd::unique_ptr<metrics_api::Gauge<double>> m_backend_bytes_per_sec;
    opentelemetry::nostd::unique_ptr<metrics_api::Gauge<double>> m_backend_syn_per_sec;

    opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>> m_service_total_packets;
    opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>> m_service_tcp_syn_packets;
    opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>> m_service_prepared_packets;
    opentelemetry::nostd::unique_ptr<metrics_api::Counter<uint64_t>> m_service_total_bytes;
    
    opentelemetry::nostd::unique_ptr<metrics_api::Gauge<int64_t>> m_service_connections;

    opentelemetry::nostd::unique_ptr<metrics_api::Gauge<double>> m_service_packets_per_sec;
    opentelemetry::nostd::unique_ptr<metrics_api::Gauge<double>> m_service_bytes_per_sec;
    opentelemetry::nostd::unique_ptr<metrics_api::Gauge<double>> m_service_syn_per_sec;
    
    std::map<BackendInfo, MetricsData> m_prevBackendMetrics;
    std::map<ServiceInfo, MetricsData> m_prevServiceMetrics;
    std::chrono::steady_clock::time_point m_prevTimestamp;
};

} 
}