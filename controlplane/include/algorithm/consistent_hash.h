#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <shared_mutex>
#include <mutex>
#include <map>
#include <atomic>
#include <chrono>
#include <optional>
#include <functional>
#include "xdpstructs.h"
#include "xxhash.h"

namespace blncr::algorithm {

static constexpr uint64_t MAGLEV_SEED_1 = 0x5bd1e995;
static constexpr uint64_t MAGLEV_SEED_2 = 0x9747b28c;
static constexpr uint64_t KEY_SEED = 0x5737a28c;


static constexpr uint32_t HASHRING_SMALL = 65537;
static constexpr uint32_t HASHRING_LARGE = 999983;

struct InstanceConfig {
    uint32_t hashring_size = HASHRING_SMALL;
    uint32_t merge_timeout_ticks = 180;
};

struct InstanceStats {
    uint64_t merge_count{};
    uint64_t update_count{};
    uint32_t current_backends_count{};
};

struct LookupResult {
    bool stable;
    std::optional<int32_t> curr;
    std::optional<int32_t> prev;
};

class ConsistentHashInstance {
public:
    explicit ConsistentHashInstance(const InstanceConfig& config = {});
    ~ConsistentHashInstance() = default;

    ConsistentHashInstance(const ConsistentHashInstance&) = delete;
    ConsistentHashInstance& operator=(const ConsistentHashInstance&) = delete;

    bool updateBackends(const std::vector<manager::xdp::Backend>& backends);

    LookupResult lookup(uint32_t key_hash) const;

    std::optional<int32_t> lookupCurr(uint32_t key_hash) const;
    std::optional<int32_t> lookupPrev(uint32_t key_hash) const;

    bool isStable(uint32_t key_hash) const;
    void merge();
    bool tickMergeTimer();

    void clear();

    InstanceStats getStats() const;
    bool needsMerge() const { return m_needsMerge.load(std::memory_order_acquire); }

    std::vector<std::pair<int32_t, int32_t>> getHashRingState() const;
    std::vector<manager::xdp::Backend> getBackends() const;
    std::vector<int32_t> getCurrLookupTable() const;
    std::vector<int32_t> getPrevLookupTable() const;
    uint32_t getHashringSize() const { return m_config.hashring_size; }

private:
    InstanceConfig m_config;
    InstanceStats m_stats;
    mutable std::mutex m_mutex;

    std::vector<manager::xdp::Backend> m_backends;
    std::vector<int32_t> m_currLookup;
    std::vector<int32_t> m_prevLookup;

    std::atomic<bool> m_needsMerge{false};
    std::atomic<uint32_t> m_mergeTimer{0};

private:
    void generatePermutations(const std::vector<manager::xdp::Backend>& backends,
                              std::vector<std::vector<uint32_t>>& permutations);

    void populateLookupTable(const std::vector<manager::xdp::Backend>& backends,
                             const std::vector<std::vector<uint32_t>>& permutations,
                             std::vector<int32_t>& curr_lookup,
                             const std::vector<int32_t>& prev_lookup);

    static uint32_t hashBackend1(const manager::xdp::Backend& backend);
    static uint32_t hashBackend2(const manager::xdp::Backend& backend);
};

class ConsistentHashManager {
public:
    using BpfUpdateCallback = std::function<bool(
        const manager::xdp::ServiceKey& service_key,
        const std::vector<manager::xdp::Backend>& backends,
        const std::vector<int32_t>& curr_lookup,
        const std::vector<int32_t>& prev_lookup,
        uint32_t hashring_size
    )>;

    ConsistentHashManager() = default;
    ~ConsistentHashManager() = default;

    void setBpfUpdateCallback(BpfUpdateCallback callback);

    bool updateServiceBackends(const manager::xdp::ServiceKey& service_key,
                               const std::vector<manager::xdp::Backend>& backends,
                               const InstanceConfig& config = {});

    bool removeService(const manager::xdp::ServiceKey& service_key);

    std::shared_ptr<ConsistentHashInstance> getInstance(const manager::xdp::ServiceKey& service_key);

    void periodicMaintenance();

    std::map<manager::xdp::ServiceKey, InstanceStats> getAllStats() const;

private:
    struct ServiceEntry {
        manager::xdp::ServiceKey key;
        std::shared_ptr<ConsistentHashInstance> instance;
        InstanceConfig config;
    };

    std::map<manager::xdp::ServiceKey, ServiceEntry> m_services;
    mutable std::shared_mutex m_mutex;
    BpfUpdateCallback m_bpfCallback;
};

} // namespace blncr::algorithm