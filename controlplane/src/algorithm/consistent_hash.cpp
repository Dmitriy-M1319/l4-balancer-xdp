#include "consistent_hash.h"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <chrono>

namespace blncr::algorithm {

ConsistentHashInstance::ConsistentHashInstance(const InstanceConfig& config)
    : m_config(config)
{
    m_currLookup.resize(m_config.hashring_size, -1);
    m_prevLookup.resize(m_config.hashring_size, -1);
}

bool ConsistentHashInstance::updateBackends(const std::vector<manager::xdp::Backend>& backends)
{
    if (backends.empty()) {
        clear();
        return true;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<int32_t> new_prev(m_config.hashring_size, -1);
    if (m_currLookup[0] != -1 && !m_needsMerge.load(std::memory_order_acquire))
    {
        new_prev = m_currLookup;
    }
    else if (m_needsMerge.load(std::memory_order_acquire))
    {
        new_prev = m_prevLookup;
    }

    std::vector<int32_t> new_curr(m_config.hashring_size, -1);

    std::vector<std::vector<uint32_t>> permutations;

    auto start = std::chrono::high_resolution_clock::now();

    generatePermutations(backends, permutations);
    populateLookupTable(backends, permutations, new_curr, new_prev);

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "[CH] setup + populate: " << duration.count() << " us, "
              << backends.size() << " backends, M=" << m_config.hashring_size << std::endl;

    m_backends = backends;
    m_currLookup = std::move(new_curr);
    m_prevLookup = std::move(new_prev);
    m_stats.update_count++;
    m_stats.current_backends_count = backends.size();

    m_mergeTimer.store(0, std::memory_order_release);
    m_needsMerge.store(true, std::memory_order_release);

    return true;
}

LookupResult ConsistentHashInstance::lookup(uint32_t key_hash) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_backends.empty()) {
        return {false, std::nullopt, std::nullopt};
    }

    uint32_t index = key_hash % m_config.hashring_size;

    int32_t curr_val = m_currLookup[index];
    int32_t prev_val = m_prevLookup[index];

    bool stable = (prev_val == -1) || (curr_val == prev_val);

    auto to_opt = [](int32_t v) -> std::optional<int32_t> {
        return (v >= 0) ? std::optional<int32_t>(v) : std::nullopt;
    };

    return {stable, to_opt(curr_val), to_opt(prev_val)};
}

std::optional<int32_t> ConsistentHashInstance::lookupCurr(uint32_t key_hash) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_backends.empty()) return std::nullopt;

    uint32_t index = key_hash % m_config.hashring_size;
    int32_t val = m_currLookup[index];
    return (val >= 0) ? std::optional<int32_t>(val) : std::nullopt;
}

std::optional<int32_t> ConsistentHashInstance::lookupPrev(uint32_t key_hash) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_backends.empty()) return std::nullopt;

    uint32_t index = key_hash % m_config.hashring_size;
    int32_t val = m_prevLookup[index];
    return (val >= 0) ? std::optional<int32_t>(val) : std::nullopt;
}

bool ConsistentHashInstance::isStable(uint32_t key_hash) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_prevLookup[0] == -1) {
        return true;
    }

    uint32_t index = key_hash % m_config.hashring_size;
    return m_currLookup[index] == m_prevLookup[index];
}

void ConsistentHashInstance::merge()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_needsMerge.load(std::memory_order_acquire)) {
        return;
    }

    // curr → prev: теперь оба кольца идентичны, переход завершён
    m_prevLookup = m_currLookup;
    m_needsMerge.store(false, std::memory_order_release);
    m_mergeTimer.store(0, std::memory_order_release);
    m_stats.merge_count++;

    std::cout << "[CH] merge completed, backends=" << m_backends.size() << std::endl;
}

bool ConsistentHashInstance::tickMergeTimer()
{
    if (!m_needsMerge.load(std::memory_order_acquire)) {
        return false;
    }

    uint32_t ticks = m_mergeTimer.fetch_add(1, std::memory_order_acq_rel) + 1;
    if (ticks >= m_config.merge_timeout_ticks) {
        merge();
        return true;
    }
    return false;
}

void ConsistentHashInstance::clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_backends.clear();
    std::fill(m_currLookup.begin(), m_currLookup.end(), -1);
    std::fill(m_prevLookup.begin(), m_prevLookup.end(), -1);
    m_needsMerge.store(false, std::memory_order_release);
    m_mergeTimer.store(0, std::memory_order_release);

    std::cout << "[CH] cleared" << std::endl;
}

InstanceStats ConsistentHashInstance::getStats() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_stats;
}

std::vector<std::pair<int32_t, int32_t>> ConsistentHashInstance::getHashRingState() const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    std::vector<std::pair<int32_t, int32_t>> result(m_config.hashring_size);
    for (size_t i = 0; i < m_config.hashring_size; ++i) {
        result[i] = {m_currLookup[i], m_prevLookup[i]};
    }
    return result;
}

std::vector<manager::xdp::Backend> ConsistentHashInstance::getBackends() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_backends;
}

std::vector<int32_t> ConsistentHashInstance::getCurrLookupTable() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_currLookup;
}

std::vector<int32_t> ConsistentHashInstance::getPrevLookupTable() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_prevLookup;
}

void ConsistentHashInstance::generatePermutations(
    const std::vector<manager::xdp::Backend>& backends,
    std::vector<std::vector<uint32_t>>& permutations)
{
    size_t n = backends.size();
    size_t m = m_config.hashring_size;

    permutations.resize(n);

    for (size_t i = 0; i < n; ++i) {
        permutations[i].resize(m);

        uint64_t offset = hashBackend1(backends[i]) % m;
        uint64_t skip = (hashBackend2(backends[i]) % (m - 1)) + 1;

        for (uint64_t j = 0; j < m; ++j) {
            permutations[i][j] = static_cast<uint32_t>((offset + j * skip) % m);
        }
    }
}

void ConsistentHashInstance::populateLookupTable(
    const std::vector<manager::xdp::Backend>& backends,
    const std::vector<std::vector<uint32_t>>& permutations,
    std::vector<int32_t>& curr_lookup,
    const std::vector<int32_t>& prev_lookup)
{
    size_t n = backends.size();
    size_t m = m_config.hashring_size;

    std::vector<uint64_t> next_index(n, 0);
    std::vector<int32_t> tmp_lookup(m, -1);
    uint32_t count = 0;

    while (count < m) {
        for (size_t i = 0; i < n; ++i) {
            uint64_t& next = next_index[i];
            uint32_t pos = permutations[i][next];

            while (tmp_lookup[pos] >= 0) {
                ++next;
                pos = permutations[i][next];
            }

            tmp_lookup[pos] = static_cast<int32_t>(i);
            curr_lookup[pos] = static_cast<int32_t>(i);
            ++next;

            if (++count == m) {
                break;
            }
        }
    }

}
uint32_t ConsistentHashInstance::hashBackend1(const manager::xdp::Backend& backend)
{
    struct {
        uint8_t addr[16];
        uint16_t port;
        uint8_t ip_version;
        uint8_t pad;
    } __attribute__((packed)) hash_input{};

    if (backend.ip_version == 4) {
        memcpy(hash_input.addr, &backend.ipv4, 4);
    } else {
        memcpy(hash_input.addr, backend.ipv6, 16);
    }
    hash_input.port = backend.port;
    hash_input.ip_version = backend.ip_version;

    return static_cast<uint32_t>(
        XXH3_64bits_withSeed(&hash_input, sizeof(hash_input), MAGLEV_SEED_1));
}

uint32_t ConsistentHashInstance::hashBackend2(const manager::xdp::Backend& backend)
{
    struct {
        uint8_t addr[16];
        uint16_t port;
        uint8_t ip_version;
        uint8_t pad;
    } __attribute__((packed)) hash_input{};

    if (backend.ip_version == 4) {
        memcpy(hash_input.addr, &backend.ipv4, 4);
    } else {
        memcpy(hash_input.addr, backend.ipv6, 16);
    }
    hash_input.port = backend.port;
    hash_input.ip_version = backend.ip_version;

    return static_cast<uint32_t>(
        XXH3_64bits_withSeed(&hash_input, sizeof(hash_input), MAGLEV_SEED_2));
}

void ConsistentHashManager::setBpfUpdateCallback(BpfUpdateCallback callback)
{
    m_bpfCallback = std::move(callback);
}

bool ConsistentHashManager::updateServiceBackends(
    const manager::xdp::ServiceKey& service_key,
    const std::vector<manager::xdp::Backend>& backends,
    const InstanceConfig& config)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    auto it = m_services.find(service_key);
    if (it != m_services.end()) {
        if (!it->second.instance->updateBackends(backends)) {
            return false;
        }
    } else {
        auto instance = std::make_shared<ConsistentHashInstance>(config);
        if (!instance->updateBackends(backends)) {
            return false;
        }
        m_services[service_key] = ServiceEntry{service_key, instance, config};
        it = m_services.find(service_key);
    }

    if (m_bpfCallback && it != m_services.end()) {
        auto inst = it->second.instance;
        m_bpfCallback(
            service_key,
            inst->getBackends(),
            inst->getCurrLookupTable(),
            inst->getPrevLookupTable(),
            inst->getHashringSize()
        );
    }

    return true;
}

bool ConsistentHashManager::removeService(const manager::xdp::ServiceKey& service_key)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    return m_services.erase(service_key) > 0;
}

std::shared_ptr<ConsistentHashInstance> ConsistentHashManager::getInstance(
    const manager::xdp::ServiceKey& service_key)
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    auto it = m_services.find(service_key);
    if (it != m_services.end()) {
        return it->second.instance;
    }
    return nullptr;
}

void ConsistentHashManager::periodicMaintenance()
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    for (auto& [key, entry] : m_services) {
        if (entry.instance->needsMerge()) {
            bool merged = entry.instance->tickMergeTimer();
            if (merged && m_bpfCallback) {
                m_bpfCallback(
                    entry.key,
                    entry.instance->getBackends(),
                    entry.instance->getCurrLookupTable(),
                    entry.instance->getPrevLookupTable(),
                    entry.instance->getHashringSize()
                );
            }
        }
    }
}

std::map<manager::xdp::ServiceKey, InstanceStats> ConsistentHashManager::getAllStats() const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    std::map<manager::xdp::ServiceKey, InstanceStats> stats;
    for (const auto& [key, entry] : m_services) {
        stats[key] = entry.instance->getStats();
    }
    return stats;
}

} // namespace blncr::algorithm