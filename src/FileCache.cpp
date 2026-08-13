// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
#include "FileCache.h"
#include <algorithm>
#include <mutex>          // std::unique_lock
#include <vector>
#include <cstdio>

namespace httpd {

// Read the whole file. `expect` is the size from stat(); the result is truncated
// to what was actually read, since the file may have shrunk in between.
static bool readWholeFile(const std::string& path, size_t expect, std::string& out) {
    FILE* f = fopen(path.c_str(), "rb");
    if(!f) return false;
    out.resize(expect);
    size_t n = expect ? fread(out.data(), 1, expect, f) : 0;
    bool ok = !ferror(f);
    fclose(f);
    out.resize(n);
    return ok;
}

std::shared_ptr<const std::string> FileCache::get(const std::string& path,
                                                  const struct stat& st) {
    {
        std::shared_lock<std::shared_mutex> lk(mu_);
        auto it = map_.find(path);
        if(it != map_.end() && it->second.stamp.sameAs(st)) {
            it->second.tick.store(tick_.fetch_add(1) + 1, std::memory_order_relaxed);
            hits_.fetch_add(1, std::memory_order_relaxed);
            // Refcount bump only — the caller copies the bytes after unlocking.
            return it->second.data;
        }
        misses_.fetch_add(1, std::memory_order_relaxed);
    }

    // Read outside the lock: disk I/O must not block other threads' hits. Two
    // threads racing the same cold file both read it; the duplicate work is
    // harmless and the second store overwrites an identical entry.
    auto data = std::make_shared<std::string>();
    if(!readWholeFile(path, (size_t)st.st_size, *data)) return nullptr;

    // Large files are served but never retained, so one big download cannot
    // evict the whole working set.
    if((size_t)st.st_size > cfg_.maxFileBytes) return data;

    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = map_.find(path);
    if(it != map_.end()) {
        bytes_ -= it->second.data->size();
        map_.erase(it);
    }
    evictLocked(data->size());
    bytes_ += data->size();
    map_.try_emplace(path, data, FileStamp::of(st), tick_.fetch_add(1) + 1);
    return data;
}

// Evict least-recently-used entries until `needBytes` fits both budgets.
// Overflow should be rare, so sorting on eviction is cheaper overall than
// maintaining an intrusive LRU list on every hit.
void FileCache::evictLocked(size_t needBytes) {
    auto fits = [&] {
        return bytes_ + needBytes <= cfg_.maxTotalBytes
            && map_.size() < cfg_.maxEntries;
    };
    if(fits()) return;

    std::vector<std::pair<uint64_t, const std::string*>> order;
    order.reserve(map_.size());
    for(const auto& kv : map_)
        order.push_back({ kv.second.tick.load(std::memory_order_relaxed), &kv.first });
    std::sort(order.begin(), order.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    for(const auto& entry : order) {
        if(fits()) break;
        auto it = map_.find(*entry.second);
        if(it == map_.end()) continue;
        bytes_ -= it->second.data->size();
        map_.erase(it);
        ++evictions_;
    }
}

FileCache::Stats FileCache::stats() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return Stats{ hits_.load(), misses_.load(), evictions_.load(),
                  bytes_, map_.size() };
}

void FileCache::clear() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    map_.clear();
    bytes_ = 0;
}

} // namespace httpd
