// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// mtime-validated cache of static file bodies
#pragma once
#include "common.h"
#include <atomic>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <sys/stat.h>

namespace httpd {

// ── File identity + version stamp ─────────────────────────────────────────────
// Nanosecond mtime so a same-second rewrite still invalidates; dev/ino/size so
// a replacement file that happens to match mtime does too.
struct FileStamp {
    dev_t  dev  = 0;
    ino_t  ino  = 0;
    off_t  size = 0;
    time_t sec  = 0;
    long   nsec = 0;

    static FileStamp of(const struct stat& st) {
        return { st.st_dev, st.st_ino, st.st_size,
                 st.st_mtim.tv_sec, st.st_mtim.tv_nsec };
    }
    bool sameAs(const struct stat& st) const {
        return dev == st.st_dev && ino == st.st_ino && size == st.st_size
            && sec == st.st_mtim.tv_sec && nsec == st.st_mtim.tv_nsec;
    }
};

// ── Static file body cache ────────────────────────────────────────────────────
//
// Bodies are immutable and handed out as shared_ptr<const std::string>, so the
// lock guards only the map: the caller copies bytes into its response after
// releasing it, and a cold read happens outside the lock entirely. Hits take a
// shared lock and bump an atomic recency counter, so concurrent readers of the
// same file do not serialise on each other — with an exclusive mutex here, the
// lock itself costs more than the read() it was meant to avoid.
// One instance is shared by every I/O thread of a worker process.
//
// Validation is per-call against a caller-supplied stat(), so an edited file is
// picked up on the next request — there is no TTL and no flush to remember.
class FileCache {
public:
    struct Config {
        size_t maxFileBytes  = 1024*1024;     // per-file ceiling; larger files are not retained
        size_t maxTotalBytes = 64*1024*1024;  // whole-cache budget
        size_t maxEntries    = 4096;
    };

    FileCache() = default;
    explicit FileCache(Config cfg) : cfg_(cfg) {}

    // Contents of `path`, read from disk on a miss or when `st` shows the
    // cached copy is out of date. nullptr only if the file cannot be read.
    // Files over maxFileBytes are returned but not retained.
    std::shared_ptr<const std::string> get(const std::string& path,
                                           const struct stat& st);

    struct Stats {
        uint64_t hits = 0, misses = 0, evictions = 0;
        size_t   bytes = 0, entries = 0;
    };
    Stats stats() const;
    void  clear();

private:
    struct Entry {
        std::shared_ptr<const std::string> data;
        FileStamp stamp;
        // Last-access order for LRU. Atomic so a hit can record recency while
        // holding only a shared lock.
        std::atomic<uint64_t> tick{0};

        Entry() = default;
        Entry(std::shared_ptr<const std::string> d, FileStamp s, uint64_t t)
            : data(std::move(d)), stamp(s), tick(t) {}
        Entry(Entry&& o) noexcept
            : data(std::move(o.data)), stamp(o.stamp), tick(o.tick.load()) {}
    };

    Config cfg_;
    mutable std::shared_mutex mu_;
    std::unordered_map<std::string, Entry> map_;
    size_t bytes_ = 0;                       // guarded by exclusive lock
    std::atomic<uint64_t> tick_{0};
    std::atomic<uint64_t> hits_{0}, misses_{0}, evictions_{0};

    void evictLocked(size_t needBytes);
};

} // namespace httpd
