// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cassert>
#include <algorithm>
#include <new>
#include <string>
#include <string_view>
#include <ctime>
#include <functional>
#include <memory>
#include <atomic>
#include <pthread.h>

namespace httpd {

// ── Error codes ───────────────────────────────────────────────────────────────
enum class Err : uint8_t {
    Ok=0, Parse, TooLong, NotFound, Duplicate, BadState,
    Transport, Auth, Resources, Timeout, Rejected, Io, Tls,
    Protocol, Forbidden, NotImpl,
};

// ── Result<T> ─────────────────────────────────────────────────────────────────
template<class T> struct Result {
    alignas(T) uint8_t storage[sizeof(T)] = {};
    Err e;
    Result(T v) : e(Err::Ok)  { new(storage) T(std::move(v)); }
    Result(Err er) : e(er) {}
    bool ok()  const { return e == Err::Ok; }
    explicit operator bool() const { return ok(); }
    T&       operator*()       { return *reinterpret_cast<T*>(storage); }
    const T& operator*() const { return *reinterpret_cast<const T*>(storage); }
    T*       operator->()       { return reinterpret_cast<T*>(storage); }
    const T* operator->() const { return reinterpret_cast<const T*>(storage); }
};
template<> struct Result<void> {
    Err e;
    Result()       : e(Err::Ok) {}
    Result(Err er) : e(er) {}
    bool ok()  const { return e == Err::Ok; }
    explicit operator bool() const { return ok(); }
};
using Res = Result<void>;

// ── Fixed string ──────────────────────────────────────────────────────────────
template<size_t N>
struct Str {
    char     buf[N+1] = {};
    uint32_t len      = 0;
    Str() = default;
    Str(const char* s, size_t l = SIZE_MAX) { assign(s, l==SIZE_MAX?(s?strlen(s):0):l); }
    Str(std::string_view sv) { assign(sv.data(), sv.size()); }
    void assign(const char* s, size_t l) {
        len=(uint32_t)std::min(l,N); if(s&&len) memcpy(buf,s,len); buf[len]=0;
    }
    void clear()             { len=0; buf[0]=0; }
    bool empty()        const { return len==0; }
    const char* c_str() const { return buf; }
    char* data()              { return buf; }
    void setLen(size_t l)    { len=(uint32_t)std::min(l,N); buf[len]=0; }
    bool append(const char* s, size_t l) {
        size_t add=std::min(l,N-(size_t)len);
        if(add) memcpy(buf+len,s,add);
        len+=(uint32_t)add; buf[len]=0; return add==l;
    }
    bool appendC(char c) { return append(&c,1); }
    bool eq(const char* s, size_t l) const { return len==(uint32_t)l&&!memcmp(buf,s,l); }
    bool operator==(const char* s)   const { return eq(s,strlen(s)); }
    bool operator==(const Str& o)    const { return eq(o.buf,o.len); }
    bool operator!=(const char* s)   const { return !(*this==s); }
    bool operator!=(const Str& o)    const { return !(*this==o); }
    bool eqi(const char* s, size_t l) const {
        if(len!=(uint32_t)l) return false;
        for(size_t i=0;i<l;++i) if((buf[i]|32)!=(s[i]|32)) return false;
        return true;
    }
    bool eqi(const char* s) const { return eqi(s,strlen(s)); }
    std::string_view sv() const { return {buf,(size_t)len}; }
    operator std::string_view() const { return sv(); }
    // printf-style format into this string
    template<class...A> void fmt(const char* f, A&&...a) {
        int r=snprintf(buf,N+1,f,std::forward<A>(a)...);
        len=(r>0&&(size_t)r<=N)?(uint32_t)r:(uint32_t)N;
    }
};

// ── RAII mutex guard ──────────────────────────────────────────────────────────
struct Guard {
    pthread_mutex_t& m;
    Guard(pthread_mutex_t& m): m(m) { pthread_mutex_lock(&m); }
    ~Guard()                        { pthread_mutex_unlock(&m); }
};

// ── Ring buffer (single-producer, single-consumer, lock-free) ─────────────────
template<size_t CAP>
struct RingBuf {
    static_assert((CAP & (CAP-1))==0, "CAP must be power of 2");
    uint8_t  data[CAP];
    std::atomic<size_t> head{0}, tail{0};

    size_t readable() const { return tail.load(std::memory_order_acquire)-head.load(std::memory_order_relaxed); }
    size_t writable() const { return CAP - readable(); }

    size_t write(const void* src, size_t n) {
        size_t avail=writable(); n=std::min(n,avail);
        size_t h=head.load(std::memory_order_relaxed);
        size_t pos=tail.load(std::memory_order_relaxed)&(CAP-1);
        size_t first=std::min(n,CAP-pos);
        memcpy(data+pos,src,first);
        if(n>first) memcpy(data,static_cast<const uint8_t*>(src)+first,n-first);
        tail.fetch_add(n,std::memory_order_release); (void)h;
        return n;
    }
    size_t read(void* dst, size_t n) {
        size_t avail=readable(); n=std::min(n,avail);
        size_t pos=head.load(std::memory_order_relaxed)&(CAP-1);
        size_t first=std::min(n,CAP-pos);
        memcpy(dst,data+pos,first);
        if(n>first) memcpy(static_cast<uint8_t*>(dst)+first,data,n-first);
        head.fetch_add(n,std::memory_order_release);
        return n;
    }
    void reset() { head.store(0); tail.store(0); }
};

// ── Intrusive list ────────────────────────────────────────────────────────────
struct ListNode { ListNode* prev=nullptr; ListNode* next=nullptr; };
struct List {
    ListNode sentinel{&sentinel,&sentinel};
    bool empty() const { return sentinel.next==&sentinel; }
    void push_front(ListNode* n) { n->next=sentinel.next; n->prev=&sentinel; sentinel.next->prev=n; sentinel.next=n; }
    void push_back(ListNode* n)  { n->prev=sentinel.prev; n->next=&sentinel; sentinel.prev->next=n; sentinel.prev=n; }
    ListNode* pop_front() { if(empty()) return nullptr; ListNode* n=sentinel.next; n->prev->next=n->next; n->next->prev=n->prev; return n; }
    void remove(ListNode* n) { n->prev->next=n->next; n->next->prev=n->prev; }
};

// ── Timestamps ────────────────────────────────────────────────────────────────
inline int64_t nowMs() {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return (int64_t)ts.tv_sec*1000+(int64_t)ts.tv_nsec/1000000;
}
inline int64_t nowWallMs() {
    struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts);
    return (int64_t)ts.tv_sec*1000+(int64_t)ts.tv_nsec/1000000;
}

// ── Limits ────────────────────────────────────────────────────────────────────
static constexpr size_t kMaxHeaders     = 128;
static constexpr size_t kMaxHeaderName  = 256;
static constexpr size_t kMaxHeaderValue = 8192;
static constexpr size_t kMaxRequestLine = 16384;
static constexpr size_t kMaxBodyBuf     = 64*1024*1024; // 64 MiB
static constexpr size_t kSendBufSize    = 64*1024;
static constexpr size_t kRecvBufSize    = 64*1024;

} // namespace httpd
