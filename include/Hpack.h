// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// RFC 7541: HPACK — Header Compression for HTTP/2
#pragma once
#include <string>
#include <vector>
#include <deque>
#include <cstdint>

namespace httpd {

struct HpackHeader { std::string name, value; };

// ── HPACK static table (RFC 7541 Appendix A) ──────────────────────────────────
struct HpackStatic {
    static constexpr size_t kSize = 61;
    static const HpackHeader& entry(size_t idx); // 1-based
};

// ── HPACK dynamic table ───────────────────────────────────────────────────────
class HpackDynTable {
public:
    void setMaxSize(size_t s) { maxSize_=s; evict(); }
    size_t maxSize() const { return maxSize_; }
    size_t size()    const { return size_; }
    size_t count()   const { return entries_.size(); }

    void insert(std::string name, std::string value);
    // Index into combined table: 1..61 = static, 62+ = dynamic (newest=62)
    const HpackHeader* get(size_t idx) const;
    size_t findName(const std::string& name) const;               // returns 0 if not found
    size_t findNameValue(const std::string& name, const std::string& val) const;

private:
    void evict();
    std::deque<HpackHeader> entries_;
    size_t size_    = 0;
    size_t maxSize_ = 4096;
    static size_t entrySize(const HpackHeader& h) { return h.name.size()+h.value.size()+32; }
};

// ── HPACK Decoder ─────────────────────────────────────────────────────────────
class HpackDecoder {
public:
    HpackDecoder();
    // Decode a complete header block; returns false on error.
    bool decode(const uint8_t* data, size_t len,
                std::vector<HpackHeader>& out);
    void setTableSize(size_t s) { table_.setMaxSize(s); }
    HpackDynTable& table() { return table_; }

private:
    HpackDynTable table_;
    static uint64_t decodeInt(const uint8_t*& p, const uint8_t* end, uint8_t prefixBits);
    static bool decodeStr(const uint8_t*& p, const uint8_t* end, std::string& out);
    static bool huffDecode(const uint8_t* in, size_t inLen, std::string& out);
};

// ── HPACK Encoder ─────────────────────────────────────────────────────────────
class HpackEncoder {
public:
    HpackEncoder();
    // Encode a list of headers; appends to out.
    void encode(const std::vector<HpackHeader>& hdrs, std::vector<uint8_t>& out);
    void setTableSize(size_t s) { table_.setMaxSize(s); }

private:
    HpackDynTable table_;
    void encodeInt(uint8_t prefix, uint8_t prefixBits, std::vector<uint8_t>& out);
    void encodeStr(const std::string& s, bool huffman, std::vector<uint8_t>& out);
    static std::vector<uint8_t> huffEncode(const std::string& s);
};

} // namespace httpd
