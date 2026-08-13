// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// RFC 7541: HPACK implementation
#include "Hpack.h"
#include <stdexcept>
#include <cstring>

namespace httpd {

// ── RFC 7541 Appendix A: static table ────────────────────────────────────────
static const HpackHeader kStaticTable[62] = {
    {"",""},                               // index 0 unused
    {":authority",""},                     // 1
    {":method","GET"},                     // 2
    {":method","POST"},                    // 3
    {":path","/"},                         // 4
    {":path","/index.html"},               // 5
    {":scheme","http"},                    // 6
    {":scheme","https"},                   // 7
    {":status","200"},                     // 8
    {":status","204"},                     // 9
    {":status","206"},                     // 10
    {":status","304"},                     // 11
    {":status","400"},                     // 12
    {":status","404"},                     // 13
    {":status","500"},                     // 14
    {"accept-charset",""},                 // 15
    {"accept-encoding","gzip, deflate"},   // 16
    {"accept-language",""},                // 17
    {"accept-ranges",""},                  // 18
    {"accept",""},                         // 19
    {"access-control-allow-origin",""},    // 20
    {"age",""},                            // 21
    {"allow",""},                          // 22
    {"authorization",""},                  // 23
    {"cache-control",""},                  // 24
    {"content-disposition",""},            // 25
    {"content-encoding",""},               // 26
    {"content-language",""},               // 27
    {"content-length",""},                 // 28
    {"content-location",""},               // 29
    {"content-range",""},                  // 30
    {"content-type",""},                   // 31
    {"cookie",""},                         // 32
    {"date",""},                           // 33
    {"etag",""},                           // 34
    {"expect",""},                         // 35
    {"expires",""},                        // 36
    {"from",""},                           // 37
    {"host",""},                           // 38
    {"if-match",""},                       // 39
    {"if-modified-since",""},              // 40
    {"if-none-match",""},                  // 41
    {"if-range",""},                       // 42
    {"if-unmodified-since",""},            // 43
    {"last-modified",""},                  // 44
    {"link",""},                           // 45
    {"location",""},                       // 46
    {"max-forwards",""},                   // 47
    {"proxy-authenticate",""},             // 48
    {"proxy-authorization",""},            // 49
    {"range",""},                          // 50
    {"referer",""},                        // 51
    {"refresh",""},                        // 52
    {"retry-after",""},                    // 53
    {"server",""},                         // 54
    {"set-cookie",""},                     // 55
    {"strict-transport-security",""},      // 56
    {"transfer-encoding",""},              // 57
    {"user-agent",""},                     // 58
    {"vary",""},                           // 59
    {"via",""},                            // 60
    {"www-authenticate",""},               // 61
};

const HpackHeader& HpackStatic::entry(size_t idx) {
    if(idx<1||idx>kSize) return kStaticTable[0];
    return kStaticTable[idx];
}

// ── Dynamic table ─────────────────────────────────────────────────────────────
void HpackDynTable::insert(std::string name, std::string value) {
    HpackHeader h{std::move(name),std::move(value)};
    size_t es=entrySize(h);
    if(es>maxSize_) { entries_.clear(); size_=0; return; }
    entries_.push_front(std::move(h));
    size_+=es;
    evict();
}
void HpackDynTable::evict() {
    while(size_>maxSize_&&!entries_.empty()) {
        size_-=entrySize(entries_.back());
        entries_.pop_back();
    }
}
const HpackHeader* HpackDynTable::get(size_t idx) const {
    // idx is 1-based in combined table; dynamic starts at 62
    if(idx<=HpackStatic::kSize) return &kStaticTable[idx];
    size_t di=idx-HpackStatic::kSize-1;
    if(di>=entries_.size()) return nullptr;
    return &entries_[di];
}
size_t HpackDynTable::findName(const std::string& name) const {
    for(size_t i=1;i<=HpackStatic::kSize;++i)
        if(kStaticTable[i].name==name) return i;
    for(size_t i=0;i<entries_.size();++i)
        if(entries_[i].name==name) return HpackStatic::kSize+1+i;
    return 0;
}
size_t HpackDynTable::findNameValue(const std::string& name, const std::string& val) const {
    for(size_t i=1;i<=HpackStatic::kSize;++i)
        if(kStaticTable[i].name==name&&kStaticTable[i].value==val) return i;
    for(size_t i=0;i<entries_.size();++i)
        if(entries_[i].name==name&&entries_[i].value==val) return HpackStatic::kSize+1+i;
    return 0;
}

// ── Huffman code table (RFC 7541 Appendix B) ─────────────────────────────────
// Stored as {code, bits} for each byte 0..255 + EOS
struct HuffCode { uint32_t code; uint8_t bits; };
static const HuffCode kHuff[257] = {
    {0x1ff8,13},{0x7fffd8,23},{0xfffffe2,28},{0xfffffe3,28},{0xfffffe4,28},
    {0xfffffe5,28},{0xfffffe6,28},{0xfffffe7,28},{0xfffffe8,28},{0xffffea,24},
    {0x3ffffffc,30},{0xfffffe9,28},{0xfffffea,28},{0x3ffffffd,30},{0xfffffeb,28},
    {0xfffffec,28},{0xfffffed,28},{0xfffffee,28},{0xfffffef,28},{0xffffff0,28},
    {0xffffff1,28},{0xffffff2,28},{0x3ffffffe,30},{0xffffff3,28},{0xffffff4,28},
    {0xffffff5,28},{0xffffff6,28},{0xffffff7,28},{0xffffff8,28},{0xffffff9,28},
    {0xffffffa,28},{0xffffffb,28},{0x14,6},{0x3f8,10},{0x3f9,10},{0xffa,12},
    {0x1ff9,13},{0x15,6},{0xf8,8},{0x7fa,11},{0x3fa,10},{0x3fb,10},{0xf9,8},
    {0x7fb,11},{0xfa,8},{0x16,6},{0x17,6},{0x18,6},{0x0,5},{0x1,5},{0x2,5},
    {0x19,6},{0x1a,6},{0x1b,6},{0x1c,6},{0x1d,6},{0x1e,6},{0x1f,6},{0x5c,7},
    {0xfb,8},{0x7ffc,15},{0x20,6},{0xffb,12},{0x3fc,10},{0x1ffa,13},{0x21,6},
    {0x5d,7},{0x5e,7},{0x5f,7},{0x60,7},{0x61,7},{0x62,7},{0x63,7},{0x64,7},
    {0x65,7},{0x66,7},{0x67,7},{0x68,7},{0x69,7},{0x6a,7},{0x6b,7},{0x6c,7},
    {0x6d,7},{0x6e,7},{0x6f,7},{0x70,7},{0x71,7},{0x72,7},{0xfc,8},{0x73,7},
    {0xfd,8},{0x1ffb,13},{0x7fff0,19},{0x1ffc,13},{0x3ffc,14},{0x22,6},{0x7ffd,15},
    {0x3,5},{0x23,6},{0x4,5},{0x24,6},{0x5,5},{0x25,6},{0x26,6},{0x27,6},
    {0x6,5},{0x74,7},{0x75,7},{0x28,6},{0x29,6},{0x2a,6},{0x7,5},{0x2b,6},
    {0x76,7},{0x2c,6},{0x8,5},{0x9,5},{0x2d,6},{0x77,7},{0x78,7},{0x79,7},
    {0x7a,7},{0x7b,7},{0x7ffe,15},{0x7fc,11},{0x3ffd,14},{0x1ffd,13},{0xffffffc,28},
    {0xfffe6,20},{0x3fffd2,22},{0xfffe7,20},{0xfffe8,20},{0x3fffd3,22},{0x3fffd4,22},
    {0x3fffd5,22},{0x7fffd9,23},{0x3fffd6,22},{0x7fffda,23},{0x7fffdb,23},{0x7fffdc,23},
    {0x7fffdd,23},{0x7fffde,23},{0xffffeb,24},{0x7fffdf,23},{0xffffec,24},{0xffffed,24},
    {0x3fffd7,22},{0x7fffe0,23},{0xffffee,24},{0x7fffe1,23},{0x7fffe2,23},{0x7fffe3,23},
    {0x7fffe4,23},{0x1fffdc,21},{0x3fffd8,22},{0x7fffe5,23},{0x3fffd9,22},{0x7fffe6,23},
    {0x7fffe7,23},{0xffffef,24},{0x3fffda,22},{0x1fffdd,21},{0xfffe9,20},{0x3fffdb,22},
    {0x3fffdc,22},{0x7fffe8,23},{0x7fffe9,23},{0x1fffde,21},{0x7fffea,23},{0x3fffdd,22},
    {0x3fffde,22},{0xfffff0,24},{0x1fffdf,21},{0x3fffdf,22},{0x7fffeb,23},{0x7fffec,23},
    {0x1fffe0,21},{0x1fffe1,21},{0x3fffe0,22},{0x1fffe2,21},{0x7fffed,23},{0x3fffe1,22},
    {0x7fffee,23},{0x7fffef,23},{0xfffea,20},{0x3fffe2,22},{0x3fffe3,22},{0x3fffe4,22},
    {0x7ffff0,23},{0x3fffe5,22},{0x3fffe6,22},{0x7ffff1,23},{0x3ffffe0,26},{0x3ffffe1,26},
    {0xfffeb,20},{0x7fff1,19},{0x3fffe7,22},{0x7ffff2,23},{0x3fffe8,22},{0x1ffffec,25},
    {0x3ffffe2,26},{0x3ffffe3,26},{0x3ffffe4,26},{0x7ffffde,27},{0x7ffffdf,27},
    {0x3ffffe5,26},{0xfffff1,24},{0x1ffffed,25},{0x7fff2,19},{0x1fffe3,21},
    {0x3ffffe6,26},{0x7ffffe0,27},{0x7ffffe1,27},{0x3ffffe7,26},{0x7ffffe2,27},
    {0xfffff2,24},{0x1fffe4,21},{0x1fffe5,21},{0x3ffffe8,26},{0x3ffffe9,26},
    {0xffffffd,28},{0x7ffffe3,27},{0x7ffffe4,27},{0x7ffffe5,27},{0xfffec,20},
    {0xfffff3,24},{0xfffed,20},{0x1fffe6,21},{0x3fffe9,22},{0x1fffe7,21},
    {0x1fffe8,21},{0x7ffff3,23},{0x3fffea,22},{0x3fffeb,22},{0x1ffffee,25},
    {0x1ffffef,25},{0xfffff4,24},{0xfffff5,24},{0x3ffffea,26},{0x7ffff4,23},
    {0x3ffffeb,26},{0x7ffffe6,27},{0x3ffffec,26},{0x3ffffed,26},{0x7ffffe7,27},
    {0x7ffffe8,27},{0x7ffffe9,27},{0x7ffffea,27},{0x7ffffeb,27},{0xffffffe,28},
    {0x7ffffec,27},{0x7ffffed,27},{0x7ffffee,27},{0x7ffffef,27},{0x7fffff0,27},
    {0x3ffffee,26},{0x3fffffff,30} // EOS
};

// ── Huffman decode tree node ──────────────────────────────────────────────────
struct HNode { int16_t child[2]{-1,-1}; int16_t sym=-1; };
static std::vector<HNode> buildHuffTree() {
    std::vector<HNode> t(1);
    for(int s=0;s<256;++s) {
        uint32_t code=kHuff[s].code; uint8_t bits=kHuff[s].bits;
        int node=0;
        for(int b=bits-1;b>=0;--b) {
            int bit=(code>>b)&1;
            if(t[node].child[bit]<0) {
                t[node].child[bit]=(int16_t)t.size();
                t.emplace_back();
            }
            node=t[node].child[bit];
        }
        t[node].sym=(int16_t)s;
    }
    return t;
}
static const std::vector<HNode>& huffTree() {
    static auto t=buildHuffTree(); return t;
}

// ── Decoder implementation ─────────────────────────────────────────────────────
HpackDecoder::HpackDecoder() {}

uint64_t HpackDecoder::decodeInt(const uint8_t*& p, const uint8_t* end, uint8_t prefBits) {
    if(p>=end) return 0;
    uint64_t mask=(1u<<prefBits)-1;
    uint64_t val=(*p++)&mask;
    if(val<mask) return val;
    // multi-byte
    uint64_t m=0; uint8_t b;
    do {
        if(p>=end) return val;
        b=*p++;
        val+=((uint64_t)(b&0x7f))<<m;
        m+=7;
    } while(b&0x80);
    return val;
}

bool HpackDecoder::huffDecode(const uint8_t* in, size_t inLen, std::string& out) {
    const auto& t=huffTree();
    int node=0;
    for(size_t i=0;i<inLen;++i) {
        for(int b=7;b>=0;--b) {
            int bit=(in[i]>>b)&1;
            int16_t ch=t[node].child[bit];
            if(ch<0) return false; // invalid code
            node=ch;
            if(t[node].sym>=0) { out+=(char)t[node].sym; node=0; }
        }
    }
    return true;
}

bool HpackDecoder::decodeStr(const uint8_t*& p, const uint8_t* end, std::string& out) {
    if(p>=end) return false;
    bool huff=(*p&0x80)!=0;
    uint64_t slen=decodeInt(p,end,7);
    if(p+slen>end) return false;
    if(huff) { bool ok=huffDecode(p,(size_t)slen,out); p+=slen; return ok; }
    out.assign((const char*)p,(size_t)slen); p+=slen;
    return true;
}

bool HpackDecoder::decode(const uint8_t* data, size_t len,
                          std::vector<HpackHeader>& out) {
    const uint8_t* p=data, *end=data+len;
    while(p<end) {
        uint8_t first=*p;

        if(first&0x80) {
            // §6.1 Indexed header field representation
            uint64_t idx=decodeInt(p,end,7);
            const HpackHeader* h=table_.get((size_t)idx);
            if(!h) return false;
            out.push_back(*h);
        } else if((first&0xC0)==0x40) {
            // §6.2.1 Literal with incremental indexing
            uint64_t idx=decodeInt(p,end,6);
            HpackHeader h;
            if(idx==0) { if(!decodeStr(p,end,h.name)) return false; }
            else { const HpackHeader* s=table_.get((size_t)idx); if(!s) return false; h.name=s->name; }
            if(!decodeStr(p,end,h.value)) return false;
            table_.insert(h.name,h.value);
            out.push_back(h);
        } else if((first&0xF0)==0x00) {
            // §6.2.2 Literal without indexing
            uint64_t idx=decodeInt(p,end,4);
            HpackHeader h;
            if(idx==0) { if(!decodeStr(p,end,h.name)) return false; }
            else { const HpackHeader* s=table_.get((size_t)idx); if(!s) return false; h.name=s->name; }
            if(!decodeStr(p,end,h.value)) return false;
            out.push_back(h);
        } else if((first&0xF0)==0x10) {
            // §6.2.3 Literal never indexed
            uint64_t idx=decodeInt(p,end,4);
            HpackHeader h;
            if(idx==0) { if(!decodeStr(p,end,h.name)) return false; }
            else { const HpackHeader* s=table_.get((size_t)idx); if(!s) return false; h.name=s->name; }
            if(!decodeStr(p,end,h.value)) return false;
            out.push_back(h);
        } else if((first&0xE0)==0x20) {
            // §6.3 Dynamic table size update
            uint64_t newSize=decodeInt(p,end,5);
            table_.setMaxSize((size_t)newSize);
        } else {
            return false;
        }
    }
    return true;
}

// ── Encoder implementation ────────────────────────────────────────────────────
HpackEncoder::HpackEncoder() {}

void HpackEncoder::encodeInt(uint8_t prefix, uint8_t prefBits, std::vector<uint8_t>& out) {
    uint8_t mask=(1u<<prefBits)-1;
    if(prefix<mask) { out.back()=((out.back()&~mask)|prefix); return; }
    out.back()=out.back()|mask;
    prefix-=mask;
    while(prefix>=128) { out.push_back((uint8_t)((prefix&0x7F)|0x80)); prefix>>=7; }
    out.push_back((uint8_t)prefix);
}

static size_t huffEncodedLen(const std::string& s) {
    size_t bits=0; for(unsigned char c:s) bits+=kHuff[c].bits;
    return (bits+7)/8;
}

std::vector<uint8_t> HpackEncoder::huffEncode(const std::string& s) {
    std::vector<uint8_t> out;
    uint64_t buf=0; int bufBits=0;
    for(unsigned char c:s) {
        uint32_t code=kHuff[c].code; uint8_t bits=kHuff[c].bits;
        buf=(buf<<bits)|code; bufBits+=bits;
        while(bufBits>=8) { bufBits-=8; out.push_back((uint8_t)(buf>>bufBits)); }
    }
    // EOS padding: pad with MSBs of EOS (0x3fffffff = 30 bits of 1)
    if(bufBits>0) { buf<<=8-bufBits; buf|=((1<<(8-bufBits))-1); out.push_back((uint8_t)buf); }
    return out;
}

void HpackEncoder::encodeStr(const std::string& s, bool huff, std::vector<uint8_t>& out) {
    if(huff) {
        auto enc=huffEncode(s);
        // huffman bit + length
        uint8_t hb=0x80; out.push_back(hb);
        uint64_t l=enc.size();
        uint8_t mask=0x7F;
        if(l<(uint64_t)mask) { out.back()|=(uint8_t)l; }
        else { out.back()|=mask; l-=mask; while(l>=128){out.push_back((uint8_t)((l&0x7F)|0x80));l>>=7;} out.push_back((uint8_t)l); }
        out.insert(out.end(),enc.begin(),enc.end());
    } else {
        out.push_back(0); // no huffman
        uint64_t l=s.size();
        uint8_t mask=0x7F;
        if(l<(uint64_t)mask) { out.back()|=(uint8_t)l; }
        else { out.back()|=mask; l-=mask; while(l>=128){out.push_back((uint8_t)((l&0x7F)|0x80));l>>=7;} out.push_back((uint8_t)l); }
        out.insert(out.end(),s.begin(),s.end());
    }
}

void HpackEncoder::encode(const std::vector<HpackHeader>& hdrs, std::vector<uint8_t>& out) {
    for(const auto& h:hdrs) {
        // Try full indexed
        size_t fi=table_.findNameValue(h.name,h.value);
        if(fi>0) {
            out.push_back(0x80); encodeInt((uint8_t)fi,7,out); continue;
        }
        // Literal with incremental indexing
        size_t ni=table_.findName(h.name);
        out.push_back(0x40);
        if(ni>0) encodeInt((uint8_t)ni,6,out);
        else { encodeInt(0,6,out); encodeStr(h.name,true,out); }
        encodeStr(h.value,true,out);
        table_.insert(h.name,h.value);
    }
}

} // namespace httpd
