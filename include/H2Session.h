// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// RFC 9113: HTTP/2 session over a TLS or cleartext TCP socket
#pragma once
#include "Hpack.h"
#include "HttpCommon.h"
#include "HttpParser.h"
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>

namespace httpd {

// ── Frame types (RFC 9113 §6) ─────────────────────────────────────────────────
enum class H2FrameType : uint8_t {
    DATA          = 0x0,
    HEADERS       = 0x1,
    PRIORITY      = 0x2,
    RST_STREAM    = 0x3,
    SETTINGS      = 0x4,
    PUSH_PROMISE  = 0x5,
    PING          = 0x6,
    GOAWAY        = 0x7,
    WINDOW_UPDATE = 0x8,
    CONTINUATION  = 0x9,
};

// ── Frame flags ───────────────────────────────────────────────────────────────
namespace H2Flags {
    static constexpr uint8_t END_STREAM  = 0x1;
    static constexpr uint8_t END_HEADERS = 0x4;
    static constexpr uint8_t PADDED      = 0x8;
    static constexpr uint8_t PRIORITY    = 0x20;
    static constexpr uint8_t ACK         = 0x1;
}

// ── Settings identifiers (RFC 9113 §6.5) ─────────────────────────────────────
namespace H2Setting {
    static constexpr uint16_t HEADER_TABLE_SIZE      = 0x1;
    static constexpr uint16_t ENABLE_PUSH            = 0x2;
    static constexpr uint16_t MAX_CONCURRENT_STREAMS = 0x3;
    static constexpr uint16_t INITIAL_WINDOW_SIZE    = 0x4;
    static constexpr uint16_t MAX_FRAME_SIZE         = 0x5;
    static constexpr uint16_t MAX_HEADER_LIST_SIZE   = 0x6;
}

// ── Error codes (RFC 9113 §7) ─────────────────────────────────────────────────
namespace H2Error {
    static constexpr uint32_t NO_ERROR            = 0;
    static constexpr uint32_t PROTOCOL_ERROR      = 1;
    static constexpr uint32_t INTERNAL_ERROR      = 2;
    static constexpr uint32_t FLOW_CONTROL_ERROR  = 3;
    static constexpr uint32_t SETTINGS_TIMEOUT    = 4;
    static constexpr uint32_t STREAM_CLOSED       = 5;
    static constexpr uint32_t FRAME_SIZE_ERROR    = 6;
    static constexpr uint32_t REFUSED_STREAM      = 7;
    static constexpr uint32_t CANCEL              = 8;
    static constexpr uint32_t COMPRESSION_ERROR   = 9;
    static constexpr uint32_t ENHANCE_YOUR_CALM   = 11;
    static constexpr uint32_t INADEQUATE_SECURITY = 12;
}

// ── Raw frame ─────────────────────────────────────────────────────────────────
struct H2Frame {
    H2FrameType type   = H2FrameType::DATA;
    uint8_t     flags  = 0;
    uint32_t    streamId = 0;
    std::vector<uint8_t> payload;

    static constexpr size_t kHeaderLen = 9;
    // Serialise to wire bytes
    void serialise(std::vector<uint8_t>& out) const;
    // Deserialise; returns false if not enough data
    static bool parse(const uint8_t* data, size_t len, H2Frame& out, size_t& consumed);
};

// ── Stream state (RFC 9113 §5.1) ─────────────────────────────────────────────
enum class H2StreamState : uint8_t { Idle, Open, HalfClosedLocal, HalfClosedRemote, Closed };

struct H2Stream {
    uint32_t      id     = 0;
    H2StreamState state  = H2StreamState::Idle;
    int32_t       localWindow  = 65535;
    int32_t       remoteWindow = 65535;
    std::vector<HpackHeader> reqHeaders;
    std::string   reqBody;
    bool          headersDone  = false;
    bool          endStream    = false;
    // Assembled HTTP request
    std::shared_ptr<RawRequest> request;
};

// ── Settings ──────────────────────────────────────────────────────────────────
struct H2Settings {
    uint32_t headerTableSize      = 4096;
    uint32_t enablePush           = 0;     // server disables push
    uint32_t maxConcurrentStreams = 100;
    uint32_t initialWindowSize    = 65535;
    uint32_t maxFrameSize         = 16384;
    uint32_t maxHeaderListSize    = 65536;
};

// ── Callback types ────────────────────────────────────────────────────────────
using H2RequestCb = std::function<void(uint32_t streamId, std::shared_ptr<RawRequest>)>;

// ── HTTP/2 session ────────────────────────────────────────────────────────────
class H2Session {
public:
    H2Session();

    // Called from connection layer with raw received bytes.
    // Returns false on fatal error (must close connection).
    bool onData(const uint8_t* data, size_t len);

    // Send response on a stream.
    bool sendResponse(uint32_t streamId, const RawResponse& resp);

    // Register callback for complete requests.
    void setRequestCb(H2RequestCb cb) { onRequest_=std::move(cb); }

    // Retrieve pending output bytes (frames to send).
    std::vector<uint8_t> takeSendBuf();

    bool fatal() const { return fatal_; }
    bool goaway() const { return goaway_; }

private:
    static const char kClientPreface[];

    HpackDecoder  decoder_;
    HpackEncoder  encoder_;
    H2Settings    localSettings_;   // what we want
    H2Settings    remoteSettings_;  // what peer wants
    int32_t       connectionWindow_ = 65535; // connection-level recv window

    std::unordered_map<uint32_t, H2Stream> streams_;
    uint32_t lastPeerStream_ = 0;
    bool     prefaceDone_   = false;
    bool     settingsSent_  = false;
    bool     fatal_         = false;
    bool     goaway_        = false;
    std::string prefaceBuf_;
    size_t   prefacePos_    = 0;

    std::vector<uint8_t> sendBuf_;   // frames queued for sending
    H2RequestCb onRequest_;

    // Frame handlers
    bool handleFrame(H2Frame& f);
    bool handleHeaders(H2Frame& f);
    bool handleData(H2Frame& f);
    bool handleSettings(H2Frame& f);
    bool handleWindowUpdate(H2Frame& f);
    bool handlePing(H2Frame& f);
    bool handleRstStream(H2Frame& f);
    bool handleGoaway(H2Frame& f);
    void handlePriority(H2Frame& f);

    H2Stream& getOrCreateStream(uint32_t id);
    void assembleRequest(H2Stream& s);

    // Frame building
    void sendSettings(bool ack=false);
    void sendWindowUpdate(uint32_t streamId, uint32_t increment);
    void sendGoaway(uint32_t lastStream, uint32_t errorCode);
    void sendRstStream(uint32_t streamId, uint32_t errorCode);
    void queueFrame(const H2Frame& f);
};

} // namespace httpd
