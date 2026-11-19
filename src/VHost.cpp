// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
#include "VHost.h"
#include <algorithm>
#include <cctype>

namespace httpd {

std::string_view VHostSelector::stripPort(std::string_view h) {
    // IPv6: "[::1]:8080" — find ']' first
    if(!h.empty() && h[0]=='[') {
        auto rb = h.find(']');
        if(rb!=std::string_view::npos) {
            // everything after ']' is port
            return h.substr(1, rb-1);
        }
        return h;
    }
    auto colon = h.rfind(':');
    if(colon != std::string_view::npos) return h.substr(0, colon);
    return h;
}

bool VHostSelector::matchName(std::string_view pattern, std::string_view host) {
    // Case-insensitive compare
    auto ci_eq = [](char a, char b) {
        return std::tolower((unsigned char)a) == std::tolower((unsigned char)b);
    };

    // Wildcard: "*.example.com" matches "foo.example.com"
    if(pattern.size() >= 2 && pattern[0]=='*' && pattern[1]=='.') {
        std::string_view suffix = pattern.substr(1); // ".example.com"
        if(host.size() <= suffix.size()) return false;
        std::string_view hostSuffix = host.substr(host.size() - suffix.size());
        // suffix must match the end of host
        if(hostSuffix.size() != suffix.size()) return false;
        for(size_t i = 0; i < suffix.size(); ++i)
            if(!ci_eq(hostSuffix[i], suffix[i])) return false;
        // and the part before the suffix must not contain another dot
        // (so "*.a.com" does not match "x.y.a.com")
        std::string_view prefix = host.substr(0, host.size() - suffix.size());
        return prefix.find('.') == std::string_view::npos;
    }

    // Exact match (case-insensitive)
    if(pattern.size() != host.size()) return false;
    for(size_t i = 0; i < pattern.size(); ++i)
        if(!ci_eq(pattern[i], host[i])) return false;
    return true;
}

const VirtualHost* VHostSelector::match(std::string_view hostHeader) const {
    if(cfg_.vhosts.empty()) return nullptr;

    std::string_view host = stripPort(hostHeader);

    // Pass 1: exact match
    for(const auto& vh : cfg_.vhosts) {
        for(const auto& name : vh.serverNames) {
            if(name[0] != '*' && matchName(name, host)) return &vh;
        }
    }

    // Pass 2: wildcard match
    for(const auto& vh : cfg_.vhosts) {
        for(const auto& name : vh.serverNames) {
            if(name[0] == '*' && matchName(name, host)) return &vh;
        }
    }

    // Pass 3: catch-all (vhost with no server_names)
    for(const auto& vh : cfg_.vhosts) {
        if(vh.serverNames.empty()) return &vh;
    }

    return nullptr;
}

} // namespace httpd
