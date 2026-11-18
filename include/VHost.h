// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// Virtual host selector — matches an incoming request to a VirtualHost config.
#pragma once
#include "Config.h"
#include <string>
#include <string_view>

namespace httpd {

class VHostSelector {
public:
    explicit VHostSelector(const YamlConfig& cfg) : cfg_(cfg) {}

    // Find the best-matching virtual host for the given Host header value.
    // Returns nullptr when no vhost matches (caller uses global defaults).
    // Matching rules (in order):
    //   1. Exact match of host[:port] against serverNames
    //   2. Wildcard prefix match (*.example.com)
    //   3. First vhost with no serverNames (catch-all)
    const VirtualHost* match(std::string_view hostHeader) const;

private:
    const YamlConfig& cfg_;

    static bool matchName(std::string_view pattern, std::string_view host);
    // Strip the port part from a host:port header value.
    static std::string_view stripPort(std::string_view h);
};

} // namespace httpd
