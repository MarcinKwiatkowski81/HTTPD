// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// URL rewrite engine — applies an ordered list of RewriteRules to a request.
#pragma once
#include "Config.h"
#include "HttpParser.h"
#include <string>
#include <vector>
#include <regex>

namespace httpd {

// Result of applying the rewrite pipeline to one request.
struct RewriteResult {
    enum class Action {
        None,       // request unchanged
        Rewritten,  // path was modified; continue normal dispatch
        Last,       // path modified; skip remaining rules (like [L])
        Redirect,   // send HTTP redirect to client
        Forbidden,  // send 403
    };
    Action      action       = Action::None;
    std::string newPath;     // new URL path (Rewritten / Last / Redirect)
    std::string newQuery;    // new query string (empty = keep original)
    int         redirectCode = 302;
};

class RewriteEngine {
public:
    // Compile rules (pre-compiles regexes). Returns false if any regex is bad.
    bool compile(const std::vector<RewriteRule>& rules, std::string& error);

    // Apply rules to req. Modifies req.url.path / query in-place and returns
    // what happened so the caller can decide the next step.
    RewriteResult apply(RawRequest& req) const;

    bool empty() const { return compiled_.empty(); }

private:
    struct CompiledRule {
        std::regex         re;
        const RewriteRule* src = nullptr;
    };
    std::vector<CompiledRule> compiled_;

    static std::string applyReplacement(const std::string& repl,
                                        const std::smatch& m);
};

} // namespace httpd
