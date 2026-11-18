// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
#include "Rewrite.h"
#include <cstdio>

namespace httpd {

bool RewriteEngine::compile(const std::vector<RewriteRule>& rules,
                             std::string& error) {
    compiled_.clear();
    compiled_.reserve(rules.size());
    for(const auto& r : rules) {
        try {
            CompiledRule cr;
            cr.re  = std::regex(r.pattern,
                                std::regex::ECMAScript | std::regex::optimize);
            cr.src = &r;
            compiled_.push_back(std::move(cr));
        } catch(const std::regex_error& e) {
            error = "Rewrite pattern error in \"" + r.pattern + "\": " +
                    e.what();
            compiled_.clear();
            return false;
        }
    }
    return true;
}

// Apply $1..$9 back-references and literal text from the replacement string.
std::string RewriteEngine::applyReplacement(const std::string& repl,
                                             const std::smatch& m) {
    std::string out;
    out.reserve(repl.size() * 2);
    for(size_t i = 0; i < repl.size(); ++i) {
        if(repl[i] == '$' && i + 1 < repl.size()) {
            char next = repl[i+1];
            if(next >= '1' && next <= '9') {
                int idx = next - '0';
                if(idx < (int)m.size() && m[idx].matched)
                    out += m[idx].str();
                ++i;
                continue;
            } else if(next == '0') {
                out += m[0].str();  // $0 = whole match
                ++i;
                continue;
            }
        }
        out += repl[i];
    }
    return out;
}

RewriteResult RewriteEngine::apply(RawRequest& req) const {
    RewriteResult result;

    for(const auto& cr : compiled_) {
        const RewriteRule& rule = *cr.src;

        // Optional condition: check request header
        if(!rule.condHeader.empty()) {
            std::string hval = std::string(req.headers.get(rule.condHeader));
            if(hval.empty()) continue;
            if(!rule.condValue.empty()) {
                try {
                    std::regex condRe(rule.condValue,
                                      std::regex::ECMAScript|std::regex::optimize);
                    if(!std::regex_search(hval, condRe)) continue;
                } catch(...) {
                    if(hval != rule.condValue) continue;
                }
            }
        }

        std::smatch m;
        const std::string& path = req.url.path;

        if(!std::regex_search(path, m, cr.re)) continue;

        // Forbidden flag: immediately return 403
        if(rule.flag == RewriteRule::Flag::Forbidden) {
            result.action = RewriteResult::Action::Forbidden;
            return result;
        }

        // Build new path from replacement
        std::string newPath = std::regex_replace(path, cr.re, rule.replacement,
                                                 std::regex_constants::format_first_only);

        // Split off any query string appended in replacement
        std::string newQuery;
        auto qpos = newPath.find('?');
        if(qpos != std::string::npos) {
            newQuery = newPath.substr(qpos+1);
            newPath  = newPath.substr(0, qpos);
        } else {
            newQuery = req.url.query;  // keep original
        }

        if(rule.flag == RewriteRule::Flag::Redirect) {
            result.action       = RewriteResult::Action::Redirect;
            result.newPath      = newPath;
            result.newQuery     = newQuery;
            result.redirectCode = rule.redirectCode;
            return result;
        }

        // Apply to request and continue (or stop if [L])
        req.url.path  = newPath;
        req.url.query = newQuery;
        // Rebuild target string so Host:// and other consumers see the new path
        req.target = newPath + (newQuery.empty() ? "" : "?" + newQuery);

        if(rule.flag == RewriteRule::Flag::Last) {
            result.action   = RewriteResult::Action::Last;
            result.newPath  = newPath;
            result.newQuery = newQuery;
            return result;
        }

        result.action   = RewriteResult::Action::Rewritten;
        result.newPath  = newPath;
        result.newQuery = newQuery;
        // Continue to next rule
    }

    return result;
}

} // namespace httpd
