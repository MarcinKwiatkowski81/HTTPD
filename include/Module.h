// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// Module system: .so plugins with stable C ABI
#pragma once
#include "HttpCommon.h"
#include "HttpParser.h"
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace httpd {

// ── Module hook points ────────────────────────────────────────────────────────
struct RequestCtx {
    RawRequest*  req       = nullptr;
    RawResponse* resp      = nullptr;
    std::string  docRoot;
    std::string  scriptPath;
    std::string  pathInfo;
    bool         handled   = false;  // set to true to skip further processing
};

// ── C ABI exported from each module .so ──────────────────────────────────────
// Every module must export these symbols with C linkage:
extern "C" {
    typedef const char* (*httpd_module_name_fn)();
    typedef const char* (*httpd_module_version_fn)();
    // Called once after loading.
    typedef int  (*httpd_module_init_fn)(const char* config);
    // Called once before unloading.
    typedef void (*httpd_module_fini_fn)();
    // Called for each request. Returns 0=not handled, 1=handled, <0=error.
    typedef int  (*httpd_module_handle_fn)(RequestCtx* ctx);
    // File extensions this module handles (NULL-terminated array of strings)
    typedef const char** (*httpd_module_extensions_fn)();
}

// ── Module descriptor (C++ side) ─────────────────────────────────────────────
struct ModuleDesc {
    std::string name;
    std::string version;
    std::string soPath;
    void*       handle     = nullptr;  // dlopen handle
    bool        active     = false;

    // Resolved function pointers
    httpd_module_init_fn       init_fn       = nullptr;
    httpd_module_fini_fn       fini_fn       = nullptr;
    httpd_module_handle_fn     handle_fn     = nullptr;
    httpd_module_extensions_fn extensions_fn = nullptr;

    std::vector<std::string>   extensions;  // from extensions_fn()
};

// ── Module registry ───────────────────────────────────────────────────────────
class ModuleRegistry {
public:
    // Load a module from .so path. Returns nullptr on failure.
    ModuleDesc* load(const std::string& soPath, const std::string& config = "");

    // Unload by name.
    void unload(const std::string& name);

    // Find module that handles the given file extension.
    ModuleDesc* findByExt(const std::string& ext);

    // Run all modules for the request. Returns true if any handled it.
    bool runAll(RequestCtx& ctx);

    ~ModuleRegistry();

private:
    std::vector<ModuleDesc> modules_;
};

} // namespace httpd
