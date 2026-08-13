// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
#include "Module.h"
#include <dlfcn.h>
#include <cstdio>
#include <algorithm>

namespace httpd {

ModuleDesc* ModuleRegistry::load(const std::string& soPath, const std::string& config) {
    void* h=dlopen(soPath.c_str(),RTLD_NOW|RTLD_LOCAL);
    if(!h) { fprintf(stderr,"[MODULE] dlopen(%s): %s\n",soPath.c_str(),dlerror()); return nullptr; }

    ModuleDesc m; m.soPath=soPath; m.handle=h;

    auto nameFn =(httpd_module_name_fn)   dlsym(h,"httpd_module_name");
    auto verFn  =(httpd_module_version_fn) dlsym(h,"httpd_module_version");
    m.init_fn       =(httpd_module_init_fn)      dlsym(h,"httpd_module_init");
    m.fini_fn       =(httpd_module_fini_fn)      dlsym(h,"httpd_module_fini");
    m.handle_fn     =(httpd_module_handle_fn)    dlsym(h,"httpd_module_handle");
    m.extensions_fn =(httpd_module_extensions_fn)dlsym(h,"httpd_module_extensions");

    if(!nameFn||!m.handle_fn) {
        fprintf(stderr,"[MODULE] %s: missing required symbols\n",soPath.c_str());
        dlclose(h); return nullptr;
    }
    m.name   =nameFn();
    m.version=verFn?verFn():"?";

    if(m.extensions_fn) {
        const char** exts=m.extensions_fn();
        for(;exts&&*exts;++exts) m.extensions.push_back(*exts);
    }
    if(m.init_fn && m.init_fn(config.c_str())!=0) {
        fprintf(stderr,"[MODULE] %s: init failed\n",m.name.c_str());
        dlclose(h); return nullptr;
    }
    m.active=true;
    modules_.push_back(std::move(m));
    printf("[MODULE] Loaded %s %s extensions=[",
           modules_.back().name.c_str(), modules_.back().version.c_str());
    for(const auto& e:modules_.back().extensions) printf(".%s ",e.c_str());
    printf("]\n");
    return &modules_.back();
}

void ModuleRegistry::unload(const std::string& name) {
    auto it=std::find_if(modules_.begin(),modules_.end(),
                         [&](const ModuleDesc& m){ return m.name==name; });
    if(it==modules_.end()) return;
    if(it->fini_fn) it->fini_fn();
    if(it->handle)  dlclose(it->handle);
    modules_.erase(it);
}

ModuleDesc* ModuleRegistry::findByExt(const std::string& ext) {
    for(auto& m:modules_) {
        if(!m.active) continue;
        for(const auto& e:m.extensions) if(e==ext) return &m;
    }
    return nullptr;
}

bool ModuleRegistry::runAll(RequestCtx& ctx) {
    for(auto& m:modules_) {
        if(!m.active||!m.handle_fn) continue;
        if(!ctx.scriptPath.empty()&&!m.extensions.empty()) {
            auto dot=ctx.scriptPath.rfind('.');
            std::string ext=(dot!=std::string::npos)?ctx.scriptPath.substr(dot+1):"";
            bool match=false;
            for(const auto& e:m.extensions) if(e==ext){match=true;break;}
            if(!match) continue;
        }
        int r=m.handle_fn(&ctx);
        if(r>0||ctx.handled) return true;
        if(r<0) { ctx.resp->statusCode=500; return true; }
    }
    return false;
}

ModuleRegistry::~ModuleRegistry() {
    for(auto& m:modules_) {
        if(m.fini_fn) m.fini_fn();
        if(m.handle)  dlclose(m.handle);
    }
}

} // namespace httpd
