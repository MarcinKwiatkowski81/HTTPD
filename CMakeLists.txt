cmake_minimum_required(VERSION 3.16)
project(httpd CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
message(STATUS "httpd | C++17 | ${CMAKE_BUILD_TYPE}")

# ── Global compile flags (NO -fvisibility=hidden here — set per-target below)
add_compile_options(-Wall -Wextra -Wno-unused-parameter)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O3 -march=native -flto)
    add_link_options(-flto)
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g3)
endif()

# ── Include paths ─────────────────────────────────────────────────────────────
include_directories(${CMAKE_SOURCE_DIR}/include)

# ── Required libraries ────────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB    REQUIRED)

find_path(LUA_INCLUDE_DIR    lua5.4/lua.h     PATHS /usr/include)
find_library(LUA_LIBRARY     NAMES lua5.4     PATHS /usr/lib/x86_64-linux-gnu)
if(LUA_INCLUDE_DIR AND LUA_LIBRARY)
    message(STATUS "  Lua 5.4 : ${LUA_LIBRARY}")
    set(HAVE_LUA TRUE)
else()
    message(WARNING "  Lua 5.4 not found — Lua module disabled")
    set(HAVE_LUA FALSE)
endif()

# ── Core library (hidden visibility — no public ABI leakage) ──────────────────
set(CORE_SOURCES
    src/HttpParser.cpp
    src/Hpack.cpp
    src/H2Session.cpp
    src/Cache.cpp
    src/FileCache.cpp
    src/Module.cpp
    src/Cgi.cpp
    src/TlsContext.cpp
    src/EventLoop.cpp
)
add_library(httpd_core STATIC ${CORE_SOURCES})
target_compile_options(httpd_core PRIVATE -fvisibility=hidden)
target_link_libraries(httpd_core
    PUBLIC OpenSSL::SSL OpenSSL::Crypto ZLIB::ZLIB
           Threads::Threads ${CMAKE_DL_LIBS}
)

# ── Server binary ─────────────────────────────────────────────────────────────
add_executable(httpd src/main.cpp)
target_compile_options(httpd PRIVATE -fvisibility=hidden)
target_link_libraries(httpd PRIVATE httpd_core)

# ── Lua module (.so) — default visibility so dlsym() can find the C ABI ───────
if(HAVE_LUA)
    add_library(lua_module MODULE modules/lua/lua_module.cpp)
    target_include_directories(lua_module PRIVATE ${LUA_INCLUDE_DIR})
    target_link_libraries(lua_module PRIVATE httpd_core ${LUA_LIBRARY})
    # IMPORTANT: modules must export their C ABI; do NOT use hidden visibility.
    target_compile_options(lua_module PRIVATE -fvisibility=default)
    target_compile_definitions(lua_module PRIVATE HAVE_LUA=1)
    set_target_properties(lua_module PROPERTIES
        PREFIX ""
        OUTPUT_NAME "lua_module"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/modules"
    )
endif()

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS httpd RUNTIME DESTINATION bin)
if(HAVE_LUA)
    install(TARGETS lua_module LIBRARY DESTINATION lib/httpd/modules)
endif()

# ── Summary ───────────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "  Features:")
message(STATUS "    HTTP/1.1  (RFC 9112)         : YES")
message(STATUS "    HTTP/2    (RFC 9113 + HPACK)  : YES")
message(STATUS "    HTTP/3    (RFC 9114)          : FRAMEWORK (needs QUIC transport)")
message(STATUS "    TLS 1.2/1.3 + ALPN (OpenSSL) : YES")
message(STATUS "    HTTP Cache (RFC 9111)         : YES")
message(STATUS "    Cookies   (RFC 6265)          : YES")
message(STATUS "    CGI/1.1   (fork-based)        : YES")
message(STATUS "    Lua 5.4   scripting           : ${HAVE_LUA}")
message(STATUS "    Module .so plugins            : YES  (C ABI, dlopen)")
message(STATUS "    Process model                 : pre-fork + epoll + thread-pool")
message(STATUS "")
