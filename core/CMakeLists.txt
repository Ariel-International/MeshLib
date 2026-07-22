# MeshLib portable C core — L0–L3 (identity, framing/link, routing).
#
# SKELETON build: configures and builds as an empty static library on a plain
# desktop CMake setup. No real logic, no crypto backend, no JNI, no ESP-IDF
# toolchain wired up yet — those are flagged below and in README.md.
#
# The wire format this core must implement is specified in ../WIRE_FORMAT.md
# (repo root). See README.md for how the two relate.
#
#   Desktop build:
#     cmake -S . -B build
#     cmake --build build
#   Produces a static lib (libmeshcore.a / meshcore.lib) with stub symbols.

cmake_minimum_required(VERSION 3.16)

project(meshcore
    VERSION 0.0.1
    DESCRIPTION "MeshLib portable C core (L0-L3) — skeleton"
    LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# ESP-IDF note (NOT configured here — flag only).
#
# On ESP-IDF this directory would instead be registered as an IDF component:
# a component-level CMakeLists.txt calling idf_component_register(SRCS ...
# INCLUDE_DIRS include REQUIRES mbedtls), and the crypto backend would be
# mbedTLS (bundled with ESP-IDF) rather than the desktop OpenSSL choice. The
# block below detects that context so this same file can eventually serve both;
# today it only takes the standalone desktop path.
# ---------------------------------------------------------------------------
if(DEFINED ESP_PLATFORM)
    message(FATAL_ERROR
        "ESP-IDF build path is not implemented yet — see README.md 'Building'. "
        "This skeleton only configures a standalone desktop static library.")
endif()

set(MESHCORE_SOURCES
    src/mesh_common.c
    src/mesh_codec.c
    src/mesh_identity.c
    src/mesh_link.c
    src/mesh_router.c)

set(MESHCORE_HEADERS
    include/mesh_common.h
    include/mesh_codec.h
    include/mesh_identity.h
    include/mesh_link.h
    include/mesh_router.h)

add_library(meshcore STATIC ${MESHCORE_SOURCES})

target_include_directories(meshcore PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

# Warnings on: this is wire-format-critical code and should build clean.
if(MSVC)
    target_compile_options(meshcore PRIVATE /W4)
else()
    target_compile_options(meshcore PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Crypto backend: NOT linked yet. When mesh_identity.c gets real ECDSA, desktop
# will link OpenSSL here (find_package(OpenSSL); target_link_libraries(meshcore
# PRIVATE OpenSSL::Crypto)); ESP-IDF resolves mbedTLS via its component system
# instead. Left unlinked so the skeleton has zero external dependencies.

set_target_properties(meshcore PROPERTIES
    PUBLIC_HEADER "${MESHCORE_HEADERS}")

# Optional install rules — harmless when building in-tree.
include(GNUInstallDirs)
install(TARGETS meshcore
    ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/meshcore)

# ---------------------------------------------------------------------------
# Tests. Desktop-only; not built under ESP-IDF. Run with:
#     cmake --build build && ctest --test-dir build --output-on-failure
# ---------------------------------------------------------------------------
option(MESHCORE_BUILD_TESTS "Build the C core unit tests" ON)
if(MESHCORE_BUILD_TESTS)
    enable_testing()
    add_executable(test_codec tests/test_codec.c)
    target_link_libraries(test_codec PRIVATE meshcore)
    add_test(NAME codec COMMAND test_codec)
endif()
