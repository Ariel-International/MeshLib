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

# ---------------------------------------------------------------------------
# Crypto backend (desktop): OpenSSL. mesh_identity.c uses the EVP API for the
# P-256 keypair, X.509 PeerId, and SHA256withECDSA sign/verify.
#
# ESP-IDF resolves mbedTLS via its component system instead (idf_component_
# register(... REQUIRES mbedtls)); that path is not wired here — see the
# ESP-IDF note above.
#
# On this machine the only MSVC-compatible OpenSSL dev install is the one
# bundled with PostgreSQL 18. If find_package can't locate OpenSSL on its own,
# pass -DOPENSSL_ROOT_DIR=... (or set it in the environment). We seed a default
# hint here so a plain `cmake -S . -B build` configures out of the box, without
# hard-failing on machines where OpenSSL lives elsewhere.
if(NOT DEFINED OPENSSL_ROOT_DIR AND EXISTS "C:/Program Files/PostgreSQL/18/include/openssl/evp.h")
    set(OPENSSL_ROOT_DIR "C:/Program Files/PostgreSQL/18")
endif()
find_package(OpenSSL REQUIRED)
target_link_libraries(meshcore PRIVATE OpenSSL::Crypto)
# ---------------------------------------------------------------------------

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

    # Identity tests link OpenSSL transitively through meshcore (PRIVATE), but
    # the test source itself only calls the mesh_identity public API.
    add_executable(test_identity tests/test_identity.c)
    target_link_libraries(test_identity PRIVATE meshcore)
    add_test(NAME identity COMMAND test_identity)

    # L2 framing + handshake. Also pulls OpenSSL in transitively via meshcore.
    add_executable(test_link tests/test_link.c)
    target_link_libraries(test_link PRIVATE meshcore)
    add_test(NAME link COMMAND test_link)

    # L3 topology + routing. Pure graph/JSON logic — no crypto of its own, but
    # it still links meshcore, which pulls OpenSSL in transitively.
    add_executable(test_router tests/test_router.c)
    target_link_libraries(test_router PRIVATE meshcore)
    add_test(NAME router COMMAND test_router)

    # Deterministic random-input hardening for the wire-facing entry points
    # (L2 frame decode + handshake JSON, L3 topology/route JSON). Not
    # coverage-guided fuzzing — no clang/libFuzzer/AFL toolchain is available
    # on this machine — see the file header comment for what it does check.
    add_executable(test_fuzz tests/test_fuzz.c)
    target_link_libraries(test_fuzz PRIVATE meshcore)
    add_test(NAME fuzz COMMAND test_fuzz)

    # Cross-implementation proof against the REAL Java com.mesh code: does a
    # frame/signature/JSON field Java actually produced decode/verify
    # correctly in the C core, and vice versa? See tests/test_interop.c's
    # header for the full rationale and tests/interop/FixtureGen.java for how
    # the fixture is regenerated (javac+java against the real Java sources;
    # not part of this CMake build — Java stays out of the C build graph).
    # Skips (does not fail) if the fixture file has not been generated on this
    # machine, e.g. no JVM/Gradle cache — this is opt-in extra assurance, not
    # a hard requirement for `ctest` to pass on every desktop.
    add_executable(test_interop tests/test_interop.c)
    target_link_libraries(test_interop PRIVATE meshcore)
    # Bake the fixture's absolute path in at configure time so the test finds
    # it regardless of the working directory it's run from (CWD-relative
    # guesses alone meant it silently skipped -- reporting success while not
    # running -- when launched from build/, which is where the built exe
    # actually lives and where anyone would naturally run it from).
    target_compile_definitions(test_interop PRIVATE
        MESHCORE_FIXTURE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/tests/interop/fixture_java.json")
    add_test(NAME interop COMMAND test_interop)
    set_tests_properties(interop PROPERTIES SKIP_RETURN_CODE 77)

    # On Windows the OpenSSL crypto DLL must sit next to any exe that pulls it in
    # (or be on PATH) at run time. When we know the OpenSSL root, copy it into
    # each test's output dir after build so `ctest` runs without PATH setup.
    # No-op on platforms/configs where the DLL isn't found.
    if(WIN32 AND OPENSSL_ROOT_DIR)
        foreach(_dll "libcrypto-3-x64.dll" "libcrypto-1_1-x64.dll")
            if(EXISTS "${OPENSSL_ROOT_DIR}/bin/${_dll}")
                foreach(_tgt test_identity test_link test_router test_fuzz test_interop)
                    add_custom_command(TARGET ${_tgt} POST_BUILD
                        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                            "${OPENSSL_ROOT_DIR}/bin/${_dll}"
                            "$<TARGET_FILE_DIR:${_tgt}>")
                endforeach()
            endif()
        endforeach()
    endif()
endif()
