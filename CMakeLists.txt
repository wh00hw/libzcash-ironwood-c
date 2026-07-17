cmake_minimum_required(VERSION 3.16)
project(zcash-ironwood-c
    VERSION 0.1.0
    LANGUAGES C
    DESCRIPTION "Zcash Orchard address generation, signing, and HWP protocol in pure C"
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Use -O2 instead of CMake's default -O3 for Release builds.
# GCC ≥13 with -O3 applies aggressive loop unrolling in SHA-2 that
# inflates stack frames beyond the 512-byte embedded budget.
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

# --- Library sources ---

set(CRYPTO_SOURCES
    src/orchard.c
    src/pallas.c
    src/redpallas.c
    src/secp256k1.c
    src/bip32.c
    src/bignum.c
    src/blake2b.c
    src/bip39.c
    src/bip39_english.c
    src/segwit_addr.c
    src/memzero.c
    src/hmac.c
    src/pbkdf2.c
    src/sha2.c
    src/rand.c
    src/hash_stubs.c
    src/aes/aes_ct.c
    src/aead.c
    src/chacha20poly1305.c
    src/wallet_lockout.c
    # The Brian Gladman AES files (aescrypt.c, aeskey.c, aes_modes.c,
    # aestab.c) were removed from the build in the security-audit
    # follow-up: their T-table implementation leaks the round-key bytes
    # via cache-timing (audit H-3), and orchard.c now routes FF1 through
    # the constant-time aes_ct_* API. The source files are retained in
    # src/aes/ for reference until external integrators migrate, but
    # nothing in the library links against them.
)

set(PROTOCOL_SOURCES
    src/hwp.c
    src/zip244.c
    src/orchard_signer.c
    src/hwp_dispatcher.c
    src/base58.c
)

# --- Static library ---

add_library(zcash-ironwood-c STATIC
    ${CRYPTO_SOURCES}
    ${PROTOCOL_SOURCES}
)

target_include_directories(zcash-ironwood-c
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/aes
)

target_compile_options(zcash-ironwood-c PRIVATE
    -Wall -Wextra -Wno-unused-parameter
)


# --- Install ---

include(GNUInstallDirs)

install(TARGETS zcash-ironwood-c
    EXPORT zcash-ironwood-c-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/zcash-ironwood-c
)

install(EXPORT zcash-ironwood-c-targets
    FILE zcash-ironwood-c-config.cmake
    NAMESPACE zcash-ironwood-c::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zcash-ironwood-c
)

# --- Stack analysis (optional, GCC only) ---

option(STACK_ANALYSIS "Enable -fstack-usage for stack bound analysis" OFF)

if(STACK_ANALYSIS)
    target_compile_options(zcash-ironwood-c PRIVATE -fstack-usage)
endif()

# --- Tests (optional) ---

option(BUILD_TESTS "Build tests" ON)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
