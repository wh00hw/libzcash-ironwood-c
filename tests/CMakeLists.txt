# Deterministic test variant of the library:
#   - TEST_DETERMINISTIC_NONCE: redpallas_sign uses fixed 0x42×32 random bytes
#     so signatures are reproducible against test_vectors.h.
#   - USE_PLATFORM_RNG=0 + ZORCHARD_INSECURE_LCG=1: the audit-C-2 hardening
#     makes the library refuse to compile against the LCG by default, but
#     unit tests are exactly the use case the LCG opt-in was designed for.
#     Tests get a deterministic random_buffer body without the integrator
#     having to provide a platform RNG stub.
#   - aes_ct.c (audit H-3): the constant-time AES, replacing the legacy
#     Brian-Gladman files that were removed from the build.
add_library(zcash-ironwood-c-deterministic STATIC
    ${CMAKE_SOURCE_DIR}/src/orchard.c
    ${CMAKE_SOURCE_DIR}/src/pallas.c
    ${CMAKE_SOURCE_DIR}/src/redpallas.c
    ${CMAKE_SOURCE_DIR}/src/secp256k1.c
    ${CMAKE_SOURCE_DIR}/src/bip32.c
    ${CMAKE_SOURCE_DIR}/src/bignum.c
    ${CMAKE_SOURCE_DIR}/src/blake2b.c
    ${CMAKE_SOURCE_DIR}/src/bip39.c
    ${CMAKE_SOURCE_DIR}/src/bip39_english.c
    ${CMAKE_SOURCE_DIR}/src/segwit_addr.c
    ${CMAKE_SOURCE_DIR}/src/memzero.c
    ${CMAKE_SOURCE_DIR}/src/hmac.c
    ${CMAKE_SOURCE_DIR}/src/pbkdf2.c
    ${CMAKE_SOURCE_DIR}/src/sha2.c
    ${CMAKE_SOURCE_DIR}/src/rand.c
    ${CMAKE_SOURCE_DIR}/src/hash_stubs.c
    ${CMAKE_SOURCE_DIR}/src/aes/aes_ct.c
    ${CMAKE_SOURCE_DIR}/src/aead.c
    ${CMAKE_SOURCE_DIR}/src/chacha20poly1305.c
    ${CMAKE_SOURCE_DIR}/src/wallet_lockout.c
    ${CMAKE_SOURCE_DIR}/src/hwp.c
    ${CMAKE_SOURCE_DIR}/src/zip244.c
    ${CMAKE_SOURCE_DIR}/src/orchard_signer.c
    ${CMAKE_SOURCE_DIR}/src/base58.c
    ${CMAKE_SOURCE_DIR}/src/hwp_dispatcher.c
)
target_include_directories(zcash-ironwood-c-deterministic
    PUBLIC ${CMAKE_SOURCE_DIR}/include
    PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/aes
)
target_compile_definitions(zcash-ironwood-c-deterministic PRIVATE
    TEST_DETERMINISTIC_NONCE
    USE_PLATFORM_RNG=0
    ZORCHARD_INSECURE_LCG=1
)
# Tests rely on assert() as the failure-detection mechanism; force it on
# regardless of the build type. Without this, Release builds (-DNDEBUG)
# silently turn every assert into a no-op and a broken invariant looks
# identical to a passing test (we hit this in the fee-gate review pass:
# tests "passed" only because asserts were compiled out).
target_compile_options(zcash-ironwood-c-deterministic PRIVATE -UNDEBUG)
target_compile_options(zcash-ironwood-c-deterministic PRIVATE -Wall -Wextra -Wno-unused-parameter)

# Asserts are the failure-detection mechanism of every test binary, not only
# of the library variant above: keep them live in every configuration
# (Release adds -DNDEBUG; this comes later on the command line and wins).
# Applies to all targets defined below in this directory.
add_compile_options(-UNDEBUG)

# All four tests link against the deterministic variant. Tests that don't
# touch crypto (test_hwp) get the same library; the redundancy is harmless
# and the single dependency keeps the build graph simple.
add_executable(test_hwp test_hwp.c)
target_link_libraries(test_hwp PRIVATE zcash-ironwood-c-deterministic)
add_test(NAME test_hwp COMMAND test_hwp)

add_executable(test_orchard test_orchard.c)
target_link_libraries(test_orchard PRIVATE zcash-ironwood-c-deterministic)
add_test(NAME test_orchard COMMAND test_orchard)

add_executable(test_signer test_signer.c)
target_link_libraries(test_signer PRIVATE zcash-ironwood-c-deterministic)
target_include_directories(test_signer PRIVATE ${CMAKE_SOURCE_DIR}/tests)
target_compile_options(test_signer PRIVATE -UNDEBUG)
add_test(NAME test_signer COMMAND test_signer)

add_executable(test_bip39 test_bip39.c)
target_link_libraries(test_bip39 PRIVATE zcash-ironwood-c-deterministic)
target_compile_options(test_bip39 PRIVATE -UNDEBUG)
add_test(NAME test_bip39 COMMAND test_bip39)

add_executable(test_vectors test_vectors.c)
target_link_libraries(test_vectors PRIVATE zcash-ironwood-c-deterministic)
add_test(NAME test_vectors COMMAND test_vectors)

add_executable(test_ironwood test_ironwood.c)
target_link_libraries(test_ironwood PRIVATE zcash-ironwood-c-deterministic)
target_compile_options(test_ironwood PRIVATE -UNDEBUG)
add_test(NAME test_ironwood COMMAND test_ironwood)

add_executable(test_h5 test_h5.c)
target_link_libraries(test_h5 PRIVATE zcash-ironwood-c-deterministic)
add_test(NAME test_h5 COMMAND test_h5)

add_executable(test_base58 test_base58.c)
target_link_libraries(test_base58 PRIVATE zcash-ironwood-c-deterministic)
add_test(NAME test_base58 COMMAND test_base58)

add_executable(test_hwp_dispatcher test_hwp_dispatcher.c)
target_link_libraries(test_hwp_dispatcher PRIVATE zcash-ironwood-c-deterministic)
target_include_directories(test_hwp_dispatcher PRIVATE ${CMAKE_SOURCE_DIR}/tests)
add_test(NAME test_hwp_dispatcher COMMAND test_hwp_dispatcher)

# Host micro-benchmark for the Pallas hot path (not a ctest; run manually:
#   ./tests/bench_pallas ../src/sinsemilla_s.bin).
add_executable(bench_pallas ${CMAKE_SOURCE_DIR}/tools/bench_pallas.c)
target_link_libraries(bench_pallas PRIVATE zcash-ironwood-c-deterministic)

add_executable(test_field test_field.c)
target_link_libraries(test_field PRIVATE zcash-ironwood-c-deterministic)
target_compile_options(test_field PRIVATE -UNDEBUG)
add_test(NAME test_field COMMAND test_field)

add_executable(test_curve test_curve.c)
target_link_libraries(test_curve PRIVATE zcash-ironwood-c-deterministic)
target_compile_options(test_curve PRIVATE -UNDEBUG)
add_test(NAME test_curve COMMAND test_curve)

# Known answers for the transparent key path (secp256k1 k*G, BIP-32, the
# Zcash BIP-44 key). Built twice: against the library as shipped (ECDSA
# signing compiled out), and from the sources with
# ZCASH_ENABLE_TRANSPARENT_SIGNING=1 so that the switched-off code keeps
# compiling and keeps giving the RFC 6979 answers.
add_executable(test_secp256k1 test_secp256k1.c)
target_link_libraries(test_secp256k1 PRIVATE zcash-ironwood-c-deterministic)
add_test(NAME test_secp256k1 COMMAND test_secp256k1)

add_executable(test_secp256k1_signing test_secp256k1.c
    ${CMAKE_SOURCE_DIR}/src/secp256k1.c
    ${CMAKE_SOURCE_DIR}/src/bip32.c
    ${CMAKE_SOURCE_DIR}/src/bignum.c
    ${CMAKE_SOURCE_DIR}/src/bip39.c
    ${CMAKE_SOURCE_DIR}/src/bip39_english.c
    ${CMAKE_SOURCE_DIR}/src/hmac.c
    ${CMAKE_SOURCE_DIR}/src/pbkdf2.c
    ${CMAKE_SOURCE_DIR}/src/sha2.c
    ${CMAKE_SOURCE_DIR}/src/memzero.c
    ${CMAKE_SOURCE_DIR}/src/rand.c
    ${CMAKE_SOURCE_DIR}/src/hash_stubs.c
)
target_include_directories(test_secp256k1_signing PRIVATE
    ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_secp256k1_signing PRIVATE
    ZCASH_ENABLE_TRANSPARENT_SIGNING=1 USE_PLATFORM_RNG=0 ZORCHARD_INSECURE_LCG=1)
add_test(NAME test_secp256k1_signing COMMAND test_secp256k1_signing)

# Secret residue in .data/.bss after a full wallet sequence (ELF/Linux;
# reports SKIP elsewhere).
add_executable(test_residue test_residue.c)
target_link_libraries(test_residue PRIVATE zcash-ironwood-c-deterministic)
target_include_directories(test_residue PRIVATE ${CMAKE_SOURCE_DIR}/src)
add_test(NAME test_residue COMMAND test_residue)

# On-device ownership classification, mandatory ciphertext verification and
# the consensus-branch allow-list, driven through the real signer state
# machine with real actions (tests/test_tx_fixture.h).
add_executable(test_ownership test_ownership.c)
target_link_libraries(test_ownership PRIVATE zcash-ironwood-c-deterministic)
target_include_directories(test_ownership PRIVATE ${CMAKE_SOURCE_DIR}/tests)
add_test(NAME test_ownership COMMAND test_ownership)

# The same library and tests with FlipZcash's RAM tuning (application.fam
# cdefines). The capacity macros shape struct layouts, so they must reach
# the library objects and the test alike. This is the configuration in
# which the memo pool is smaller than the action table, and where the
# firmware's sizeof budgets are asserted.
set(FLIPZ_TUNING_DEFS
    ORCHARD_SIGNER_MAX_ACTIONS=8
    ORCHARD_SIGNER_MAX_MEMOS=4
    HWP_MAX_PAYLOAD=1536
    PALLAS_FIXED_BASE_COMB=0
    PALLAS_POINT_MUL_WINDOW=2
    FLIPZ_TUNING
)
get_target_property(DETERMINISTIC_SOURCES zcash-ironwood-c-deterministic SOURCES)
add_library(zcash-ironwood-c-flipz STATIC ${DETERMINISTIC_SOURCES})
target_include_directories(zcash-ironwood-c-flipz
    PUBLIC ${CMAKE_SOURCE_DIR}/include
    PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/aes
)
target_compile_definitions(zcash-ironwood-c-flipz
    PRIVATE TEST_DETERMINISTIC_NONCE USE_PLATFORM_RNG=0 ZORCHARD_INSECURE_LCG=1
    PUBLIC ${FLIPZ_TUNING_DEFS}
)
target_compile_options(zcash-ironwood-c-flipz PRIVATE -UNDEBUG -Wall -Wextra -Wno-unused-parameter)

# The known-answer vectors and the signer/curve tests in the Flipper
# configuration too: no comb table, 2-bit window.
foreach(t test_vectors test_curve test_signer test_ironwood)
    add_executable(${t}_flipz ${t}.c)
    target_link_libraries(${t}_flipz PRIVATE zcash-ironwood-c-flipz)
    target_include_directories(${t}_flipz PRIVATE ${CMAKE_SOURCE_DIR}/tests ${CMAKE_SOURCE_DIR}/src)
    target_compile_options(${t}_flipz PRIVATE -UNDEBUG)
endforeach()
add_test(NAME test_vectors_flipz COMMAND test_vectors_flipz)
add_test(NAME test_curve_flipz COMMAND test_curve_flipz)
add_test(NAME test_signer_flipz COMMAND test_signer_flipz)
add_test(NAME test_ironwood_flipz COMMAND test_ironwood_flipz)

add_executable(test_ownership_flipz test_ownership.c)
target_link_libraries(test_ownership_flipz PRIVATE zcash-ironwood-c-flipz)
target_include_directories(test_ownership_flipz PRIVATE ${CMAKE_SOURCE_DIR}/tests)
add_test(NAME test_ownership_flipz COMMAND test_ownership_flipz)

add_executable(test_hwp_dispatcher_flipz test_hwp_dispatcher.c)
target_link_libraries(test_hwp_dispatcher_flipz PRIVATE zcash-ironwood-c-flipz)
target_include_directories(test_hwp_dispatcher_flipz PRIVATE ${CMAKE_SOURCE_DIR}/tests)
add_test(NAME test_hwp_dispatcher_flipz COMMAND test_hwp_dispatcher_flipz)
