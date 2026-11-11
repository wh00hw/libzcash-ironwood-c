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
