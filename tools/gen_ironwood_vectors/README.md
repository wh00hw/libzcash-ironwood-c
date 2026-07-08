# gen_ironwood_vectors

Regenerates the NU6.3 / Ironwood cross-validation vectors embedded in
`tests/test_ironwood.c` from the reference Rust implementation
(orchard 0.15.0-pre.2):

```
cargo run --release
```

Outputs (hex): V3 (ZIP-2005) note-commitment cmx, V3/V2 note-encryption
epk + ciphertext samples, and the v6 empty-bundle effects digests for the
Orchard and Ironwood pools. The V2 cmx sanity line must match the historical
`note_commit_expected_cmx` vector in `tests/test_vectors.h`.
