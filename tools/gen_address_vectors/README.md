# gen_address_vectors

Regenerates `tests/test_address_vectors.h`, the default-address known-answer
vectors checked by `tests/test_vectors.c`:

```
cargo run --release > ../../tests/test_address_vectors.h
```

Reference: `orchard` 0.16.0 (`SpendingKey::from_zip32_seed` →
`FullViewingKey` → `address_at(0, Scope::External)`), account 0, eight seeds
on mainnet (coin type 133) and testnet (coin type 1).

Per vector the tool also emits

- `ak_odd` — whether the un-normalised `[ask]·G` has an odd y (the case in
  which the spec negates `ask`);
- `legacy_d` / `legacy_pk_d` — the address libzcash-ironwood-c returned up to
  a55d168, which fed the un-normalised `ak` encoding into the diversifier-key
  PRF. It equals the default address when `ak_odd` is 0.

Both are computed outside the `orchard` crate (PRF^expand, FF1) and
cross-checked against it at run time: the replicated diversifier key must
reproduce the crate's default diversifier, and the legacy address must be an
external address of the same full viewing key. The run aborts otherwise, and
also if the set does not contain at least four vectors of each parity.
