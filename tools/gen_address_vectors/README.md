# gen_address_vectors

Regenerates `tests/test_address_vectors.h`, the default-address and
viewing-key known-answer vectors checked by `tests/test_vectors.c` (and used
as the wallet / foreign addresses of `tests/test_ownership.c` and
`tests/test_hwp_dispatcher.c`):

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

For on-device ownership classification the tool also emits, per vector:

- `nk`, `rivk` — the other two components of the full viewing key;
- `ivk_external`, `ivk_internal` — `FullViewingKey::to_ivk(scope)`;
- `rivk_internal` — `ToScalar(PRF^expand(rivk, [0x83] || ak || nk))`. The
  crate keeps it private, so it is recomputed here and checked through
  `Commit^ivk` (evaluated with the `sinsemilla` crate) against the crate's
  internal ivk; the same commitment with `rivk` must give the external ivk;
- `int_d` / `int_pk_d` — `address_at(0, Scope::Internal)`, the default change
  address;
- `ext_j`, `extj_d` / `extj_pk_d` — `address_at(ext_j, Scope::External)`, an
  own receiving address at a non-default diversifier index.
