# gen_ztot_vector

Generates `tests/test_ztot_vector.h`: a real v6 (NU7 branch) shielded → transparent
transaction built with `zcash_primitives` 0.31.0 / `pczt` 0.10.0 / `orchard` 0.16.0 —
one Ironwood spend, one transparent P2PKH output, Ironwood change, and the dummy
output the builder pads with — together with the shielded signature hash computed by
the `pczt` Signer role.

`tests/test_ironwood.c` (`test_ztot_crate_vector`) replays it through the device's
signer and requires the same sighash. It is the cross-check for

- the transparent leaf when the transaction has transparent outputs and no
  transparent inputs (the only transparent shape the device supports);
- the rule that every action comes with its memo: the builder's dummy output
  (value 0, random address, 512 zero bytes of memo, no OVK) passes the device's
  ciphertext recomputation.

```
cargo run --release > ../../tests/test_ztot_vector.h
```

The transaction uses OS randomness, so every run gives a different (equally valid)
vector.
