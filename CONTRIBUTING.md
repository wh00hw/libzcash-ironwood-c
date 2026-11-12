# Contributing to libzcash-ironwood-c

This library signs Zcash transactions on devices that hold spending keys. A
change is judged first on whether it can be shown to be correct, and only then
on anything else. The conventions below follow the
[librustzcash style guides](https://github.com/zcash/librustzcash/blob/main/CONTRIBUTING.md#styleguides)
where they apply to C.

## Before you open a pull request

```bash
cmake -B build -DSTACK_ANALYSIS=ON && cmake --build build -j
(cd build && ctest --output-on-failure)   # every test binary must pass
./scripts/check_stack.sh build            # must print PASSED
```

A pull request that changes behaviour needs a test that fails without it.

## Rules that are not negotiable

- **Correctness is established against the reference implementation.** New or
  changed cryptographic behaviour comes with known-answer vectors generated
  from the Rust `orchard` / `librustzcash` crates by a generator under
  `tools/`, committed together with the generator so anyone can reproduce
  them. Hand-written expected values are not accepted.
- **Constant time.** No branch, table index or loop bound may depend on secret
  data (spending keys, viewing keys, nonces, note randomness). Masks go
  through `ct_mask_barrier`. `SECURITY.md` describes how this is checked
  (valgrind taint harness, GCC and clang, four optimisation levels); a change
  to a secret-dependent path must be re-checked the same way and the result
  stated in the pull request. A deliberately variable-time routine carries a
  `_vartime` suffix and a comment naming each call site and why its inputs
  are public.
- **No secret residue.** Static or long-lived buffers that hold secret-derived
  data are wiped before the function returns. `tests/test_residue.c` enforces
  this for static storage; extend it when you add state.
- **Stack budget.** 512 bytes per function, enforced by
  `scripts/check_stack.sh`. No recursion, no variable-length arrays, no heap.
- **No new dependencies.** The library builds with a C11 compiler and nothing
  else.
- **Wire protocol and public headers.** The HWP wire format is shared with the
  host SDK and every firmware. A change to it, or to an existing public
  function, needs an issue and agreement first.
- **Documentation tells the truth.** If a change alters what `README.md` or
  `SECURITY.md` claims, update them in the same pull request. State what was
  measured and on what; do not state device timings you did not measure.

## Commits and pull requests

- One logical change per commit. The subject line says what changed; the body
  says why, and how it was verified.
- Keep refactors separate from behaviour changes.
- Rebase on `main`; do not merge `main` into your branch.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability
reporting on this repository (Security tab, "Report a vulnerability").
