# elip-sp-reference

Minimal, standalone **reference implementation** for the *Silent Payments for the
Liquid Network* ELIP.

It re-derives the deterministic values pinned in the ELIP's **Test Vectors** section —
address encoding, input aggregation, the ECDH shared secret, the per-output spend key
`P_k`, the Liquid-specific blinding key `bk_k`, and the Taproot scriptPubKey — and
asserts they reproduce byte-for-byte (`cargo test`).

## Why this crate exists

This is the implementation the ELIP points at. It depends on
[`lwk_wollet`](https://crates.io/crates/lwk_wollet) (from crates.io) **only** for
cryptographic primitives: the secp256k1 context, key/scalar types, the tagged-hash
machinery, and Taproot script construction. Every Silent Payments rule is implemented
here directly from the ELIP. That makes it a self-contained check that the
construction is reproducible from public primitives, and keeps the spec's reference
small and legible.

## Scope

Covered:

- the derivation core + known-answer test vectors (the values an independent
  implementer must match), plus address round-trip / network separation; and
- the spec's novel claim — a confidential output blinded to the shared-secret key
  `BK_k` is unblinded non-interactively by the receiver with `bk_k` (the
  `ct_round_trip_unblind_with_bk` test).

Out of scope, by design — these are wallet integration, not spec verification, and are
left to the implementation: the tweak-server scan loop, signing, and
`Wollet`/`TxBuilder` wiring.

## Run

```sh
cargo test
```

## License

BSD-3-Clause.
