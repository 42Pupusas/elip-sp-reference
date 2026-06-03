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

Covered: the derivation core + known-answer test vectors (the values an independent
implementer must match), and address round-trip / network separation.

Out of scope, by design (not needed to back the Test Vectors section): building and
unblinding confidential transactions, the tweak-server scan loop, and Schnorr
key-path spending.

## Run

```sh
cargo test
```

## License

BSD-3-Clause.
