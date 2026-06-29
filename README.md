# elip-sp-reference

Reference implementation for the *Silent Payments for the Liquid Network* ELIP.

## Contents

There are two independent implementations that derive the same test vectors
byte-for-byte:

- `src/lib.rs` — Rust, built on `lwk_wollet`.
- `python/` — Python, in the canonical BIP-352 `reference.py` style, using the
  pure-Python `secp256k1lab` for the curve algebra and `wallycore` only for the
  Liquid Confidential Transactions plumbing. See [`python/README.md`](python/README.md).

Both cover:

- **Address encoding** — Bech32m, HRP `lqsp`/`tlqsp`, version `q`
- **Sender derivation** — input aggregation, ECDH shared secret, `P_k`, `BK_k`, `bk_k`
- **Tweak server** — `T = input_hash · A`, publish, and client-side `S = b_scan · T`
- **Receiver scanning** — recompute `P_k`, match against outputs, derive spend secret
- **Confidential output blinding and unblinding** — the ELIP's novel claim: `bk_k`
  derived from the shared secret unblinds the output non-interactively
- **Test vectors** — deterministic known-answer values matching the ELIP specification

## Run

```sh
# Rust — 5 tests: test_vectors, taproot_even_y_negation, tweak_server_agreement,
#                 ct_round_trip_unblind_with_bk, address_round_trip_and_network_separation
cargo test

# Python — same 5 tests
cd python && python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[test]' && pytest -v
```

## Taproot usage analysis

```sh
cargo run --bin analyze_taproot -- --blocks 500 --base-url https://liquid.network/liquid/api
```

Results are recorded in `TAPROOT_ANALYSIS.md`.

## Dependencies

The only external dependency is [`lwk_wollet`](https://crates.io/crates/lwk_wollet),
used for secp256k1 primitives, key and scalar types, tagged hashes, Taproot script
construction, and Confidential Transactions primitives. All Silent Payments logic
is implemented directly from the ELIP.

## License

BSD-3-Clause.
