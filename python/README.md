# Silent Payments for the Liquid Network — Python reference

A reference implementation written in the style of the canonical
[BIP-352 reference](https://github.com/bitcoin/bips/blob/master/bip-0352/reference.py):
the elliptic-curve algebra is done with the pure-Python
[`secp256k1lab`](https://github.com/secp256k1lab/secp256k1lab), so the spec math
reads literally —

```python
P_k = B_spend + t_k * G                      # output public key
S   = input_hash * a * B_scan                # sender's shared secret
a   = -a   if is_taproot and odd_y else a    # BIP-341 even-Y normalization
```

It re-derives the ELIP's test vectors byte-for-byte (the same constants as the
sibling Rust [`elip-sp-reference`](../elip-sp-reference) crate).

> **INSECURE.** `secp256k1lab` is slow and not constant-time, intended for
> prototyping, test vectors, and education only. Do not use in production.

## What's BIP-352 and what's new

Everything up to the output public key `P_k` is plain BIP-352. The two
Liquid-specific additions are:

1. **The output blinding key** `bk_k = tagged_hash("LiquidSilentPayments/Blind",
   serP(S) || ser32(k))`. Both parties derive it from the shared secret `S`, so
   the receiver can unblind the Confidential Transactions output with no
   out-of-band data.
2. **The CT plumbing** (`build_confidential_sp_txout` / `unblind_output`) — the
   one place needing Liquid primitives, so it (and only it) uses `wallycore`.
   Everything else is pure `secp256k1lab`.

## Layout

```
elip_sp_reference/
  __init__.py     public API re-exports
  core.py         the protocol — addresses, inputs, shared secret, derivation, CT
  bech32m.py      Bech32m, verbatim from BIP-350 / the BIP-352 reference
tests/
  test_vectors.py byte-pinned vectors + taproot/tweak-server/address/CT round-trips
```

## Running

```sh
python3 -m venv .venv
source .venv/bin/activate          # fish: source .venv/bin/activate.fish
pip install -e '.[test]'
pytest -v
```

`secp256k1lab` is fetched from git (it is not published on PyPI). `wallycore`'s
PyPI wheels are built with Elements support, which the CT test needs; if it is
not installed, that one test is skipped automatically.
