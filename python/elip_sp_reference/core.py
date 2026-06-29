"""Silent Payments for the Liquid Network — Python reference implementation.

Written in the style of the canonical BIP-352 reference
(https://github.com/bitcoin/bips/blob/master/bip-0352/reference.py): the elliptic
curve algebra is done with the pure-Python ``secp256k1lab`` library, so the spec
math reads literally — ``B_spend + t_k * G``, ``input_hash * a * B_scan``, ``-k``.

INSECURE. ``secp256k1lab`` is for prototyping and test vectors only; it is slow
and not constant-time. Do not use in production.

Everything up to and including the output public key ``P_k`` is BIP-352. The two
Liquid-specific additions are:

* the per-output **blinding key** ``bk_k`` (tag ``LiquidSilentPayments/Blind``),
  which lets the sender blind a Confidential Transactions output so that only the
  receiver — who can recompute ``bk_k`` — can unblind it, and
* the Confidential Transactions plumbing (``build_confidential_sp_txout`` /
  ``unblind_output``), which is the one place that needs Liquid primitives and so
  uses ``wallycore`` rather than ``secp256k1lab``.
"""

from typing import Dict, List, Tuple

from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.util import tagged_hash

from . import bech32m


# ═══════════════════════════════════════════════════════════════════════════════
# Tagged-hash domains
# ═══════════════════════════════════════════════════════════════════════════════

TAG_INPUTS = "BIP0352/Inputs"
TAG_SHARED_SECRET = "BIP0352/SharedSecret"
# Disjoint from BIP0352/SharedSecret, so bk_k and t_k are independent even though
# both are derived from the same shared secret S.
TAG_BLIND = "LiquidSilentPayments/Blind"

# Address version 0 (Bech32 character `q`).
SP_ADDRESS_VERSION = 0


def ser_uint32(n: int) -> bytes:
    """Serialize a 32-bit counter, most-significant byte first."""
    return n.to_bytes(4, "big")


# ═══════════════════════════════════════════════════════════════════════════════
# Address encoding / decoding
# ═══════════════════════════════════════════════════════════════════════════════

# HRP per network. Distinct from Liquid's ex/lq (and testnet tex/tlq) prefixes.
_HRP = {"liquid": "lqsp", "liquid-testnet": "tlqsp", "liquid-regtest": "tlqsp"}


def hrp_for(network: str) -> str:
    return _HRP["liquid"] if network == "liquid" else _HRP["liquid-testnet"]


def encode_silent_payment_address(B_scan: GE, B_spend: GE, network: str = "liquid") -> str:
    """Bech32m(HRP, version || serP(B_scan) || serP(B_spend))."""
    data = bech32m.convertbits(
        B_scan.to_bytes_compressed() + B_spend.to_bytes_compressed(), 8, 5
    )
    return bech32m.bech32_encode(
        hrp_for(network), [SP_ADDRESS_VERSION] + data, bech32m.Encoding.BECH32M
    )


def decode_silent_payment_address(address: str, network: str = "liquid") -> Tuple[GE, GE]:
    """Inverse of encode_silent_payment_address. Raises on a bad HRP or version."""
    version, data = bech32m.decode(hrp_for(network), address)
    if data is None:
        raise ValueError("bad HRP or checksum")
    if version != SP_ADDRESS_VERSION:
        raise ValueError(f"unknown address version {version}")
    if len(data) != 66:
        raise ValueError(f"wrong payload length {len(data)}")
    B_scan = GE.from_bytes_compressed(bytes(data[:33]))
    B_spend = GE.from_bytes_compressed(bytes(data[33:]))
    return B_scan, B_spend


# ═══════════════════════════════════════════════════════════════════════════════
# Inputs — aggregation and input hash
# ═══════════════════════════════════════════════════════════════════════════════


def sum_input_privkeys(input_priv_keys: List[Tuple[Scalar, bool]]) -> Scalar:
    """Sum the eligible input private keys, applying BIP-352 even-Y normalization.

    Each entry is ``(private_key, is_taproot)``. A taproot (BIP-341) prevout
    commits only to the x-only key, so its implicit public key is even-Y: if
    ``a * G`` has odd Y, negate ``a`` first. Non-taproot keys are summed as-is.
    """
    negated = []
    for a, is_taproot in input_priv_keys:
        if is_taproot and not (a * G).has_even_y():
            a = -a
        negated.append(a)
    return Scalar.sum(*negated)


def get_input_hash(outpoints: List[bytes], A: GE) -> Scalar:
    """input_hash = tagged_hash("BIP0352/Inputs", lowest_outpoint || serP(A)).

    Each outpoint is the 36 bytes ``txid (32) || vout (4, little-endian)``.
    """
    lowest = sorted(outpoints)[0]
    h = tagged_hash(TAG_INPUTS, lowest + A.to_bytes_compressed())
    return Scalar.from_bytes_wrapping(h)


# ═══════════════════════════════════════════════════════════════════════════════
# Shared secret
# ═══════════════════════════════════════════════════════════════════════════════


def sender_shared_secret(input_hash: Scalar, a_sum: Scalar, B_scan: GE) -> GE:
    """Sender's ECDH shared secret S = input_hash * a * B_scan."""
    return input_hash * a_sum * B_scan


def receiver_shared_secret(input_hash: Scalar, b_scan: Scalar, A_sum: GE) -> GE:
    """Receiver's ECDH shared secret S = input_hash * b_scan * A_sum."""
    return input_hash * b_scan * A_sum


# ═══════════════════════════════════════════════════════════════════════════════
# Per-output derivation
# ═══════════════════════════════════════════════════════════════════════════════


def output_tweak(S: GE, k: int) -> Scalar:
    """t_k = tagged_hash("BIP0352/SharedSecret", serP(S) || ser32(k))."""
    return Scalar.from_bytes_wrapping(
        tagged_hash(TAG_SHARED_SECRET, S.to_bytes_compressed() + ser_uint32(k))
    )


def output_pubkey(B_spend: GE, S: GE, k: int) -> GE:
    """P_k = B_spend + t_k * G."""
    return B_spend + output_tweak(S, k) * G


def output_spend_privkey(b_spend: Scalar, S: GE, k: int) -> Scalar:
    """The spend private key for P_k: b_spend + t_k (mod n)."""
    return b_spend + output_tweak(S, k)


def blinding_privkey(S: GE, k: int) -> Scalar:
    """bk_k = tagged_hash("LiquidSilentPayments/Blind", serP(S) || ser32(k)).

    The Liquid-specific output blinding key. Both sender and receiver can derive
    it from S, so the receiver needs no out-of-band data to unblind the output.
    """
    return Scalar.from_bytes_wrapping(
        tagged_hash(TAG_BLIND, S.to_bytes_compressed() + ser_uint32(k))
    )


def script_pubkey(P_k: GE) -> bytes:
    """scriptPubKey = OP_1 <x-only(P_k)> (a P2TR output, no taptweak per BIP-352)."""
    return bytes([0x51, 0x20]) + P_k.to_bytes_xonly()


# ═══════════════════════════════════════════════════════════════════════════════
# Confidential Transactions blinding / unblinding (Liquid-specific)
# ═══════════════════════════════════════════════════════════════════════════════
#
# This is the only part that needs Liquid primitives, so it uses wallycore. The
# sender blinds the output to BK_k = bk_k * G; the CT nonce is an ECDH between an
# ephemeral key and BK_k. The receiver recomputes bk_k, derives the same nonce,
# and unblinds — recovering the plaintext asset and value with no extra messages.


def build_confidential_sp_txout(
    BK_k: GE,
    P_k: GE,
    asset_id: bytes,
    value: int,
    abf: bytes,
    vbf: bytes,
    ephemeral_sk: Scalar,
) -> Dict[str, bytes]:
    """Build a confidential output blinded to BK_k.

    ``asset_id`` is the 32-byte asset tag, ``value`` the amount in satoshi,
    ``abf``/``vbf`` the 32-byte asset/value blinding factors, ``ephemeral_sk`` the
    ephemeral scalar whose ECDH with BK_k forms the CT nonce. Returns the
    commitments, nonce pubkey, rangeproof and scriptPubKey.
    """
    import wallycore as wally

    script = script_pubkey(P_k)
    nonce_hash = wally.ecdh_nonce_hash(BK_k.to_bytes_compressed(), ephemeral_sk.to_bytes())
    nonce_pubkey = (ephemeral_sk * G).to_bytes_compressed()

    asset_generator = wally.asset_generator_from_bytes(asset_id, abf)
    value_commitment = wally.asset_value_commitment(value, vbf, asset_generator)
    rangeproof = wally.asset_rangeproof_with_nonce(
        value, nonce_hash, asset_id, abf, vbf,
        value_commitment, script, asset_generator,
        1, 0, 52,
    )
    return {
        "asset_generator": asset_generator,
        "value_commitment": value_commitment,
        "nonce_pubkey": nonce_pubkey,
        "rangeproof": rangeproof,
        "script_pubkey": script,
    }


def unblind_output(txout: Dict[str, bytes], bk_k: Scalar) -> Dict[str, object]:
    """Unblind a confidential output with bk_k, recovering (asset, value, abf, vbf).

    Raises if bk_k is wrong (the rangeproof will not validate against the nonce).
    """
    import wallycore as wally

    nonce_hash = wally.ecdh_nonce_hash(txout["nonce_pubkey"], bk_k.to_bytes())
    # The high-level wrapper allocates its own asset/abf/vbf buffers and returns
    # (value, asset, abf, vbf).
    value, asset, abf, vbf = wally.asset_unblind_with_nonce(
        nonce_hash,
        txout["rangeproof"],
        txout["value_commitment"],
        txout["script_pubkey"],
        txout["asset_generator"],
    )
    return {"asset": bytes(asset), "value": value, "abf": bytes(abf), "vbf": bytes(vbf)}
