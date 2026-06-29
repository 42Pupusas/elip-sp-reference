"""Silent Payments for the Liquid Network — Python reference implementation.

Written in the style of the canonical BIP-352 reference, using the pure-Python
``secp256k1lab`` for the curve algebra (so the spec math reads literally) and
``wallycore`` only for the Liquid-specific Confidential Transactions plumbing.

INSECURE — prototyping and test vectors only. See :mod:`elip_sp_reference.core`.
"""

from .core import (
    TAG_INPUTS,
    TAG_SHARED_SECRET,
    TAG_BLIND,
    SP_ADDRESS_VERSION,
    ser_uint32,
    hrp_for,
    encode_silent_payment_address,
    decode_silent_payment_address,
    sum_input_privkeys,
    get_input_hash,
    sender_shared_secret,
    receiver_shared_secret,
    output_tweak,
    output_pubkey,
    output_spend_privkey,
    blinding_privkey,
    script_pubkey,
    compute_tweak,
    shared_secret_from_tweak,
    build_confidential_sp_txout,
    unblind_output,
)

__all__ = [
    "TAG_INPUTS",
    "TAG_SHARED_SECRET",
    "TAG_BLIND",
    "SP_ADDRESS_VERSION",
    "ser_uint32",
    "hrp_for",
    "encode_silent_payment_address",
    "decode_silent_payment_address",
    "sum_input_privkeys",
    "get_input_hash",
    "sender_shared_secret",
    "receiver_shared_secret",
    "output_tweak",
    "output_pubkey",
    "output_spend_privkey",
    "blinding_privkey",
    "script_pubkey",
    "compute_tweak",
    "shared_secret_from_tweak",
    "build_confidential_sp_txout",
    "unblind_output",
]
