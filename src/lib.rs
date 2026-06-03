//! Reference implementation for **Silent Payments for the Liquid Network** (ELIP).
//!
//! This crate is intentionally minimal: it covers the *deterministic derivation*
//! the ELIP's "Test Vectors" section pins — address encoding, input aggregation,
//! the ECDH shared secret, the per-output spend key `P_k`, the Liquid-specific
//! blinding key `bk_k`, and the Taproot scriptPubKey — and proves they reproduce
//! byte-for-byte (see the `known_answer_vectors` test).
//!
//! It depends on [`lwk_wollet`] **only** for cryptographic primitives (the secp256k1
//! `EC` context and key/scalar types, the tagged-hash machinery, and Taproot script
//! construction). All Silent Payments logic is implemented here directly from the
//! ELIP.
//!
//! Out of scope, by design: building and unblinding confidential transactions, the
//! tweak-server scan loop, and Schnorr spending. This crate is about the deterministic
//! values an independent implementer must match.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Fe32, Hrp};

use lwk_wollet::elements::schnorr::TweakedPublicKey;
use lwk_wollet::elements::secp256k1_zkp::XOnlyPublicKey;
use lwk_wollet::elements::Script;
use lwk_wollet::hashes::{sha256t_hash_newtype, Hash, HashEngine};
use lwk_wollet::secp256k1::{PublicKey, Scalar, SecretKey};
use lwk_wollet::{ElementsNetwork, EC};

// --- Tagged hashes: BIP-352 domains + the Liquid blinding-key domain (ELIP §4.3) ---

sha256t_hash_newtype! {
    /// `BIP0352/Inputs` — `input_hash = H(outpoint_L || serP(A))`.
    struct InputsTag = hash_str("BIP0352/Inputs");
    #[hash_newtype(forward)]
    struct InputsHash(_);

    /// `BIP0352/SharedSecret` — `t_k = H(serP(S) || ser32(k))`.
    struct SharedSecretTag = hash_str("BIP0352/SharedSecret");
    #[hash_newtype(forward)]
    struct SharedSecretHash(_);

    /// `LiquidSilentPayments/Blind` — `bk_k = H(serP(S) || ser32(k))` (ELIP-specific).
    struct BlindTag = hash_str("LiquidSilentPayments/Blind");
    #[hash_newtype(forward)]
    struct BlindHash(_);
}

/// Silent payment address version 0, the Bech32 character `q`.
const SP_ADDRESS_VERSION: Fe32 = Fe32::Q;

/// The silent-payment address HRP per network.
///
/// Distinct from every existing Liquid address HRP — `ex`/`tex` (unconfidential)
/// and `lq`/`tlq` (confidential, blech32) — and from Bitcoin's `sp`/`tsp`, so an SP
/// address cannot be confused with a native Liquid address or a Bitcoin one.
fn hrp_for(network: ElementsNetwork) -> Hrp {
    match network {
        ElementsNetwork::Liquid => Hrp::parse_unchecked("lqsp"),
        _ => Hrp::parse_unchecked("tlqsp"),
    }
}

/// A Liquid silent-payment address: the receiver's scan and spend public keys.
///
/// Wire format (ELIP §4.1): Bech32m, network HRP, version symbol `q`, then the
/// 66-byte payload `serP(B_scan) || serP(B_spend)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    /// `B_scan`.
    pub scan: PublicKey,
    /// `B_spend`.
    pub spend: PublicKey,
}

impl SilentPaymentAddress {
    /// Encode as a Bech32m silent-payment address for `network`.
    pub fn encode(&self, network: ElementsNetwork) -> String {
        use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};

        let mut payload = Vec::with_capacity(66);
        payload.extend_from_slice(&self.scan.serialize());
        payload.extend_from_slice(&self.spend.serialize());

        std::iter::once(SP_ADDRESS_VERSION)
            .chain(payload.into_iter().bytes_to_fes())
            .with_checksum::<Bech32m>(&hrp_for(network))
            .chars()
            .collect()
    }

    /// Parse a Bech32m silent-payment address, validating the HRP against `network`.
    pub fn parse(s: &str, network: ElementsNetwork) -> Result<Self, AddressError> {
        use bech32::primitives::iter::Fe32IterExt;

        let checked =
            CheckedHrpstring::new::<Bech32m>(s).map_err(|_| AddressError::InvalidBech32m)?;
        if checked.hrp() != hrp_for(network) {
            return Err(AddressError::WrongNetwork);
        }

        let mut iter = checked.fe32_iter::<std::vec::IntoIter<u8>>();
        let version = iter.next().ok_or(AddressError::Truncated)?;
        if version != SP_ADDRESS_VERSION {
            return Err(AddressError::UnknownVersion);
        }

        let bytes: Vec<u8> = iter.fes_to_bytes().collect();
        if bytes.len() != 66 {
            return Err(AddressError::WrongPayloadLength(bytes.len()));
        }
        let scan =
            PublicKey::from_slice(&bytes[..33]).map_err(|_| AddressError::InvalidPublicKey)?;
        let spend =
            PublicKey::from_slice(&bytes[33..]).map_err(|_| AddressError::InvalidPublicKey)?;
        Ok(SilentPaymentAddress { scan, spend })
    }
}

/// Errors parsing a [`SilentPaymentAddress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    /// Not a valid Bech32m string.
    InvalidBech32m,
    /// HRP does not match the expected network.
    WrongNetwork,
    /// Payload ended before the version/keys could be read.
    Truncated,
    /// Unsupported address version.
    UnknownVersion,
    /// Payload was not the expected 66 bytes.
    WrongPayloadLength(usize),
    /// A public key in the payload is not a valid point.
    InvalidPublicKey,
}

/// The aggregated input data a sender derives (ELIP §4.4).
#[derive(Debug, Clone, Copy)]
pub struct AggregatedInputs {
    /// `a = Σ a_i`.
    pub a_sum: SecretKey,
    /// `A = a·G`.
    pub a_pubkey: PublicKey,
    /// `input_hash = H_BIP0352/Inputs(outpoint_L || serP(A))`.
    pub input_hash: Scalar,
}

/// One derived silent-payment output (ELIP §4.1–4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SilentPaymentOutput {
    /// `P_k = B_spend + t_k·G`.
    pub spend_pubkey: PublicKey,
    /// `BK_k = bk_k·G`.
    pub blinding_pubkey: PublicKey,
    /// `bk_k`, the blinding secret derived from the shared secret.
    pub blinding_seckey: SecretKey,
}

impl SilentPaymentOutput {
    /// The Taproot scriptPubKey `OP_1 <x_only(P_k)>` — `P_k` used directly, no
    /// taptweak, matching BIP-352 (ELIP §4.2).
    pub fn script_pubkey(&self) -> Script {
        let x_only: XOnlyPublicKey = self.spend_pubkey.x_only_public_key().0;
        Script::new_v1_p2tr_tweaked(TweakedPublicKey::new(x_only))
    }
}

/// `input_hash = H_BIP0352/Inputs(outpoint_L || serP(A))`.
fn input_hash(outpoint_l: &[u8], a_pubkey: &PublicKey) -> Scalar {
    let mut eng = InputsHash::engine();
    eng.input(outpoint_l);
    eng.input(&a_pubkey.serialize());
    let h = InputsHash::from_engine(eng);
    Scalar::from_be_bytes(h.to_byte_array()).expect("input hash within curve order")
}

/// Aggregate `(outpoint, private_key)` pairs for the sender's eligible inputs into
/// `a`, `A`, and `input_hash` (ELIP §4.4). `outpoint_l` is the serialized
/// lexicographically smallest outpoint (Elements consensus encoding).
pub fn aggregate_inputs(inputs: &[(Vec<u8>, SecretKey)], outpoint_l: &[u8]) -> AggregatedInputs {
    let (first, rest) = inputs.split_first().expect("at least one eligible input");
    let mut a_sum = first.1;
    for (_, sk) in rest {
        a_sum = a_sum
            .add_tweak(&Scalar::from_be_bytes(sk.secret_bytes()).expect("scalar"))
            .expect("non-zero aggregated key");
    }
    let a_pubkey = a_sum.public_key(&EC);
    let ih = input_hash(outpoint_l, &a_pubkey);
    AggregatedInputs {
        a_sum,
        a_pubkey,
        input_hash: ih,
    }
}

/// `t_k = H_BIP0352/SharedSecret(serP(S) || ser32(k))`.
fn shared_secret_tweak(s: &PublicKey, k: u32) -> Scalar {
    let mut eng = SharedSecretHash::engine();
    eng.input(&s.serialize());
    eng.input(&k.to_be_bytes());
    let h = SharedSecretHash::from_engine(eng);
    Scalar::from_be_bytes(h.to_byte_array()).expect("t_k within curve order")
}

/// `bk_k = H_LiquidSilentPayments/Blind(serP(S) || ser32(k))`.
fn blinding_key(s: &PublicKey, k: u32) -> SecretKey {
    let mut eng = BlindHash::engine();
    eng.input(&s.serialize());
    eng.input(&k.to_be_bytes());
    let h = BlindHash::from_engine(eng);
    SecretKey::from_slice(&h.to_byte_array()).expect("bk_k within curve order")
}

/// Sender's shared secret `S = input_hash · a · B_scan`.
fn sender_shared_secret(scan_pubkey: &PublicKey, agg: &AggregatedInputs) -> PublicKey {
    let a_ih = agg.a_sum.mul_tweak(&agg.input_hash).expect("scalar mul");
    scan_pubkey
        .mul_tweak(
            &EC,
            &Scalar::from_be_bytes(a_ih.secret_bytes()).expect("scalar"),
        )
        .expect("ecdh")
}

/// Receiver's shared secret `S = input_hash · b_scan · A`.
fn receiver_shared_secret(scan_seckey: &SecretKey, a_pubkey: &PublicKey, ih: &Scalar) -> PublicKey {
    let b_ih = scan_seckey.mul_tweak(ih).expect("scalar mul");
    a_pubkey
        .mul_tweak(
            &EC,
            &Scalar::from_be_bytes(b_ih.secret_bytes()).expect("scalar"),
        )
        .expect("ecdh")
}

/// Derive `P_k`/`BK_k`/`bk_k` from the spend base, the shared secret, and `k`.
fn derive_output(spend_base: &PublicKey, s: &PublicKey, k: u32) -> SilentPaymentOutput {
    let t_k = shared_secret_tweak(s, k);
    let spend_pubkey = spend_base.add_exp_tweak(&EC, &t_k).expect("P_k");
    let blinding_seckey = blinding_key(s, k);
    let blinding_pubkey = blinding_seckey.public_key(&EC);
    SilentPaymentOutput {
        spend_pubkey,
        blinding_pubkey,
        blinding_seckey,
    }
}

/// Sender side: derive the output at index `k` for `address` from aggregated inputs.
pub fn sender_derive_output(
    address: &SilentPaymentAddress,
    agg: &AggregatedInputs,
    k: u32,
) -> SilentPaymentOutput {
    let s = sender_shared_secret(&address.scan, agg);
    derive_output(&address.spend, &s, k)
}

/// Receiver side: recompute the output at index `k` plus the spend secret
/// `b_spend + t_k`, from `A`, `input_hash`, and the scan/spend secret keys.
pub fn receiver_derive_output(
    scan: &SecretKey,
    spend: &SecretKey,
    a_pubkey: &PublicKey,
    ih: &Scalar,
    k: u32,
) -> (SilentPaymentOutput, SecretKey) {
    let s = receiver_shared_secret(scan, a_pubkey, ih);
    let out = derive_output(&spend.public_key(&EC), &s, k);
    let t_k = shared_secret_tweak(&s, k);
    let spend_sk = spend.add_tweak(&t_k).expect("spend sk");
    (out, spend_sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lwk_wollet::elements::hashes::hex::DisplayHex;

    fn sk(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }

    /// Serialize an outpoint to BIP-352's 36-byte form: txid (32, internal) || vout (4, LE).
    fn outpoint_bytes(txid_byte: u8, vout: u32) -> Vec<u8> {
        let mut v = vec![txid_byte; 32];
        v.extend_from_slice(&vout.to_le_bytes());
        v
    }

    /// Known-answer test: reproduces the ELIP "Test Vectors" section exactly.
    ///
    /// Fixed inputs: receiver `b_scan = 0x11*32`, `b_spend = 0x22*32`; two eligible
    /// inputs `0x31*32 @ 0x10..:0` and `0x32*32 @ 0x20..:1`. The lexicographically
    /// smallest outpoint is input 0 (`0x10..`).
    #[test]
    fn known_answer_vectors() {
        let scan = sk(0x11);
        let spend = sk(0x22);
        let address = SilentPaymentAddress {
            scan: scan.public_key(&EC),
            spend: spend.public_key(&EC),
        };

        let inputs = [
            (outpoint_bytes(0x10, 0), sk(0x31)),
            (outpoint_bytes(0x20, 1), sk(0x32)),
        ];
        let outpoint_l = outpoint_bytes(0x10, 0); // smallest
        let agg = aggregate_inputs(&inputs, &outpoint_l);

        assert_eq!(
            agg.a_pubkey.serialize().to_lower_hex_string(),
            "031195a8046dcbb8e17034bca630065e7a0982e4e36f6f7e5a8d4554e4846fcd99",
            "A = a·G"
        );
        assert_eq!(
            agg.input_hash.to_be_bytes().to_lower_hex_string(),
            "d392922c00280a7e8d282182f5026f2fddbc74c1e1de18b4822128b2b77ec641",
            "input_hash"
        );

        // (k, P_k, BK_k, bk_k, spend_sk, scriptPubKey) — scriptPubKey = 5120 || x_only(P_k).
        let expected: [(u32, &str, &str, &str, &str, &str); 2] = [
            (
                0,
                "02a29d9716417c964ca9e477343e71ffe730a4991a3eaad668eabec84e9feb7931",
                "0344e1289497e6da66fde710d2f38de053fc07355e405524401d7d609df5a1a8cc",
                "70ab8897b64bd21b427339ff4d014b883191ef6425862246c53bfc27a59aa3f0",
                "f03c436d2cd67ae1fecf7d88a38aa3a03c0abea43feaf6da8eb71e2e3a866bda",
                "5120a29d9716417c964ca9e477343e71ffe730a4991a3eaad668eabec84e9feb7931",
            ),
            (
                1,
                "0229d77654023af267dbe9cb7ff1956f947c816f203494381308387168fb010c92",
                "03efdeda770ccdbe8bf466fba48bfd2b2c436ab0c04658fc6d6c277de5078129fa",
                "945ba73a9804f62089c7d2ffdc079031031f0aebab372cec17ef9c110ebceb10",
                "9eff3472230fc83ef5ea8f8c80401c4eecd595a048bd2482a107d3a49baa5a58",
                "512029d77654023af267dbe9cb7ff1956f947c816f203494381308387168fb010c92",
            ),
        ];

        for (k, p_k, bk_pub, bk_sec, spend_sk_hex, script_hex) in expected {
            let out = sender_derive_output(&address, &agg, k);
            let (recv, spend_sk) =
                receiver_derive_output(&scan, &spend, &agg.a_pubkey, &agg.input_hash, k);
            assert_eq!(out, recv, "sender/receiver agree at k={k}");

            assert_eq!(
                out.spend_pubkey.serialize().to_lower_hex_string(),
                p_k,
                "P_k k={k}"
            );
            assert_eq!(
                out.blinding_pubkey.serialize().to_lower_hex_string(),
                bk_pub,
                "BK k={k}"
            );
            assert_eq!(
                out.blinding_seckey.secret_bytes().to_lower_hex_string(),
                bk_sec,
                "bk k={k}"
            );
            assert_eq!(
                spend_sk.secret_bytes().to_lower_hex_string(),
                spend_sk_hex,
                "spend_sk k={k}"
            );
            assert_eq!(
                out.script_pubkey().as_bytes().to_lower_hex_string(),
                script_hex,
                "scriptPubKey k={k}"
            );
        }

        // The unlabeled mainnet (HRP `lqsp`) address for these keys.
        assert_eq!(
            address.encode(ElementsNetwork::Liquid),
            "lqsp1qqd8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc65qjxd4lu4etruh9sngx3su9mtqp5fqzxz7re59y5nnez9p03ht3lyudcfhfe",
        );
    }

    #[test]
    fn address_round_trip_and_network_separation() {
        let address = SilentPaymentAddress {
            scan: sk(0x11).public_key(&EC),
            spend: sk(0x22).public_key(&EC),
        };
        for network in [ElementsNetwork::Liquid, ElementsNetwork::LiquidTestnet] {
            let encoded = address.encode(network);
            assert_eq!(
                SilentPaymentAddress::parse(&encoded, network).unwrap(),
                address
            );
        }
        // A mainnet address must not parse as testnet.
        let mainnet = address.encode(ElementsNetwork::Liquid);
        assert_eq!(
            SilentPaymentAddress::parse(&mainnet, ElementsNetwork::LiquidTestnet),
            Err(AddressError::WrongNetwork),
        );
    }
}
