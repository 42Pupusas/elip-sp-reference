//! # Silent Payments for the Liquid Network — Reference Implementation
//!
//! Reference implementation for the Liquid Silent Payments ELIP. Each function
//! maps to a single derivation step from the specification. The only external
//! dependency is [`lwk_wollet`], used for secp256k1 primitives, tagged hashes,
//! Taproot script construction, and Confidential Transactions — all Silent
//! Payments logic is implemented here directly.
//!
//! ## Protocol overview
//!
//! ### 1. Address encoding
//!
//! The receiver picks two random private keys `b_scan` and `b_spend`. Their
//! public keys `B_scan = b_scan·G` and `B_spend = b_spend·G` are Bech32m-encoded
//! with HRP `lqsp` (mainnet) or `tlqsp` (testnet), version `q`.
//!
//! ### 2. Sender derivation
//!
//! Given the receiver's address `(B_scan, B_spend)` and eligible inputs:
//!
//!   a. `a = Σ a_i`,  `A = a·G`
//!   b. Pick the lexicographically smallest outpoint `outpoint_L`
//!   c. `input_hash = SHA256("BIP0352/Inputs"||"BIP0352/Inputs" || outpoint_L || serP(A))` mod n
//!   d. `S = input_hash · a · B_scan`
//!   e. For each output index `k`:
//!      - `t_k = SHA256("BIP0352/SharedSecret"||… || serP(S) || ser32(k))` mod n
//!      - `P_k = B_spend + t_k·G`
//!      - `bk_k = SHA256("LiquidSilentPayments/Blind"||… || serP(S) || ser32(k))` mod n
//!      - `BK_k = bk_k·G`
//!
//! The output is a confidential Taproot output: `OP_1 <x_only(P_k)>`, blinded to `BK_k`.
//!
//! ### 3. Tweak server
//!
//! The server publishes `T = input_hash · A` per transaction. The client computes
//! `S = b_scan · T`, recovering the sender's shared secret without private keys.
//!
//! ### 4. Receiver
//!
//! `S = b_scan · (input_hash · A)`, then for each `k` recompute `P_k`, match
//! against outputs, derive `bk_k` and `b_spend + t_k`.
//!
//! ### 5. Spending
//!
//! BIP-340 Schnorr with key `d = b_spend + t_k` (even-Y normalized). Standard
//! key-path Taproot.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Fe32, Hrp};

use lwk_wollet::elements::schnorr::TweakedPublicKey;
use lwk_wollet::elements::secp256k1_zkp::XOnlyPublicKey;
use lwk_wollet::elements::Script;
use lwk_wollet::hashes::{sha256t_hash_newtype, Hash, HashEngine};
use lwk_wollet::secp256k1::{Parity, PublicKey, Scalar, SecretKey};
use lwk_wollet::{ElementsNetwork, EC};

// ═══════════════════════════════════════════════════════════════════════════════
// Section 1 — Tagged hash domains
// ═══════════════════════════════════════════════════════════════════════════════

sha256t_hash_newtype! {
    /// `input_hash = SHA256("BIP0352/Inputs"||"BIP0352/Inputs" || outpoint_L || serP(A))` mod n.
    struct InputsTag = hash_str("BIP0352/Inputs");
    #[hash_newtype(forward)]
    struct InputsHash(_);

    /// `t_k = SHA256("BIP0352/SharedSecret"||"BIP0352/SharedSecret" || serP(S) || ser32(k))` mod n.
    struct SharedSecretTag = hash_str("BIP0352/SharedSecret");
    #[hash_newtype(forward)]
    struct SharedSecretHash(_);

    /// `bk_k = SHA256("LiquidSilentPayments/Blind"||"LiquidSilentPayments/Blind" || serP(S) || ser32(k))` mod n.
    ///
    /// The domain `LiquidSilentPayments/Blind` is disjoint from
    /// `BIP0352/SharedSecret`, so `bk_k` and `t_k` are independent.
    struct BlindTag = hash_str("LiquidSilentPayments/Blind");
    #[hash_newtype(forward)]
    struct BlindHash(_);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 2 — Address encoding / decoding
// ═══════════════════════════════════════════════════════════════════════════════

/// Address version 0 → Bech32 character `q`.
const SP_ADDRESS_VERSION: Fe32 = Fe32::Q;

/// HRP per network. Distinct from `ex`/`tex`, `lq`/`tlq`, and `sp`/`tsp`.
fn hrp_for(network: ElementsNetwork) -> Hrp {
    match network {
        ElementsNetwork::Liquid => Hrp::parse_unchecked("lqsp"),
        _ => Hrp::parse_unchecked("tlqsp"),
    }
}

/// A silent-payment address: `B_scan` and `B_spend`.
///
/// Wire format: Bech32m(HRP, version=`q`, `serP(B_scan) || serP(B_spend)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    pub scan: PublicKey,
    pub spend: PublicKey,
}

impl SilentPaymentAddress {
    /// Encode: HRP + `q` + 66 bytes of key data, 5-bit groups, Bech32m checksum.
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

    /// Parse, validating the HRP and version byte.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    InvalidBech32m,
    WrongNetwork,
    Truncated,
    UnknownVersion,
    WrongPayloadLength(usize),
    InvalidPublicKey,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 3 — Derivation core
// ═══════════════════════════════════════════════════════════════════════════════

/// The aggregated input state computed once per transaction by the sender.
#[derive(Debug, Clone, Copy)]
pub struct AggregatedInputs {
    pub a_sum: SecretKey,
    pub a_pubkey: PublicKey,
    pub input_hash: Scalar,
}

/// One derived output: spend key, blinding key, blinding secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SilentPaymentOutput {
    pub spend_pubkey: PublicKey,
    pub blinding_pubkey: PublicKey,
    pub blinding_seckey: SecretKey,
}

impl SilentPaymentOutput {
    /// `scriptPubKey = OP_1 <x_only(P_k)>` (no taptweak, per BIP-352).
    pub fn script_pubkey(&self) -> Script {
        let x_only: XOnlyPublicKey = self.spend_pubkey.x_only_public_key().0;
        Script::new_v1_p2tr_tweaked(TweakedPublicKey::new(x_only))
    }
}

// ── Helpers ──

/// Convert a [`SecretKey`] to a [`Scalar`] for curve arithmetic.
fn secret_key_to_scalar(sk: &SecretKey) -> Scalar {
    Scalar::from_be_bytes(sk.secret_bytes()).expect("secret key is a valid scalar")
}

/// BIP-352 even-Y normalization for a Taproot (BIP-341) input key.
///
/// A taproot prevout commits only to the x-only key, i.e. the implicit public
/// key has an even Y. The signing key for the silent-payment computation must
/// therefore be the one whose public key is even-Y: if `sk·G` has odd Y, negate
/// `sk` (which flips the parity) before aggregating. For non-taproot inputs the
/// full public key is recoverable from the witness/scriptSig and no negation is
/// applied.
fn normalize_taproot_input_key(sk: SecretKey) -> SecretKey {
    match sk.x_only_public_key(&EC).1 {
        Parity::Even => sk,
        Parity::Odd => sk.negate(),
    }
}

/// `input_hash = SHA256("BIP0352/Inputs"||"BIP0352/Inputs" || outpoint_L || serP(A))` mod n.
fn input_hash(outpoint_l: &[u8], a_pubkey: &PublicKey) -> Scalar {
    let mut eng = InputsHash::engine();
    eng.input(outpoint_l);
    eng.input(&a_pubkey.serialize());
    Scalar::from_be_bytes(InputsHash::from_engine(eng).to_byte_array())
        .expect("input_hash < curve order")
}

/// `t_k = SHA256("BIP0352/SharedSecret"||"BIP0352/SharedSecret" || serP(S) || ser32(k))` mod n.
fn shared_secret_tweak(s: &PublicKey, k: u32) -> Scalar {
    let mut eng = SharedSecretHash::engine();
    eng.input(&s.serialize());
    eng.input(&k.to_be_bytes());
    Scalar::from_be_bytes(SharedSecretHash::from_engine(eng).to_byte_array())
        .expect("t_k < curve order")
}

/// `bk_k = SHA256("LiquidSilentPayments/Blind"||"LiquidSilentPayments/Blind" || serP(S) || ser32(k))` mod n.
fn blinding_secret(s: &PublicKey, k: u32) -> SecretKey {
    let mut eng = BlindHash::engine();
    eng.input(&s.serialize());
    eng.input(&k.to_be_bytes());
    SecretKey::from_slice(&BlindHash::from_engine(eng).to_byte_array())
        .expect("bk_k < curve order")
}

/// Sender's ECDH shared secret: `S = input_hash · a · B_scan`.
fn sender_shared_secret(scan: &PublicKey, agg: &AggregatedInputs) -> PublicKey {
    let a_ih = agg.a_sum.mul_tweak(&agg.input_hash).expect("scalar mul");
    scan.mul_tweak(&EC, &secret_key_to_scalar(&a_ih)).expect("ecdh")
}

/// Receiver's ECDH shared secret: `S = b_scan · (input_hash · A)`.
fn receiver_shared_secret(
    b_scan: &SecretKey,
    a_pubkey: &PublicKey,
    input_hash: &Scalar,
) -> PublicKey {
    let b_ih = b_scan.mul_tweak(input_hash).expect("scalar mul");
    a_pubkey.mul_tweak(&EC, &secret_key_to_scalar(&b_ih)).expect("ecdh")
}

/// Derive `P_k`, `bk_k`, `BK_k` for output `k` from a shared secret and spend base.
fn derive_output(spend_base: &PublicKey, s: &PublicKey, k: u32) -> SilentPaymentOutput {
    let t_k = shared_secret_tweak(s, k);
    let spend_pubkey = spend_base.add_exp_tweak(&EC, &t_k).expect("P_k");
    let sk = blinding_secret(s, k);
    SilentPaymentOutput { spend_pubkey, blinding_pubkey: sk.public_key(&EC), blinding_seckey: sk }
}

// ── Public API ──

/// Aggregate the sender's eligible inputs.
///
/// Keys are used as-is; this models a set of non-taproot inputs whose full public
/// key is recoverable from the witness/scriptSig. For taproot (BIP-341) inputs,
/// use [`aggregate_inputs_with_parity`] so the even-Y normalization is applied.
pub fn aggregate_inputs(
    inputs: &[(Vec<u8>, SecretKey)],
    outpoint_l: &[u8],
) -> AggregatedInputs {
    let keys: Vec<(Vec<u8>, SecretKey, bool)> =
        inputs.iter().map(|(o, sk)| (o.clone(), *sk, false)).collect();
    aggregate_inputs_with_parity(&keys, outpoint_l)
}

/// Aggregate eligible inputs, applying BIP-352 even-Y normalization per input.
///
/// Each entry is `(outpoint, private_key, is_taproot)`. For taproot inputs the
/// key is replaced by [`normalize_taproot_input_key`] before summation, exactly
/// as BIP-352 requires ("for each private key `a_i` corresponding to a BIP341
/// taproot output, check that the private key produces a point with an even Y
/// coordinate and negate the private key if not"). The aggregate `a` and
/// `A = a·G` — and therefore every derived output — differ from the un-normalized
/// aggregate whenever any taproot input key had odd Y.
pub fn aggregate_inputs_with_parity(
    inputs: &[(Vec<u8>, SecretKey, bool)],
    outpoint_l: &[u8],
) -> AggregatedInputs {
    let norm = |sk: SecretKey, is_taproot: bool| {
        if is_taproot {
            normalize_taproot_input_key(sk)
        } else {
            sk
        }
    };
    let (first, rest) = inputs.split_first().expect("at least one eligible input");
    let mut a_sum = norm(first.1, first.2);
    for (_, sk, is_taproot) in rest {
        a_sum = a_sum
            .add_tweak(&secret_key_to_scalar(&norm(*sk, *is_taproot)))
            .expect("non-zero aggregated key");
    }
    let a_pubkey = a_sum.public_key(&EC);
    let input_hash = input_hash(outpoint_l, &a_pubkey);
    AggregatedInputs { a_sum, a_pubkey, input_hash }
}

/// Sender: derive output `k` for a given address.
pub fn sender_derive_output(
    address: &SilentPaymentAddress,
    agg: &AggregatedInputs,
    k: u32,
) -> SilentPaymentOutput {
    let s = sender_shared_secret(&address.scan, agg);
    derive_output(&address.spend, &s, k)
}

/// Receiver: recompute output `k` and the spend private key `b_spend + t_k`.
pub fn receiver_derive_output(
    b_scan: &SecretKey,
    b_spend: &SecretKey,
    a_pubkey: &PublicKey,
    input_hash: &Scalar,
    k: u32,
) -> (SilentPaymentOutput, SecretKey) {
    let s = receiver_shared_secret(b_scan, a_pubkey, input_hash);
    let out = derive_output(&b_spend.public_key(&EC), &s, k);
    let t_k = shared_secret_tweak(&s, k);
    let spend_sk = b_spend.add_tweak(&t_k).expect("spend sk");
    (out, spend_sk)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 4 — Tweak server
// ═══════════════════════════════════════════════════════════════════════════════
//
// The server publishes `T = input_hash · A`. The client computes `S = b_scan · T`.
// On Liquid, BIP-158 compact filters are unnecessary: the scriptPubKey is public.

/// Compute `(T = input_hash · A, input_hash, A)` from the eligible input public keys.
pub fn compute_tweak(
    input_pubkeys: &[PublicKey],
    outpoint_l: &[u8],
) -> (PublicKey, Scalar, PublicKey) {
    let a = PublicKey::combine_keys(&input_pubkeys.iter().collect::<Vec<_>>())
        .expect("at least one input pubkey");
    let ih = input_hash(outpoint_l, &a);
    let t = a.mul_tweak(&EC, &ih).expect("tweak point");
    (t, ih, a)
}

/// A published tweak for one transaction.
#[derive(Debug, Clone)]
pub struct TweakEntry {
    pub txid: [u8; 32],
    pub tweak: PublicKey,     // T = input_hash · A
    pub a_pubkey: PublicKey,  // A
    pub input_hash: Scalar,   // input_hash
}

/// Minimal tweak server.
#[derive(Debug, Default)]
pub struct TweakServer {
    entries: Vec<TweakEntry>,
}

impl TweakServer {
    pub fn publish(
        &mut self,
        txid: [u8; 32],
        input_pubkeys: &[PublicKey],
        outpoint_l: &[u8],
    ) {
        let (tweak, input_hash, a_pubkey) = compute_tweak(input_pubkeys, outpoint_l);
        self.entries.push(TweakEntry { txid, tweak, a_pubkey, input_hash });
    }

    pub fn get_by_txid(&self, txid: &[u8; 32]) -> Option<&TweakEntry> {
        self.entries.iter().find(|e| &e.txid == txid)
    }
}

/// `S = b_scan · T` (from a tweak server entry).
pub fn shared_secret_from_tweak(b_scan: &SecretKey, entry: &TweakEntry) -> PublicKey {
    let b = secret_key_to_scalar(b_scan);
    entry.tweak.mul_tweak(&EC, &b).expect("ecdh")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 5 — Confidential output blinding / unblinding
// ═══════════════════════════════════════════════════════════════════════════════
//
// The sender blinds to `BK_k = bk_k·G`. The receiver recomputes `bk_k` and
// unblinds, recovering plaintext asset + value with no out-of-band exchange.

/// Build a confidential `TxOut` blinded to `BK_k`.
pub fn build_confidential_sp_txout(
    out: &SilentPaymentOutput,
    asset: lwk_wollet::elements::AssetId,
    value: u64,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<
    (lwk_wollet::elements::TxOut, lwk_wollet::elements::TxOutSecrets),
    lwk_wollet::elements::secp256k1_zkp::Error,
> {
    use lwk_wollet::elements::confidential::{
        Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor,
    };
    use lwk_wollet::elements::secp256k1_zkp::{Generator, PedersenCommitment, RangeProof, Tag};
    use lwk_wollet::elements::{TxOut, TxOutSecrets, TxOutWitness};

    let script_pubkey = out.script_pubkey();

    let abf = AssetBlindingFactor::new(&mut *rng);
    let vbf = ValueBlindingFactor::new(&mut *rng);

    // CT nonce derived from BK_k — this is what lets the receiver unblind.
    let (nonce, ct_shared_secret) =
        Nonce::new_confidential(&mut *rng, &EC, &out.blinding_pubkey);

    let asset_tag = Tag::from(asset.into_inner().to_byte_array());
    let asset_gen = Generator::new_blinded(&EC, asset_tag, abf.into_inner());
    let value_commitment =
        PedersenCommitment::new(&EC, value, vbf.into_inner(), asset_gen);

    let mut message = [0u8; 64];
    message[..32].copy_from_slice(&asset.into_inner().to_byte_array());
    message[32..].copy_from_slice(abf.into_inner().as_ref());

    let rangeproof = RangeProof::new(
        &EC, 1, value_commitment, value, vbf.into_inner(),
        &message, script_pubkey.as_bytes(), ct_shared_secret, 0, 52, asset_gen,
    )?;

    let txout = TxOut {
        asset: Asset::Confidential(asset_gen),
        value: Value::Confidential(value_commitment),
        nonce,
        script_pubkey,
        witness: TxOutWitness { surjection_proof: None, rangeproof: Some(Box::new(rangeproof)) },
    };
    let secrets = TxOutSecrets { asset, asset_bf: abf, value, value_bf: vbf };

    Ok((txout, secrets))
}

/// Unblind a confidential output with `bk_k`, recovering asset + value.
pub fn unblind_output(
    txout: &lwk_wollet::elements::TxOut,
    bk_k: SecretKey,
) -> Result<lwk_wollet::elements::TxOutSecrets, lwk_wollet::elements::UnblindError> {
    txout.unblind(&EC, bk_k)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 6 — Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use lwk_wollet::elements::hashes::hex::DisplayHex;

    fn sk_byte(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }

    fn outpoint(txid_byte: u8, vout: u32) -> Vec<u8> {
        let mut v = vec![txid_byte; 32];
        v.extend_from_slice(&vout.to_le_bytes());
        v
    }

    /// Test vectors from the ELIP.
    ///
    /// b_scan = 0x11×32, b_spend = 0x22×32.
    /// Two inputs: 0x31×32 @ 0x10…:0, 0x32×32 @ 0x20…:1.
    #[test]
    fn test_vectors() {
        let b_scan = sk_byte(0x11);
        let b_spend = sk_byte(0x22);
        let address = SilentPaymentAddress {
            scan: b_scan.public_key(&EC),
            spend: b_spend.public_key(&EC),
        };

        let agg = aggregate_inputs(
            &[(outpoint(0x10, 0), sk_byte(0x31)), (outpoint(0x20, 1), sk_byte(0x32))],
            &outpoint(0x10, 0),
        );

        assert_eq!(
            agg.a_pubkey.serialize().to_lower_hex_string(),
            "031195a8046dcbb8e17034bca630065e7a0982e4e36f6f7e5a8d4554e4846fcd99",
            "A"
        );
        assert_eq!(
            agg.input_hash.to_be_bytes().to_lower_hex_string(),
            "d392922c00280a7e8d282182f5026f2fddbc74c1e1de18b4822128b2b77ec641",
            "input_hash"
        );

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

        for (k, pk, bk, bk_sk, spk_sk, script) in expected {
            let sender = sender_derive_output(&address, &agg, k);
            let (recv, spend_sk) =
                receiver_derive_output(&b_scan, &b_spend, &agg.a_pubkey, &agg.input_hash, k);

            assert_eq!(sender, recv, "sender/receiver agree at k={k}");
            assert_eq!(sender.spend_pubkey.serialize().to_lower_hex_string(), pk,      "P_k k={k}");
            assert_eq!(sender.blinding_pubkey.serialize().to_lower_hex_string(), bk,   "BK_k k={k}");
            assert_eq!(sender.blinding_seckey.secret_bytes().to_lower_hex_string(), bk_sk, "bk_k k={k}");
            assert_eq!(spend_sk.secret_bytes().to_lower_hex_string(), spk_sk, "spend_sk k={k}");
            assert_eq!(sender.script_pubkey().as_bytes().to_lower_hex_string(), script, "scriptPubKey k={k}");
        }

        assert_eq!(
            address.encode(ElementsNetwork::Liquid),
            "lqsp1qqd8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc65qjxd4lu4etruh9sngx3su9mtqp5fqzxz7re59y5nnez9p03ht3lyudcfhfe",
            "mainnet address"
        );
    }

    /// BIP-352 even-Y normalization for taproot inputs.
    ///
    /// `normalize_taproot_input_key` must return a key whose public point has
    /// even Y, leaving even-Y keys untouched and negating odd-Y ones. We assert
    /// the invariant directly, and that aggregating an odd-Y key *as taproot*
    /// changes the aggregate (negation happened) while aggregating it *as
    /// non-taproot* does not.
    #[test]
    fn taproot_even_y_negation() {
        // Find one even-Y and one odd-Y sample key among simple byte fills.
        let mut even_key = None;
        let mut odd_key = None;
        for b in 1u8..=0xff {
            let sk = sk_byte(b);
            match sk.x_only_public_key(&EC).1 {
                Parity::Even if even_key.is_none() => even_key = Some(sk),
                Parity::Odd if odd_key.is_none() => odd_key = Some(sk),
                _ => {}
            }
            if even_key.is_some() && odd_key.is_some() {
                break;
            }
        }
        let even_key = even_key.expect("some even-Y key exists");
        let odd_key = odd_key.expect("some odd-Y key exists");

        // Invariant: output always has even-Y public key.
        for sk in [even_key, odd_key] {
            let norm = normalize_taproot_input_key(sk);
            assert_eq!(
                norm.x_only_public_key(&EC).1,
                Parity::Even,
                "normalized key must have even-Y public point"
            );
        }
        // Even-Y key is untouched; odd-Y key is negated.
        assert_eq!(normalize_taproot_input_key(even_key), even_key, "even-Y unchanged");
        assert_eq!(normalize_taproot_input_key(odd_key), odd_key.negate(), "odd-Y negated");

        // Aggregation: treating the odd-Y key as taproot must differ from
        // treating it as non-taproot (the negation changes `a` and `A`).
        let op = outpoint(0x10, 0);
        let as_taproot = aggregate_inputs_with_parity(&[(op.clone(), odd_key, true)], &op);
        let as_legacy = aggregate_inputs_with_parity(&[(op.clone(), odd_key, false)], &op);
        assert_ne!(
            as_taproot.a_pubkey.serialize(),
            as_legacy.a_pubkey.serialize(),
            "odd-Y taproot input must be negated, changing A"
        );
        // The taproot aggregate's A is the even-Y point of the odd-Y key.
        assert_eq!(
            as_taproot.a_pubkey.x_only_public_key().0,
            odd_key.x_only_public_key(&EC).0,
            "x-only A is unchanged by negation"
        );
        assert_eq!(as_taproot.a_pubkey.serialize()[0], 0x02, "A is even-Y");

        // An even-Y taproot input behaves identically to a non-taproot input.
        let t_even = aggregate_inputs_with_parity(&[(op.clone(), even_key, true)], &op);
        let l_even = aggregate_inputs_with_parity(&[(op.clone(), even_key, false)], &op);
        assert_eq!(
            t_even.a_pubkey.serialize(),
            l_even.a_pubkey.serialize(),
            "even-Y key: taproot vs non-taproot agree"
        );
    }

    /// Tweak server: client's `S = b_scan · T` must equal sender's `S`.
    #[test]
    fn tweak_server_agreement() {
        let b_scan = sk_byte(0x11);
        let b_spend = sk_byte(0x22);
        let address = SilentPaymentAddress {
            scan: b_scan.public_key(&EC),
            spend: b_spend.public_key(&EC),
        };

        let agg = aggregate_inputs(&[(outpoint(0xAA, 0), sk_byte(0x55))], &outpoint(0xAA, 0));
        let sender_out = sender_derive_output(&address, &agg, 0);

        // Tweak server publishes T from public keys only.
        let (tweak, input_hash, a_pubkey) =
            compute_tweak(&[sk_byte(0x55).public_key(&EC)], &outpoint(0xAA, 0));
        let client_s = shared_secret_from_tweak(
            &b_scan,
            &TweakEntry { txid: [0u8; 32], tweak, a_pubkey, input_hash },
        );

        let client_out = derive_output(&b_spend.public_key(&EC), &client_s, 0);
        assert_eq!(client_out, sender_out, "client output must match sender");

        let sender_s = sender_shared_secret(&address.scan, &agg);
        assert_eq!(client_s.serialize(), sender_s.serialize(), "shared secrets must match");
    }

    /// CT round-trip: sender blinds to BK_k, receiver unblinds with bk_k.
    #[test]
    fn ct_round_trip_unblind_with_bk() {
        use lwk_wollet::elements::AssetId;

        let b_scan = sk_byte(0x11);
        let b_spend = sk_byte(0x22);
        let address = SilentPaymentAddress {
            scan: b_scan.public_key(&EC),
            spend: b_spend.public_key(&EC),
        };

        let agg = aggregate_inputs(&[(outpoint(0xAB, 0), sk_byte(0x33))], &outpoint(0xAB, 0));
        let k = 0;
        let asset = AssetId::from_slice(&[0x42; 32]).unwrap();
        let value = 123_456u64;
        let mut rng = rand::thread_rng();

        let sender_out = sender_derive_output(&address, &agg, k);
        let (txout, secrets) =
            build_confidential_sp_txout(&sender_out, asset, value, &mut rng).unwrap();

        let (recv_out, _) =
            receiver_derive_output(&b_scan, &b_spend, &agg.a_pubkey, &agg.input_hash, k);
        assert_eq!(recv_out.blinding_seckey, sender_out.blinding_seckey);

        let recovered = txout.unblind(&EC, recv_out.blinding_seckey).unwrap();
        assert_eq!(recovered.asset, asset);
        assert_eq!(recovered.value, value);
        assert_eq!(recovered.asset_bf, secrets.asset_bf);
        assert_eq!(recovered.value_bf, secrets.value_bf);

        // Wrong scan key → unblind fails.
        let (wrong, _) =
            receiver_derive_output(&sk_byte(0x99), &b_spend, &agg.a_pubkey, &agg.input_hash, k);
        assert_ne!(wrong.blinding_seckey, sender_out.blinding_seckey);
        assert!(txout.unblind(&EC, wrong.blinding_seckey).is_err());
    }

    /// Address round-trip and network separation.
    #[test]
    fn address_round_trip_and_network_separation() {
        let address = SilentPaymentAddress {
            scan: sk_byte(0x11).public_key(&EC),
            spend: sk_byte(0x22).public_key(&EC),
        };
        for network in [ElementsNetwork::Liquid, ElementsNetwork::LiquidTestnet] {
            let enc = address.encode(network);
            assert_eq!(SilentPaymentAddress::parse(&enc, network).unwrap(), address);
        }
        let mainnet = address.encode(ElementsNetwork::Liquid);
        assert_eq!(
            SilentPaymentAddress::parse(&mainnet, ElementsNetwork::LiquidTestnet),
            Err(AddressError::WrongNetwork),
        );
    }
}
