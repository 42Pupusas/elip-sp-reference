//! # Silent Payments for the Liquid Network — Reference Implementation
//!
//! This file is the reference implementation for the Liquid Silent Payments ELIP.
//! Each function maps to a single derivation step from the specification, with
//! inline documentation that spells out the underlying mathematics.
//!
//! The only external dependency is [`lwk_wollet`](https://crates.io/crates/lwk_wollet),
//! used for the secp256k1 context, key and scalar types, BIP-340 tagged hashes,
//! Taproot script construction, and Confidential Transactions primitives.
//! All Silent Payments logic is implemented here directly from the ELIP.
//!
//! ---
//!
//! ## Protocol overview
//!
//! ### 1. Address encoding
//!
//! The receiver generates two random private keys: `b_scan` and `b_spend`.
//! Their corresponding public keys `B_scan = b_scan·G` and `B_spend = b_spend·G`
//! are Bech32m-encoded with HRP `lqsp` (mainnet) or `tlqsp` (testnet), version `q`:
//!
//! ```text
//! lqsp1qqd8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc65qjxd4lu4etruh9sngx3su9mtqp5fqzxz7re59y5nnez9p03ht3lyudcfhfe
//! ```
//!
//! ### 2. Sender derivation
//!
//! Given the receiver's address `(B_scan, B_spend)` and a set of eligible
//! transaction inputs:
//!
//!   a. Sum the input private keys:  `a = Σ a_i`,  `A = a·G`
//!   b. Select the lexicographically smallest outpoint, `outpoint_L`
//!   c. `input_hash = SHA256("BIP0352/Inputs"||"BIP0352/Inputs" || outpoint_L || serP(A))`
//!      interpreted as a scalar modulo n
//!   d. ECDH shared secret: `S = input_hash · a · B_scan`
//!   e. For each output index `k`:
//!      - `t_k = SHA256("BIP0352/SharedSecret"||"BIP0352/SharedSecret" || serP(S) || ser32(k))` mod n
//!      - `P_k = B_spend + t_k·G`  — the Taproot spend key
//!      - `bk_k = SHA256("LiquidSilentPayments/Blind"||"LiquidSilentPayments/Blind" || serP(S) || ser32(k))` mod n
//!      - `BK_k = bk_k·G`  — the blinding key
//!
//! The output is a confidential Taproot output: `scriptPubKey = OP_1 <x_only(P_k)>`,
//! with asset and amount blinded to `BK_k`.
//!
//! ### 3. Tweak server (light-client support)
//!
//! The server computes and publishes one 33-byte value per transaction:
//!
//! ```text
//! T = input_hash · A   (where A = Σ input public keys)
//! ```
//!
//! The client retrieves `T` and computes `S = b_scan · T`, producing the same
//! shared secret the sender derived, without access to the sender's private keys.
//!
//! ### 4. Receiver scanning and unblinding
//!
//! The receiver knows `b_scan`, `b_spend`, and for each transaction either
//! `A` and `input_hash` or `T` from the tweak server:
//!
//!   a. `S = b_scan · (input_hash · A)`  — the same ECDH point as the sender
//!   b. For `k = 0, 1, 2, …`:
//!      - Recompute `P_k` and `scriptPubKey` as in step 2
//!      - Match against the transaction's outputs
//!      - On a match: derive `bk_k` and unblind the output
//!      - The spend secret is `b_spend + t_k` (even-Y normalized)
//!
//! ### 5. Spending
//!
//! A BIP-340 Schnorr signature with key `d = b_spend + t_k`, normalized to even Y.
//! Standard key-path Taproot spend.
//!
//! ---
//!
//! ## Running
//!
//! ```sh
//! cargo test    # verify the test vectors (4 tests)
//! ```

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Fe32, Hrp};

use lwk_wollet::elements::schnorr::TweakedPublicKey;
use lwk_wollet::elements::secp256k1_zkp::XOnlyPublicKey;
use lwk_wollet::elements::Script;
use lwk_wollet::hashes::{sha256t_hash_newtype, Hash, HashEngine};
use lwk_wollet::secp256k1::{PublicKey, Scalar, SecretKey};
use lwk_wollet::{ElementsNetwork, EC};

// ═══════════════════════════════════════════════════════════════════════════════
// Section 1 — Tagged hash domains (ELIP: Output blinding key)
// ═══════════════════════════════════════════════════════════════════════════════
//
// The `sha256t_hash_newtype!` macro expands each struct below to the BIP-340
// tagged-hash construction:  SHA256(tag || tag || message)  where
// tag = SHA256(domain_separator_string).
//
// Three domains are defined:
//   - "BIP0352/Inputs"              →  input_hash        (from BIP-352)
//   - "BIP0352/SharedSecret"        →  t_k               (from BIP-352)
//   - "LiquidSilentPayments/Blind"  →  bk_k              (ELIP-specific)

sha256t_hash_newtype! {
    /// Tagged hash for `input_hash = SHA256(tag||tag || outpoint_L || serP(A))` mod n.
    struct InputsTag = hash_str("BIP0352/Inputs");
    #[hash_newtype(forward)]
    struct InputsHash(_);

    /// Tagged hash for `t_k = SHA256(tag||tag || serP(S) || ser32(k))` mod n.
    struct SharedSecretTag = hash_str("BIP0352/SharedSecret");
    #[hash_newtype(forward)]
    struct SharedSecretHash(_);

    /// Tagged hash for `bk_k = SHA256(tag||tag || serP(S) || ser32(k))` mod n.
    ///
    /// The domain `LiquidSilentPayments/Blind` is disjoint from
    /// `BIP0352/SharedSecret`. This guarantees that `bk_k` and `t_k` are
    /// independent outputs even though both hash the same `(S, k)` pair —
    /// knowledge of one does not reveal the other.
    struct BlindTag = hash_str("LiquidSilentPayments/Blind");
    #[hash_newtype(forward)]
    struct BlindHash(_);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 2 — Address encoding and decoding  (ELIP: Address format)
// ═══════════════════════════════════════════════════════════════════════════════

/// Address version 0, encoded as the Bech32 character `q`.
const SP_ADDRESS_VERSION: Fe32 = Fe32::Q;

/// The human-readable part (HRP) for each network.
///
/// These are distinct from `ex`/`tex` (unconfidential addresses) and `lq`/`tlq`
/// (confidential blech32 addresses), as well as from Bitcoin's `sp`/`tsp`, so a
/// silent-payment address cannot be confused with any other address type.
fn hrp_for(network: ElementsNetwork) -> Hrp {
    match network {
        ElementsNetwork::Liquid => Hrp::parse_unchecked("lqsp"),
        _ => Hrp::parse_unchecked("tlqsp"),
    }
}

/// A Liquid silent-payment address, consisting of two public keys:
/// `B_scan` and `B_spend`.
///
/// Wire format: Bech32m(HRP, version=`q`, `serP(B_scan) || serP(B_spend)`),
/// where `serP` denotes the 33-byte SEC-1 compressed encoding of a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    /// 33-byte compressed scan public key (`B_scan`).
    pub scan: PublicKey,
    /// 33-byte compressed spend base public key (`B_spend`).
    pub spend: PublicKey,
}

impl SilentPaymentAddress {
    /// Encode this address as a Bech32m string for the given network.
    ///
    /// The encoded form is: HRP + separator + version `q` + 66 bytes of key data
    /// (33 for B_scan, 33 for B_spend), converted to 5-bit groups, with a
    /// Bech32m checksum appended.
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

    /// Parse a Bech32m silent-payment address, validating the HRP against the
    /// expected network and the version byte.
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

/// Errors returned when parsing a [`SilentPaymentAddress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    /// The string is not valid Bech32m.
    InvalidBech32m,
    /// The HRP does not match the expected network.
    WrongNetwork,
    /// The payload ended before the version byte could be read.
    Truncated,
    /// The version byte is not the expected value.
    UnknownVersion,
    /// The key payload is not 66 bytes.
    WrongPayloadLength(usize),
    /// One of the two public keys is not a valid curve point.
    InvalidPublicKey,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 3 — Sender derivation  (ELIP: Sender, Receiver)
// ═══════════════════════════════════════════════════════════════════════════════

/// The aggregated input state computed once per transaction by the sender.
#[derive(Debug, Clone, Copy)]
pub struct AggregatedInputs {
    /// `a = Σ a_i` — sum of all eligible input private keys.
    pub a_sum: SecretKey,
    /// `A = a·G` — the corresponding public key.
    pub a_pubkey: PublicKey,
    /// `input_hash = SHA256("BIP0352/Inputs"||"BIP0352/Inputs" || outpoint_L || serP(A))` mod n.
    pub input_hash: Scalar,
}

/// One derived silent-payment output: spend key, blinding key, and blinding
/// secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SilentPaymentOutput {
    /// `P_k = B_spend + t_k·G` — 33-byte compressed public key.
    pub spend_pubkey: PublicKey,
    /// `BK_k = bk_k·G` — the blinding public key.
    pub blinding_pubkey: PublicKey,
    /// `bk_k` — the 32-byte blinding secret (private key for `BK_k`).
    pub blinding_seckey: SecretKey,
}

impl SilentPaymentOutput {
    /// Build the Taproot `scriptPubKey`: `OP_1 <x_only(P_k)>`.
    ///
    /// Per BIP-352, `P_k` is used directly as the internal key with no taptweak.
    /// This is required so the receiver can match outputs by recomputing the
    /// script.
    pub fn script_pubkey(&self) -> Script {
        let x_only: XOnlyPublicKey = self.spend_pubkey.x_only_public_key().0;
        Script::new_v1_p2tr_tweaked(TweakedPublicKey::new(x_only))
    }
}

// ── Primitive helpers ──

/// `input_hash = SHA256("BIP0352/Inputs"||"BIP0352/Inputs" || outpoint_L || serP(A))` mod n.
///
/// `outpoint_L` is the 36-byte serialized lexicographically smallest outpoint
/// (32-byte txid in internal byte order, 4-byte little-endian vout).
/// `serP(A)` is the 33-byte compressed encoding of the aggregated public key.
fn input_hash(outpoint_l: &[u8], a_pubkey: &PublicKey) -> Scalar {
    let mut engine = InputsHash::engine();
    engine.input(outpoint_l);
    engine.input(&a_pubkey.serialize());
    let hash_bytes = InputsHash::from_engine(engine);
    Scalar::from_be_bytes(hash_bytes.to_byte_array()).expect("input_hash < curve order")
}

/// `t_k = SHA256("BIP0352/SharedSecret"||"BIP0352/SharedSecret" || serP(S) || ser32(k))` mod n.
///
/// `serP(S)` is the 33-byte compressed encoding of the shared secret point.
/// `ser32(k)` is the 4-byte big-endian encoding of the output index.
fn shared_secret_tweak(shared_secret_point: &PublicKey, output_index: u32) -> Scalar {
    let mut engine = SharedSecretHash::engine();
    engine.input(&shared_secret_point.serialize());
    engine.input(&output_index.to_be_bytes());
    let hash_bytes = SharedSecretHash::from_engine(engine);
    Scalar::from_be_bytes(hash_bytes.to_byte_array()).expect("t_k < curve order")
}

/// `bk_k = SHA256("LiquidSilentPayments/Blind"||"LiquidSilentPayments/Blind" || serP(S) || ser32(k))` mod n.
///
/// This is the ELIP's contribution beyond BIP-352. The domain tag
/// `LiquidSilentPayments/Blind` is disjoint from `BIP0352/SharedSecret`, so
/// `bk_k` is cryptographically independent of `t_k`.
fn blinding_secret(shared_secret_point: &PublicKey, output_index: u32) -> SecretKey {
    let mut engine = BlindHash::engine();
    engine.input(&shared_secret_point.serialize());
    engine.input(&output_index.to_be_bytes());
    let hash_bytes = BlindHash::from_engine(engine);
    SecretKey::from_slice(&hash_bytes.to_byte_array()).expect("bk_k < curve order")
}

/// Sender's ECDH shared secret: `S = input_hash · a · B_scan`.
///
/// `input_hash` binds the shared secret to the specific transaction inputs,
/// preventing it from being reused across transactions.
fn sender_shared_secret(
    scan_pubkey: &PublicKey,
    agg: &AggregatedInputs,
) -> PublicKey {
    let scalar = agg.a_sum.mul_tweak(&agg.input_hash).expect("scalar mul");
    scan_pubkey
        .mul_tweak(
            &EC,
            &Scalar::from_be_bytes(scalar.secret_bytes()).expect("scalar"),
        )
        .expect("ecdh")
}

/// Receiver's ECDH shared secret: `S = b_scan · (input_hash · A)`.
///
/// This produces the same point as the sender's `S = input_hash · a · B_scan`
/// because `b_scan · (input_hash · A) = b_scan · (input_hash · a·G) =
/// input_hash · a · (b_scan·G) = input_hash · a · B_scan`.
fn receiver_shared_secret(
    scan_seckey: &SecretKey,
    a_pubkey: &PublicKey,
    input_hash: &Scalar,
) -> PublicKey {
    let scalar = scan_seckey.mul_tweak(input_hash).expect("scalar mul");
    a_pubkey
        .mul_tweak(
            &EC,
            &Scalar::from_be_bytes(scalar.secret_bytes()).expect("scalar"),
        )
        .expect("ecdh")
}

/// Derive the output at index `k` from the shared secret and spend base key.
///
/// Both sender and receiver invoke this function with the same `S`, so they
/// produce identical `P_k` and `bk_k`.
fn derive_output(
    spend_base: &PublicKey,
    shared_secret: &PublicKey,
    output_index: u32,
) -> SilentPaymentOutput {
    let t_k = shared_secret_tweak(shared_secret, output_index);
    let spend_pubkey = spend_base.add_exp_tweak(&EC, &t_k).expect("P_k = B_spend + t_k*G");

    let blinding_seckey = blinding_secret(shared_secret, output_index);
    let blinding_pubkey = blinding_seckey.public_key(&EC);

    SilentPaymentOutput { spend_pubkey, blinding_pubkey, blinding_seckey }
}

// ── Public API ──

/// Aggregate the sender's eligible inputs.
///
/// `inputs` is a list of `(outpoint_bytes, private_key)` pairs for the
/// transaction inputs that are eligible under BIP-352's rules.
/// `outpoint_l` is the serialized lexicographically smallest outpoint among them
/// (Elements consensus encoding: 32-byte txid in internal byte order followed by
/// 4-byte little-endian vout).
pub fn aggregate_inputs(
    inputs: &[(Vec<u8>, SecretKey)],
    outpoint_l: &[u8],
) -> AggregatedInputs {
    let (first, rest) = inputs.split_first().expect("at least one eligible input");
    let mut a_sum = first.1;
    for (_, sk) in rest {
        a_sum = a_sum
            .add_tweak(&Scalar::from_be_bytes(sk.secret_bytes()).expect("scalar"))
            .expect("non-zero aggregated key");
    }

    let a_pubkey = a_sum.public_key(&EC);
    let ih = input_hash(outpoint_l, &a_pubkey);

    AggregatedInputs { a_sum, a_pubkey, input_hash: ih }
}

/// Sender: derive the silent-payment output at index `k` for a given address.
///
/// Call `aggregate_inputs` first, then call this for each output.
pub fn sender_derive_output(
    address: &SilentPaymentAddress,
    agg: &AggregatedInputs,
    k: u32,
) -> SilentPaymentOutput {
    let shared_secret = sender_shared_secret(&address.scan, agg);
    derive_output(&address.spend, &shared_secret, k)
}

/// Receiver: recompute the output at index `k` and derive the spend private key.
///
/// Returns `(SilentPaymentOutput, spend_secret)` where the spend secret is
/// `b_spend + t_k` (to be normalized to even Y at signing time).
pub fn receiver_derive_output(
    scan_seckey: &SecretKey,
    spend_seckey: &SecretKey,
    a_pubkey: &PublicKey,
    input_hash: &Scalar,
    k: u32,
) -> (SilentPaymentOutput, SecretKey) {
    let shared_secret = receiver_shared_secret(scan_seckey, a_pubkey, input_hash);
    let output = derive_output(&spend_seckey.public_key(&EC), &shared_secret, k);
    let t_k = shared_secret_tweak(&shared_secret, k);
    let spend_secret = spend_seckey.add_tweak(&t_k).expect("spend sk");

    (output, spend_secret)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 4 — Tweak server  (ELIP: Light-Client Receive)
// ═══════════════════════════════════════════════════════════════════════════════
//
// The tweak server publishes one 33-byte value per transaction:
//
//     T = input_hash · A          where A = Σ(input public keys)
//
// A light client retrieves `T` and computes `S = b_scan · T`, yielding the same
// ECDH shared secret the sender derived, without access to the sender's private
// keys.
//
// On Liquid, BIP-158 compact filters are unnecessary because Confidential
// Transactions blind the asset and amount but leave the scriptPubKey public.
// The client can match candidate scripts directly against the outputs it
// retrieves from the Esplora API.

/// Compute the partial tweak for a transaction: `T = input_hash · A`.
///
/// The result is not secret — both `input_hash` and `A` are computable from
/// public transaction data.
///
/// `input_pubkeys` are the public keys extracted from each eligible input
/// (per BIP-352's P2PKH, P2SH-P2WPKH, P2WPKH, P2TR eligibility rules).
/// `outpoint_l` is the serialized lexicographically smallest outpoint.
pub fn compute_tweak(
    input_pubkeys: &[PublicKey],
    outpoint_l: &[u8],
) -> (PublicKey, Scalar) {
    let a_pubkey = PublicKey::combine_keys(
        &input_pubkeys.iter().collect::<Vec<_>>(),
    )
    .expect("at least one input pubkey");

    let ih = input_hash(outpoint_l, &a_pubkey);

    let tweak_point = a_pubkey
        .mul_tweak(&EC, &ih)
        .expect("tweak point");

    (tweak_point, ih)
}

/// A published tweak for one transaction.
#[derive(Debug, Clone)]
pub struct TweakEntry {
    /// The transaction ID.
    pub txid: [u8; 32],
    /// `T = input_hash · A` — 33-byte compressed point.
    pub tweak: PublicKey,
    /// `A` — the aggregated input public key.
    pub a_pubkey: PublicKey,
    /// `input_hash` — from the lexicographically smallest outpoint and `A`.
    pub input_hash: Scalar,
}

/// A minimal tweak server that stores tweaks per transaction.
#[derive(Debug, Default)]
pub struct TweakServer {
    entries: Vec<TweakEntry>,
}

impl TweakServer {
    /// Publish a tweak for a transaction.
    pub fn publish(
        &mut self,
        txid: [u8; 32],
        input_pubkeys: &[PublicKey],
        outpoint_l: &[u8],
    ) {
        let (tweak, input_hash) = compute_tweak(input_pubkeys, outpoint_l);
        let a_pubkey = PublicKey::combine_keys(
            &input_pubkeys.iter().collect::<Vec<_>>(),
        )
        .expect("at least one input pubkey");
        self.entries.push(TweakEntry { txid, tweak, a_pubkey, input_hash });
    }

    /// Look up a tweak by transaction ID.
    pub fn get_by_txid(&self, txid: &[u8; 32]) -> Option<&TweakEntry> {
        self.entries.iter().find(|e| &e.txid == txid)
    }
}

/// Compute the shared secret from a tweak server entry: `S = b_scan · T`.
///
/// Because `T = input_hash · A`, this is equivalent to the sender's
/// `S = input_hash · a · B_scan`.
pub fn shared_secret_from_tweak(
    scan_seckey: &SecretKey,
    tweak_entry: &TweakEntry,
) -> PublicKey {
    tweak_entry
        .tweak
        .mul_tweak(
            &EC,
            &Scalar::from_be_bytes(scan_seckey.secret_bytes()).expect("scalar"),
        )
        .expect("ecdh")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 5 — Confidential output blinding and unblinding  (ELIP: Output blinding key)
// ═══════════════════════════════════════════════════════════════════════════════
//
// The sender blinds the confidential output to `BK_k = bk_k·G`. The receiver
// independently computes `bk_k` from the shared secret and unblinds the output,
// recovering the plaintext asset and value with no out-of-band key exchange.

/// Build a fully-blinded confidential `TxOut` for a silent-payment output.
///
/// The Confidential Transactions nonce is derived from `BK_k`, the SP-derived
/// blinding public key. Because the receiver recomputes `bk_k` → `BK_k`, the
/// same nonce derivation path is available to them for unblinding.
pub fn build_confidential_sp_txout(
    out: &SilentPaymentOutput,
    asset: lwk_wollet::elements::AssetId,
    value: u64,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<
    (
        lwk_wollet::elements::TxOut,
        lwk_wollet::elements::TxOutSecrets,
    ),
    lwk_wollet::elements::secp256k1_zkp::Error,
> {
    use lwk_wollet::elements::confidential::{
        Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor,
    };
    use lwk_wollet::elements::secp256k1_zkp::{Generator, PedersenCommitment, RangeProof, Tag};
    use lwk_wollet::elements::{TxOut, TxOutSecrets, TxOutWitness};

    let script_pubkey = out.script_pubkey();

    // Random blinding factors for asset and value.
    let abf = AssetBlindingFactor::new(&mut *rng);
    let vbf = ValueBlindingFactor::new(&mut *rng);

    // The CT ephemeral nonce is derived from BK_k, the SP-derived blinding
    // public key. This is what lets the receiver — who recomputes bk_k and
    // therefore BK_k — unblind the output.
    let (nonce, ct_shared_secret) =
        Nonce::new_confidential(&mut *rng, &EC, &out.blinding_pubkey);

    let asset_tag = Tag::from(asset.into_inner().to_byte_array());
    let asset_generator = Generator::new_blinded(&EC, asset_tag, abf.into_inner());
    let value_commitment =
        PedersenCommitment::new(&EC, value, vbf.into_inner(), asset_generator);

    let mut message = [0u8; 64];
    message[..32].copy_from_slice(&asset.into_inner().to_byte_array());
    message[32..].copy_from_slice(abf.into_inner().as_ref());

    let rangeproof = RangeProof::new(
        &EC,
        1,
        value_commitment,
        value,
        vbf.into_inner(),
        &message,
        script_pubkey.as_bytes(),
        ct_shared_secret,
        0,
        52,
        asset_generator,
    )?;

    let txout = TxOut {
        asset: Asset::Confidential(asset_generator),
        value: Value::Confidential(value_commitment),
        nonce,
        script_pubkey,
        witness: TxOutWitness {
            surjection_proof: None,
            rangeproof: Some(Box::new(rangeproof)),
        },
    };
    let secrets = TxOutSecrets { asset, asset_bf: abf, value, value_bf: vbf };

    Ok((txout, secrets))
}

/// Unblind a confidential output using the SP-derived `bk_k`.
///
/// After matching `P_k` to the output's scriptPubKey, the receiver derives
/// `bk_k` from the shared secret and calls this function to recover the
/// plaintext asset and value.
///
/// Returns the `TxOutSecrets` containing `asset`, `value`, `asset_bf`, and
/// `value_bf`.
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

    /// Construct a secret key from a single repeated byte (e.g. `0x11`
    /// repeated 32 times).
    fn secret_key_from_byte(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }

    /// Serialize an outpoint to the 36-byte form used by BIP-352:
    /// 32-byte txid (internal/consensus byte order) followed by 4-byte
    /// little-endian vout.
    fn outpoint_bytes(txid_byte: u8, vout: u32) -> Vec<u8> {
        let mut v = vec![txid_byte; 32];
        v.extend_from_slice(&vout.to_le_bytes());
        v
    }

    /// ── Test vectors ──
    ///
    /// Fixed inputs:
    ///   - Receiver keys:  `b_scan = 0x11×32`,  `b_spend = 0x22×32`
    ///   - Two eligible inputs:
    ///       input 0:  priv = 0x31×32,  outpoint = 0x10…:0  (lexicographically smallest)
    ///       input 1:  priv = 0x32×32,  outpoint = 0x20…:1
    ///
    /// A conforming implementation must reproduce every value checked below.
    #[test]
    fn test_vectors() {
        let b_scan  = secret_key_from_byte(0x11);
        let b_spend = secret_key_from_byte(0x22);
        let address = SilentPaymentAddress {
            scan:  b_scan.public_key(&EC),
            spend: b_spend.public_key(&EC),
        };

        let inputs = [
            (outpoint_bytes(0x10, 0), secret_key_from_byte(0x31)),
            (outpoint_bytes(0x20, 1), secret_key_from_byte(0x32)),
        ];
        let outpoint_l = outpoint_bytes(0x10, 0);
        let agg = aggregate_inputs(&inputs, &outpoint_l);

        // A = a·G
        assert_eq!(
            agg.a_pubkey.serialize().to_lower_hex_string(),
            "031195a8046dcbb8e17034bca630065e7a0982e4e36f6f7e5a8d4554e4846fcd99",
            "A"
        );
        // input_hash
        assert_eq!(
            agg.input_hash.to_be_bytes().to_lower_hex_string(),
            "d392922c00280a7e8d282182f5026f2fddbc74c1e1de18b4822128b2b77ec641",
            "input_hash"
        );

        let expected_outputs: [(u32, &str, &str, &str, &str, &str); 2] = [
            (
                0,
                "02a29d9716417c964ca9e477343e71ffe730a4991a3eaad668eabec84e9feb7931",  // P_k
                "0344e1289497e6da66fde710d2f38de053fc07355e405524401d7d609df5a1a8cc",  // BK_k
                "70ab8897b64bd21b427339ff4d014b883191ef6425862246c53bfc27a59aa3f0",   // bk_k
                "f03c436d2cd67ae1fecf7d88a38aa3a03c0abea43feaf6da8eb71e2e3a866bda",   // spend_sk
                "5120a29d9716417c964ca9e477343e71ffe730a4991a3eaad668eabec84e9feb7931", // scriptPubKey
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

        for (k, p_k_hex, bk_pub_hex, bk_sec_hex, spend_sk_hex, spk_hex) in expected_outputs {
            let sender_out = sender_derive_output(&address, &agg, k);
            let (recv_out, spend_sk) =
                receiver_derive_output(&b_scan, &b_spend, &agg.a_pubkey, &agg.input_hash, k);

            assert_eq!(sender_out, recv_out, "sender and receiver must agree at k={k}");

            assert_eq!(sender_out.spend_pubkey.serialize().to_lower_hex_string(),
                       p_k_hex, "P_k  k={k}");
            assert_eq!(sender_out.blinding_pubkey.serialize().to_lower_hex_string(),
                       bk_pub_hex, "BK_k k={k}");
            assert_eq!(sender_out.blinding_seckey.secret_bytes().to_lower_hex_string(),
                       bk_sec_hex, "bk_k k={k}");
            assert_eq!(spend_sk.secret_bytes().to_lower_hex_string(),
                       spend_sk_hex, "spend_sk k={k}");
            assert_eq!(sender_out.script_pubkey().as_bytes().to_lower_hex_string(),
                       spk_hex, "scriptPubKey k={k}");
        }

        // Mainnet address (HRP `lqsp`).
        assert_eq!(
            address.encode(ElementsNetwork::Liquid),
            "lqsp1qqd8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc65qjxd4lu4etruh9sngx3su9mtqp5fqzxz7re59y5nnez9p03ht3lyudcfhfe",
            "mainnet address"
        );
    }

    /// ── Tweak server agreement ──
    ///
    /// Verifies that the shared secret computed from the tweak server's `T`
    /// matches the sender's shared secret.
    #[test]
    fn tweak_server_agreement() {
        let b_scan = secret_key_from_byte(0x11);
        let b_spend = secret_key_from_byte(0x22);
        let address = SilentPaymentAddress {
            scan: b_scan.public_key(&EC),
            spend: b_spend.public_key(&EC),
        };

        let inputs = [(outpoint_bytes(0xAA, 0), secret_key_from_byte(0x55))];
        let outpoint_l = outpoint_bytes(0xAA, 0);
        let agg = aggregate_inputs(&inputs, &outpoint_l);

        let sender_out = sender_derive_output(&address, &agg, 0);

        // The tweak server only knows the public keys.
        let input_pubkeys = vec![secret_key_from_byte(0x55).public_key(&EC)];
        let (tweak_point, input_hash) = compute_tweak(&input_pubkeys, &outpoint_l);

        // The client retrieves T and computes S.
        let client_s = shared_secret_from_tweak(
            &b_scan,
            &TweakEntry {
                txid: [0u8; 32],
                tweak: tweak_point,
                a_pubkey: agg.a_pubkey,
                input_hash,
            },
        );

        let client_out = derive_output(&b_spend.public_key(&EC), &client_s, 0);

        assert_eq!(client_out, sender_out,
            "client output must match sender output");

        let sender_s = sender_shared_secret(&address.scan, &agg);
        assert_eq!(client_s.serialize(), sender_s.serialize(),
            "shared secrets must match");
    }

    /// ── Confidential output round-trip ──
    ///
    /// The sender blinds a confidential output to `BK_k`. The receiver
    /// independently computes `bk_k` from the shared secret and unblinds,
    /// recovering the exact asset and value with no out-of-band key exchange.
    #[test]
    fn ct_round_trip_unblind_with_bk() {
        use lwk_wollet::elements::AssetId;

        let b_scan  = secret_key_from_byte(0x11);
        let b_spend = secret_key_from_byte(0x22);
        let address = SilentPaymentAddress {
            scan: b_scan.public_key(&EC),
            spend: b_spend.public_key(&EC),
        };

        let inputs = [(outpoint_bytes(0xAB, 0), secret_key_from_byte(0x33))];
        let outpoint_l = outpoint_bytes(0xAB, 0);
        let agg = aggregate_inputs(&inputs, &outpoint_l);
        let k = 0u32;

        let asset = AssetId::from_slice(&[0x42; 32]).unwrap();
        let value: u64 = 123_456;
        let mut rng = rand::thread_rng();

        // Sender: derive and blind.
        let sender_out = sender_derive_output(&address, &agg, k);
        let (txout, secrets_in) =
            build_confidential_sp_txout(&sender_out, asset, value, &mut rng).unwrap();

        // Receiver: recompute bk_k and unblind.
        let (recv_out, _spend_sk) =
            receiver_derive_output(&b_scan, &b_spend, &agg.a_pubkey, &agg.input_hash, k);
        assert_eq!(recv_out.blinding_seckey, sender_out.blinding_seckey,
            "bk_k must match between sender and receiver");

        let recovered = txout
            .unblind(&EC, recv_out.blinding_seckey)
            .expect("unblind with bk_k");

        assert_eq!(recovered.asset, asset, "asset must match");
        assert_eq!(recovered.value, value, "value must match");
        assert_eq!(recovered.asset_bf, secrets_in.asset_bf, "asset BF must match");
        assert_eq!(recovered.value_bf, secrets_in.value_bf, "value BF must match");

        // Wrong scan key produces a different bk_k, and unblinding must fail.
        let wrong_scan = secret_key_from_byte(0x99);
        let (wrong_out, _) =
            receiver_derive_output(&wrong_scan, &b_spend, &agg.a_pubkey, &agg.input_hash, k);
        assert_ne!(wrong_out.blinding_seckey, sender_out.blinding_seckey);
        assert!(txout.unblind(&EC, wrong_out.blinding_seckey).is_err(),
            "unblind with wrong scan key must fail");
    }

    /// ── Address round-trip and network separation ──
    #[test]
    fn address_round_trip_and_network_separation() {
        let address = SilentPaymentAddress {
            scan: secret_key_from_byte(0x11).public_key(&EC),
            spend: secret_key_from_byte(0x22).public_key(&EC),
        };

        for network in [ElementsNetwork::Liquid, ElementsNetwork::LiquidTestnet] {
            let encoded = address.encode(network);
            assert_eq!(SilentPaymentAddress::parse(&encoded, network).unwrap(), address);
        }

        // A mainnet address must not parse under the testnet HRP.
        let mainnet_addr = address.encode(ElementsNetwork::Liquid);
        assert_eq!(
            SilentPaymentAddress::parse(&mainnet_addr, ElementsNetwork::LiquidTestnet),
            Err(AddressError::WrongNetwork),
        );
    }
}
