//! Sample the last N Liquid blocks from the Esplora HTTP API and count outputs
//! by script type, to gauge real-world Taproot usage on Liquid mainnet.
//!
//! Usage:
//!   cargo run --bin analyze_taproot -- [--blocks N] [--base-url URL]
//!
//! Default: 100 blocks from https://blockstream.info/liquid/api

use serde::Deserialize;
use std::collections::BTreeMap;
use std::thread::sleep;
use std::time::{Duration, Instant};

const DEFAULT_BASE_URL: &str = "https://blockstream.info/liquid/api";
const DEFAULT_BLOCKS: u32 = 100;

#[derive(Deserialize)]
struct BlockTx {
    #[allow(dead_code)]
    txid: String,
    vout: Vec<Vout>,
}

#[derive(Deserialize)]
struct Vout {
    scriptpubkey_type: String,
}

struct HttpClient {
    client: reqwest::blocking::Client,
    base_url: String,
}

impl HttpClient {
    fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            base_url: base_url.to_string(),
        }
    }

    fn get(&self, path: &str) -> String {
        let url = format!("{}/{}", self.base_url, path);
        let mut attempt = 0u32;
        loop {
            match self.client.get(&url).send() {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().unwrap_or_default();
                    if status == 200 {
                        return body;
                    }
                    if status == 429 {
                        attempt += 1;
                        if attempt > 10 {
                            panic!("still rate-limited after 10 retries");
                        }
                        let wait = Duration::from_secs(attempt as u64 * 2);
                        eprintln!(
                            "  rate-limited (429) — waiting {:?} (attempt {})",
                            wait, attempt
                        );
                        sleep(wait);
                        continue;
                    }
                    panic!("HTTP {} for {}: {}", status, url, body);
                }
                Err(e) => {
                    attempt += 1;
                    if attempt > 5 {
                        panic!("request failed after 5 attempts: {}", e);
                    }
                    let wait = Duration::from_millis(500 * (1 << attempt));
                    eprintln!(
                        "  request error (attempt {}/5): {} — retrying in {:?}",
                        attempt, e, wait
                    );
                    sleep(wait);
                }
            }
        }
    }
}

fn parse_txs(body: &str) -> Vec<BlockTx> {
    serde_json::from_str(body).unwrap_or_else(|_| {
        let single: BlockTx = serde_json::from_str(body).expect("neither array nor object");
        vec![single]
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut blocks_to_fetch = DEFAULT_BLOCKS;
    let mut base_url = DEFAULT_BASE_URL.to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--blocks" => {
                i += 1;
                blocks_to_fetch = args[i].parse().expect("--blocks needs a number");
            }
            "--base-url" => {
                i += 1;
                base_url = args[i].clone();
            }
            _ => {
                eprintln!("unknown arg: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    eprintln!("fetching {} blocks from {} ...", blocks_to_fetch, base_url);
    let http = HttpClient::new(&base_url);
    let tip_height: u32 = http
        .get("blocks/tip/height")
        .trim()
        .parse()
        .expect("tip height is a u32");
    eprintln!("tip height = {}", tip_height);

    let start_height = tip_height.saturating_sub(blocks_to_fetch - 1);
    let mut total_outputs: u64 = 0;
    let mut type_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut blocks_processed = 0u32;
    let mut tx_count = 0u64;
    let t0 = Instant::now();

    for height in start_height..=tip_height {
        let hash = http
            .get(&format!("block-height/{}", height))
            .trim()
            .to_string();
        let body = http.get(&format!("block/{}/txs", hash));
        let txs = parse_txs(&body);
        sleep(Duration::from_millis(200));

        for tx in &txs {
            tx_count += 1;
            for vout in &tx.vout {
                total_outputs += 1;
                *type_counts
                    .entry(vout.scriptpubkey_type.clone())
                    .or_insert(0) += 1;
            }
        }
        blocks_processed += 1;
        if blocks_processed % 25 == 0 {
            eprintln!(
                "  block {}/{} (height {}) — {:.1}s",
                blocks_processed,
                blocks_to_fetch,
                height,
                t0.elapsed().as_secs_f64()
            );
        }
    }

    let elapsed = t0.elapsed().as_secs_f64();
    let mut sorted: Vec<_> = type_counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    let taproot_count = type_counts.get("v1_p2tr").copied().unwrap_or(0);
    let taproot_pct = if total_outputs > 0 {
        taproot_count as f64 / total_outputs as f64 * 100.0
    } else {
        0.0
    };
    let avg_per_block = taproot_count as f64 / blocks_processed as f64;

    println!();
    println!("═══════════════════════════════════════════════");
    println!("Liquid Taproot Usage Analysis");
    println!("═══════════════════════════════════════════════");
    println!(
        "blocks scanned:  {}  ({}-{})",
        blocks_processed, start_height, tip_height
    );
    println!("transactions:    {}", tx_count);
    println!("total outputs:   {}", total_outputs);
    println!("time:            {:.1}s", elapsed);
    println!();
    println!("{:<30} {:>10} {:>10}", "script type", "count", "%");
    println!("{:-<52}", "");
    for (typ, count) in &sorted {
        let pct = if total_outputs > 0 {
            **count as f64 / total_outputs as f64 * 100.0
        } else {
            0.0
        };
        println!("{:<30} {:>10} {:>9.2}%", typ, count, pct);
    }
    println!("{:-<52}", "");
    println!();
    println!("═══════════════════════════════════════════════");
    println!("KEY FINDING");
    println!("═══════════════════════════════════════════════");
    println!(
        "Taproot (v1_p2tr) outputs: {} / {} ({:.2}%)",
        taproot_count, total_outputs, taproot_pct
    );
    println!("avg v1_p2tr per block:    {:.1}", avg_per_block);
    println!();

    if taproot_pct < 0.1 || avg_per_block < 0.5 {
        println!("WARNING: Taproot usage is near-zero on Liquid mainnet.");
        println!("  ({:.2}%, {:.1}/block)", taproot_pct, avg_per_block);
        println!("  Every v1_p2tr output would stand out as anomalous.");
        println!();
        println!("  -> SP outputs are distinguishable on Liquid today.");
        println!("  -> The anonymity set is effectively empty.");
        println!();
        println!("  Mitigations:");
        println!("  1. Encourage organic Taproot adoption (DLCs, MuSig, etc.)");
        println!("  2. Consider a different output type (v0_p2wpkh + tweak");
        println!("     recoverable from the shared secret at extra byte cost)");
        println!("  3. Accept degraded unlinkability for early adopters");
        println!("     and document as a known bootstrapping limitation");
    } else if avg_per_block < 3.0 {
        println!(
            "NOTE: Taproot usage exists but is thin ({:.1}/block).",
            avg_per_block
        );
        println!("  SP outputs have a limited per-block anonymity set.");
        println!(
            "  In aggregate (~{:.0} across the scan window) they are",
            taproot_count
        );
        println!("  harder to single out, but per-block analysis is a concern.");
        println!("  This is a known bootstrapping limitation - improves with adoption.");
    } else {
        println!("OK: Taproot usage is healthy ({:.1}/block).", avg_per_block);
        println!("  SP outputs have a reasonable crowd to hide in.");
    }
}
