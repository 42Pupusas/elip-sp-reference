# Liquid Taproot Usage Analysis

**Date**: 2026-02-15  
**Source**: `https://liquid.network/liquid/api`  
**Blocks scanned**: 500 (heights 3,935,091 – 3,935,590)  
**Time**: ~315s (200ms delay between requests)

## Summary

| Script type | Count | % |
|---|---|---|
| v0_p2wpkh | 13,558 | 68.30% |
| fee | 3,530 | 17.78% |
| op_return | 1,046 | 5.27% |
| p2sh | 614 | 3.09% |
| **v1_p2tr** | **603** | **3.04%** |
| p2pkh | 499 | 2.51% |
| v0_p2wsh | 2 | 0.01% |
| **Total** | **19,852** | |

| Metric | Value |
|---|---|
| Total transactions | 4,030 |
| v1_p2tr outputs | 603 |
| v1_p2tr percentage | 3.04% |
| Avg v1_p2tr per block | 1.2 |

## Interpretation

Taproot usage on Liquid mainnet exists but is sparse:

- ~1.2 Taproot outputs per block on average
- 3.04% of all outputs, compared to ~30% on Bitcoin mainnet
- An SP output is not automatically identifiable, but in blocks with few or no
  other Taproot outputs a new v1_p2tr output would stand out


## Tool

```
cargo run --bin analyze_taproot -- --blocks N [--base-url URL]
```

Source: `src/bin/analyze_taproot.rs`
