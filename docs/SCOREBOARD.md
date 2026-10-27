# skillspector-rs vs SkillSpector v2.12.0 (--no-llm), measured
Hardware: Apple M1 Pro, macOS-26.5.2-arm64-arm-64bit-Mach-O. Corpus: 16 public fixture skills (tests/fixtures).
Single-skill runs are one process per scan (cold start included): Python 3x, Rust 20x per skill => n=48 vs n=320.

## Wall time per skill scan (seconds)
| | p50 | p95 | p99 |
|---|---|---|---|
| SkillSpector (Python) | 3.73 | 4.63 | 5.13 |
| skillspector-rs | 0.230 | 0.492 | 0.534 |
| **speedup** | 16x | 9x | 10x |

## Resources per scan
| | CPU time p50 (s) | CPU time p95 (s) | peak RSS p50 (MB) | peak RSS p95 (MB) |
|---|---|---|---|---|
| SkillSpector (Python) | 3.65 | 4.23 | 202 | 209 |
| skillspector-rs | 0.30 | 0.50 | 80 | 106 |

## Batch (one process, --recursive)
| Workload | SkillSpector (Python) | skillspector-rs |
|---|---|---|
| 24 skills | 5.3s | 0.48s (11x) |
| 500 skills | not possible (stops at 32 skills) | p50 5.6s, p95 5.8s (89 skills/s) |

## Parity (file, rule id, start line; SC4 excluded)
Reference findings 71; matched **65 (91.5%)**; extra findings in Rust **4**; missing 6 (unported analyzers P5, TP1-3, TR2, SC3/oms; see KNOWN_DIFFERENCES.md).
Private corpus (865 real skill folders, 3 runs today): 2777/2800 matched (99.2%), 0 extra findings, 0 errors. The 23 differences are SC4 (18, needs network) and AE1 (5, depends on machine load). Rust scans all 865 skills in 13.0-13.7 s wall (83 s CPU, 8 cores), about 65 skills/s.
