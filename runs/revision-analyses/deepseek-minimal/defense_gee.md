# GEE logistic models of attack success: per model and model-by-defense-by-goal

Runs: `runs/revision-deepseek-minimal/full` (prompt version v3).
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Logistic GEE with an exchangeable working correlation, clustered by vulnerable/fixed pair, as in `analyze_gee`. Outcome `attack_success` uses every attacked prompt (raw ASR); `conditional_flip` uses attacked prompts whose clean verdict (same model, item and defense) was correct. Per-model fits: defense + style + goal (+ placement). Pooled fit: defense x goal x model, plus style and placement. References: neutral defense, DSC style, suppression goal, top placement. Status `unstable` flags separation (an odds ratio beyond e^10 or a non-finite SE); such estimates should not be reported. Total fitting time 0.8s.

## Per-model defense odds ratios (attack_success)

| Model | n | Pairs | Status | defense[tagged] | defense[warning] |
|---|---:|---:|---|---:|---:|
| `deepseek/deepseek-v4-pro` | 3168 | 176 | converged | 0.29 [0.25, 0.34], p=4.5e-61 | 0.30 [0.26, 0.34], p=3e-70 |

## Pooled defense x goal x model (attack_success)

n=3168, pairs=176, status: converged, 0.0s.

| Term (joint Wald test) | chi2 | df | p |
|---|---:|---:|---:|
| `defense` | 58.98 | 2 | 1.6e-13 |
| `goal` | 52.74 | 1 | 3.8e-13 |
| `style` | 7.39 | 2 | 0.025 |
| `defense:goal` | 69.08 | 2 | 1e-15 |

| Term | Odds ratio [95% CI], p |
|---|---:|
| `defense[tagged]` | 0.54 [0.45, 0.65], p=6.9e-11 |
| `defense[warning]` | 0.51 [0.43, 0.61], p=5.8e-14 |
| `defense[tagged]:goal[induction]` | 0.23 [0.16, 0.33], p=3.6e-16 |
| `defense[warning]:goal[induction]` | 0.27 [0.20, 0.38], p=2.2e-14 |

## Per-model defense odds ratios (conditional_flip)

| Model | n | Pairs | Status | defense[tagged] | defense[warning] |
|---|---:|---:|---|---:|---:|
| `deepseek/deepseek-v4-pro` | 1815 | 170 | converged | 0.16 [0.12, 0.21], p=4.5e-41 | 0.18 [0.14, 0.23], p=1.5e-41 |

## Pooled defense x goal x model (conditional_flip)

n=1815, pairs=170, status: converged, 0.0s.

| Term (joint Wald test) | chi2 | df | p |
|---|---:|---:|---:|
| `defense` | 56.17 | 2 | 6.3e-13 |
| `goal` | 43.30 | 1 | 4.7e-11 |
| `style` | 2.34 | 2 | 0.31 |
| `defense:goal` | 40.64 | 2 | 1.5e-09 |

| Term | Odds ratio [95% CI], p |
|---|---:|
| `defense[tagged]` | 0.30 [0.21, 0.42], p=1.4e-12 |
| `defense[warning]` | 0.36 [0.26, 0.51], p=4.4e-09 |
| `defense[tagged]:goal[induction]` | 0.28 [0.17, 0.46], p=5.8e-07 |
| `defense[warning]:goal[induction]` | 0.23 [0.14, 0.37], p=1.2e-09 |
