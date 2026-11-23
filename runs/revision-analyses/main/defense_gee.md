# GEE logistic models of attack success: per model and model-by-defense-by-goal

Runs: `runs/openrouter-v2/full` (prompt version v2); `runs/revision-placebo/full` (prompt version v3).
Adaptive runs: `runs/revision-adaptive/full`.
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Logistic GEE with an exchangeable working correlation, clustered by vulnerable/fixed pair, as in `analyze_gee`. Outcome `attack_success` uses every attacked prompt (raw ASR); `conditional_flip` uses attacked prompts whose clean verdict (same model, item and defense) was correct. Per-model fits: defense + style + goal (+ placement). Pooled fit: defense x goal x model, plus style and placement. References: neutral defense, DSC style, suppression goal, top placement. Status `unstable` flags separation (an odds ratio beyond e^10 or a non-finite SE); such estimates should not be reported. Total fitting time 2.7s.

## Per-model defense odds ratios (attack_success)

| Model | n | Pairs | Status | defense[placebo] | defense[tagged] | defense[warning] |
|---|---:|---:|---|---:|---:|---:|
| `anthropic/claude-sonnet-5.5` | 11264 | 176 | converged | 0.82 [0.76, 0.89], p=6.3e-07 | 0.74 [0.68, 0.81], p=2.6e-11 | 0.78 [0.72, 0.83], p=2.7e-12 |
| `deepseek/deepseek-v4-pro` | 11264 | 176 | converged | 1.05 [0.91, 1.20], p=0.53 | 0.21 [0.17, 0.25], p=7.6e-59 | 0.31 [0.27, 0.37], p=5.6e-43 |
| `google/gemini-3.8-flash` | 11262 | 176 | converged | 1.05 [0.98, 1.12], p=0.14 | 0.70 [0.64, 0.77], p=1.6e-14 | 0.65 [0.59, 0.70], p=1e-22 |
| `openai/gpt-6.1-sol` | 11264 | 176 | converged | 0.97 [0.93, 1.01], p=0.087 | 1.03 [0.96, 1.10], p=0.45 | 1.02 [0.96, 1.09], p=0.53 |

## Pooled defense x goal x model (attack_success)

n=45054, pairs=176, status: converged, 0.4s.

| Term (joint Wald test) | chi2 | df | p |
|---|---:|---:|---:|
| `defense` | 4.32 | 3 | 0.23 |
| `goal` | 36.53 | 1 | 1.5e-09 |
| `model` | 271.09 | 3 | 1.8e-58 |
| `style` | 202.79 | 4 | 9.4e-43 |
| `placement` | 7.77 | 1 | 0.0053 |
| `defense:goal` | 93.46 | 3 | 4e-20 |
| `defense:model` | 121.94 | 9 | 5.4e-22 |
| `goal:model` | 58.02 | 3 | 1.6e-12 |
| `defense:goal:model` | 330.43 | 9 | 9e-66 |

| Term | Odds ratio [95% CI], p |
|---|---:|
| `defense[placebo]` | 1.13 [1.00, 1.26], p=0.041 |
| `defense[tagged]` | 1.05 [0.95, 1.16], p=0.36 |
| `defense[warning]` | 1.01 [0.94, 1.08], p=0.81 |
| `defense[placebo]:goal[induction]` | 0.46 [0.37, 0.57], p=2e-12 |
| `defense[tagged]:goal[induction]` | 0.41 [0.33, 0.51], p=5.2e-15 |
| `defense[warning]:goal[induction]` | 0.52 [0.44, 0.63], p=1.3e-11 |
| `defense[placebo]:model[deepseek/deepseek-v4-pro]` | 0.79 [0.65, 0.95], p=0.014 |
| `defense[tagged]:model[deepseek/deepseek-v4-pro]` | 0.50 [0.41, 0.60], p=1.3e-13 |
| `defense[warning]:model[deepseek/deepseek-v4-pro]` | 0.74 [0.63, 0.86], p=6.3e-05 |
| `defense[placebo]:model[google/gemini-3.8-flash]` | 1.00 [0.86, 1.16], p=1 |
| `defense[tagged]:model[google/gemini-3.8-flash]` | 1.21 [1.05, 1.38], p=0.0063 |
| `defense[warning]:model[google/gemini-3.8-flash]` | 1.08 [0.97, 1.20], p=0.16 |
| `defense[placebo]:model[openai/gpt-6.1-sol]` | 0.85 [0.74, 0.96], p=0.011 |
| `defense[tagged]:model[openai/gpt-6.1-sol]` | 0.85 [0.75, 0.95], p=0.0052 |
| `defense[warning]:model[openai/gpt-6.1-sol]` | 0.89 [0.81, 0.99], p=0.025 |
| `defense[placebo]:goal[induction]:model[deepseek/deepseek-v4-pro]` | 3.18 [2.32, 4.36], p=7e-13 |
| `defense[tagged]:goal[induction]:model[deepseek/deepseek-v4-pro]` | 0.60 [0.44, 0.82], p=0.0013 |
| `defense[warning]:goal[induction]:model[deepseek/deepseek-v4-pro]` | 0.49 [0.37, 0.64], p=3.6e-07 |
| `defense[placebo]:goal[induction]:model[google/gemini-3.8-flash]` | 1.89 [1.45, 2.46], p=2.5e-06 |
| `defense[tagged]:goal[induction]:model[google/gemini-3.8-flash]` | 0.59 [0.45, 0.77], p=8.7e-05 |
| `defense[warning]:goal[induction]:model[google/gemini-3.8-flash]` | 0.54 [0.43, 0.69], p=4.1e-07 |
| `defense[placebo]:goal[induction]:model[openai/gpt-6.1-sol]` | 2.27 [1.79, 2.88], p=2.1e-11 |
| `defense[tagged]:goal[induction]:model[openai/gpt-6.1-sol]` | 3.38 [2.60, 4.39], p=8.2e-20 |
| `defense[warning]:goal[induction]:model[openai/gpt-6.1-sol]` | 2.53 [2.00, 3.18], p=4.1e-15 |

## Per-model defense odds ratios (conditional_flip)

| Model | n | Pairs | Status | defense[placebo] | defense[tagged] | defense[warning] |
|---|---:|---:|---|---:|---:|---:|
| `anthropic/claude-sonnet-5.5` | 7528 | 174 | converged | 0.72 [0.60, 0.87], p=0.00052 | 0.48 [0.38, 0.60], p=1.9e-10 | 0.48 [0.40, 0.59], p=1.2e-13 |
| `deepseek/deepseek-v4-pro` | 5960 | 175 | converged | 1.21 [1.06, 1.38], p=0.0039 | 0.13 [0.10, 0.16], p=1.2e-57 | 0.20 [0.16, 0.25], p=3.9e-44 |
| `google/gemini-3.8-flash` | 7159 | 176 | converged | 0.80 [0.65, 0.99], p=0.037 | 0.25 [0.16, 0.40], p=2.1e-09 | 0.16 [0.10, 0.26], p=8.8e-14 |
| `openai/gpt-6.1-sol` | 7888 | 175 | converged | 0.90 [0.53, 1.53], p=0.7 | 1.21 [0.68, 2.15], p=0.52 | 1.11 [0.68, 1.82], p=0.67 |

## Pooled defense x goal x model (conditional_flip)

n=28535, pairs=176, status: converged, 0.3s.

| Term (joint Wald test) | chi2 | df | p |
|---|---:|---:|---:|
| `defense` | 5.79 | 3 | 0.12 |
| `goal` | 5.70 | 1 | 0.017 |
| `model` | 140.63 | 3 | 2.8e-30 |
| `style` | 326.44 | 4 | 2.1e-69 |
| `placement` | 3.55 | 1 | 0.059 |
| `defense:goal` | 30.98 | 3 | 8.6e-07 |
| `defense:model` | 25.40 | 9 | 0.0026 |
| `goal:model` | 58.78 | 3 | 1.1e-12 |
| `defense:goal:model` | 38.45 | 9 | 1.4e-05 |

| Term | Odds ratio [95% CI], p |
|---|---:|
| `defense[placebo]` | 0.98 [0.70, 1.38], p=0.91 |
| `defense[tagged]` | 0.75 [0.52, 1.08], p=0.13 |
| `defense[warning]` | 0.69 [0.49, 0.98], p=0.036 |
| `defense[placebo]:goal[induction]` | 0.47 [0.31, 0.72], p=0.00041 |
| `defense[tagged]:goal[induction]` | 0.24 [0.12, 0.46], p=2e-05 |
| `defense[warning]:goal[induction]` | 0.35 [0.22, 0.57], p=1.7e-05 |
| `defense[placebo]:model[deepseek/deepseek-v4-pro]` | 0.95 [0.62, 1.46], p=0.82 |
| `defense[tagged]:model[deepseek/deepseek-v4-pro]` | 0.45 [0.27, 0.77], p=0.0036 |
| `defense[warning]:model[deepseek/deepseek-v4-pro]` | 0.55 [0.32, 0.95], p=0.03 |
| `defense[placebo]:model[google/gemini-3.8-flash]` | 0.77 [0.41, 1.43], p=0.4 |
| `defense[tagged]:model[google/gemini-3.8-flash]` | 1.24 [0.67, 2.28], p=0.5 |
| `defense[warning]:model[google/gemini-3.8-flash]` | 0.96 [0.50, 1.87], p=0.91 |
| `defense[placebo]:model[openai/gpt-6.1-sol]` | 1.23 [0.43, 3.50], p=0.7 |
| `defense[tagged]:model[openai/gpt-6.1-sol]` | 1.71 [0.61, 4.77], p=0.31 |
| `defense[warning]:model[openai/gpt-6.1-sol]` | 1.62 [0.57, 4.60], p=0.36 |
| `defense[placebo]:goal[induction]:model[deepseek/deepseek-v4-pro]` | 2.92 [1.74, 4.90], p=5.1e-05 |
| `defense[tagged]:goal[induction]:model[deepseek/deepseek-v4-pro]` | 1.31 [0.60, 2.85], p=0.5 |
| `defense[warning]:goal[induction]:model[deepseek/deepseek-v4-pro]` | 1.31 [0.65, 2.63], p=0.46 |
| `defense[placebo]:goal[induction]:model[google/gemini-3.8-flash]` | 2.30 [1.17, 4.51], p=0.016 |
| `defense[tagged]:goal[induction]:model[google/gemini-3.8-flash]` | 0.62 [0.24, 1.61], p=0.33 |
| `defense[warning]:goal[induction]:model[google/gemini-3.8-flash]` | 0.41 [0.16, 1.06], p=0.066 |
| `defense[placebo]:goal[induction]:model[openai/gpt-6.1-sol]` | 1.09 [0.34, 3.51], p=0.88 |
| `defense[tagged]:goal[induction]:model[openai/gpt-6.1-sol]` | 4.55 [1.25, 16.57], p=0.022 |
| `defense[warning]:goal[induction]:model[openai/gpt-6.1-sol]` | 3.19 [0.91, 11.21], p=0.071 |
