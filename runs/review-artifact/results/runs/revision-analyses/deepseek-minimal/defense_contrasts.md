# Paired defense contrasts on conditional flip rate and attack success

Runs: `runs/revision-deepseek-minimal/full` (prompt version v3).
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Paired defense contrasts. Attacked prompts are matched on model, item and attack family across the two defenses; the difference is defense minus baseline. `conditional_flip` keeps matched prompts whose clean verdict (same model, item and defense) was correct under both defenses and compares attack success, the conditional flip rate; `attack_success` keeps every matched prompt (raw ASR). Intervals: 95% cluster bootstrap over vulnerable/fixed pairs (2000 resamples, seed 20260101). Exact McNemar on discordant prompts; Holm adjustment over the per-model tests of each metric (pooled rows are not adjusted).

| Metric | Model | Goal | Contrast | Pairs | Clusters | Baseline | Defense | Difference | 95% CI | Discordant (b/d) | p | p (Holm) |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| conditional_flip | `all` | induction | warning - neutral | 246 | 82 | 0.764 | 0.215 | -0.549 | [-0.610, -0.484] | 137/2 | 2.79e-38 | n/a |
| conditional_flip | `all` | suppression | warning - neutral | 225 | 75 | 0.342 | 0.116 | -0.227 | [-0.289, -0.164] | 62/11 | 9.09e-10 | n/a |
| conditional_flip | `deepseek/deepseek-v4-pro` | induction | warning - neutral | 246 | 82 | 0.764 | 0.215 | -0.549 | [-0.610, -0.484] | 137/2 | 2.79e-38 | 1.12e-37 |
| conditional_flip | `deepseek/deepseek-v4-pro` | suppression | warning - neutral | 225 | 75 | 0.342 | 0.116 | -0.227 | [-0.289, -0.164] | 62/11 | 9.09e-10 | 1.82e-09 |
| conditional_flip | `all` | induction | tagged - neutral | 240 | 80 | 0.750 | 0.192 | -0.558 | [-0.633, -0.487] | 140/6 | 2.84e-34 | n/a |
| conditional_flip | `all` | suppression | tagged - neutral | 234 | 78 | 0.359 | 0.141 | -0.218 | [-0.286, -0.154] | 65/14 | 5.19e-09 | n/a |
| conditional_flip | `deepseek/deepseek-v4-pro` | induction | tagged - neutral | 240 | 80 | 0.750 | 0.192 | -0.558 | [-0.633, -0.487] | 140/6 | 2.84e-34 | 8.51e-34 |
| conditional_flip | `deepseek/deepseek-v4-pro` | suppression | tagged - neutral | 234 | 78 | 0.359 | 0.141 | -0.218 | [-0.286, -0.154] | 65/14 | 5.19e-09 | 5.19e-09 |
| attack_success | `all` | induction | warning - neutral | 528 | 176 | 0.869 | 0.485 | -0.384 | [-0.434, -0.337] | 209/6 | 5e-54 | n/a |
| attack_success | `all` | suppression | warning - neutral | 528 | 176 | 0.633 | 0.470 | -0.163 | [-0.205, -0.119] | 113/27 | 1.04e-13 | n/a |
| attack_success | `deepseek/deepseek-v4-pro` | induction | warning - neutral | 528 | 176 | 0.869 | 0.485 | -0.384 | [-0.434, -0.337] | 209/6 | 5e-54 | 1.5e-53 |
| attack_success | `deepseek/deepseek-v4-pro` | suppression | warning - neutral | 528 | 176 | 0.633 | 0.470 | -0.163 | [-0.205, -0.119] | 113/27 | 1.04e-13 | 2.07e-13 |
| attack_success | `all` | induction | tagged - neutral | 528 | 176 | 0.869 | 0.455 | -0.415 | [-0.464, -0.362] | 230/11 | 1.88e-54 | n/a |
| attack_success | `all` | suppression | tagged - neutral | 528 | 176 | 0.633 | 0.483 | -0.150 | [-0.195, -0.106] | 114/35 | 5.8e-11 | n/a |
| attack_success | `deepseek/deepseek-v4-pro` | induction | tagged - neutral | 528 | 176 | 0.869 | 0.455 | -0.415 | [-0.464, -0.362] | 230/11 | 1.88e-54 | 7.52e-54 |
| attack_success | `deepseek/deepseek-v4-pro` | suppression | tagged - neutral | 528 | 176 | 0.633 | 0.483 | -0.150 | [-0.195, -0.106] | 114/35 | 5.8e-11 | 5.8e-11 |

Skipped: placebo - neutral (no attacked rows for placebo); warning - placebo (no attacked rows for placebo); tagged - placebo (no attacked rows for placebo).
