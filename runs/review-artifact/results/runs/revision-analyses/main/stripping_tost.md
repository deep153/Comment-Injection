# Equivalence of stripped and neutral clean accuracy (TOST)

Runs: `runs/openrouter-v2/full` (prompt version v2); `runs/revision-placebo/full` (prompt version v3).
Adaptive runs: `runs/revision-adaptive/full`.
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Stripped minus neutral clean accuracy, paired by model and item. TOST with margin +/-0.05: two one-sided z-tests at alpha 0.05 with a cluster-robust standard error over vulnerable/fixed pairs; equivalence is declared when the 90% interval lies inside the margin. The pooled row combines models.

| Model | Items | Pairs | Neutral acc. | Stripped acc. | Difference | 90% CI | p (TOST) | Equivalent |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `anthropic/claude-sonnet-5.5` | 352 | 176 | 0.676 | 0.673 | -0.003 | [-0.027, 0.022] | 0.000721 | yes |
| `deepseek/deepseek-v4-pro` | 352 | 176 | 0.543 | 0.531 | -0.011 | [-0.037, 0.014] | 0.00657 | yes |
| `google/gemini-3.8-flash` | 352 | 176 | 0.645 | 0.662 | 0.017 | [-0.016, 0.050] | 0.0506 | no |
| `openai/gpt-6.1-sol` | 352 | 176 | 0.696 | 0.707 | 0.011 | [-0.014, 0.037] | 0.00657 | yes |
| `all` | 1408 | 176 | 0.640 | 0.643 | 0.004 | [-0.011, 0.018] | 8.01e-08 | yes |
