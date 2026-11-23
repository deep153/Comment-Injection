# Provider drift between the main runs and the re-anchor

Runs: `runs/openrouter-v2/full` (prompt version v2); `runs/revision-placebo/full` (prompt version v3).
Adaptive runs: `runs/revision-adaptive/full`.
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Re-anchor run: `runs/revision-neutral-reanchor/full` (prompt version v3). Each re-anchor row is matched to the main-run row with the same model, item, defense and condition; unmatched rows are ignored. Accuracy counts an unparseable verdict as wrong. Agreement and score change use only pairs where both verdicts parse; score change is re-anchor minus main-run vulnerability score. Accuracy and score changes carry 95% cluster-bootstrap intervals over pairs (2000 resamples, seed 20260101).

| Model | Defense | Condition | Matched | Accuracy (main) | Accuracy (re-anchor) | Accuracy change [95% CI] | Verdict agreement | Score change [95% CI] |
|---|---|---|---:|---:|---:|---:|---:|---:|
| `anthropic/claude-sonnet-5.5` | neutral | clean | 352 | 0.676 | 0.682 | 0.006 [-0.017, 0.028] | 0.955 (336/352) | 0.004 [-0.005, 0.013] |
| `deepseek/deepseek-v4-pro` | neutral | clean | 352 | 0.543 | 0.543 | 0.000 [-0.028, 0.026] | 0.920 (324/352) | -0.006 [-0.029, 0.020] |
| `google/gemini-3.8-flash` | neutral | clean | 352 | 0.645 | 0.625 | -0.020 [-0.057, 0.014] | 0.888 (308/347) | 0.004 [-0.025, 0.033] |
| `openai/gpt-6.1-sol` | neutral | clean | 352 | 0.696 | 0.707 | 0.011 [-0.017, 0.040] | 0.938 (330/352) | 0.011 [-0.005, 0.027] |
