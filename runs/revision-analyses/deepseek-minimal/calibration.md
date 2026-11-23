# Confidence calibration on clean prompts

Runs: `runs/revision-deepseek-minimal/full` (prompt version v3).
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Clean prompts only. Confidence is the model's stated confidence in its own verdict; accuracy is the share of correct verdicts. ECE = expected calibration error over the bins below; Brier = mean (confidence - correct)^2.

| Model | Defense | n | Accuracy | Mean confidence | ECE | Brier |
|---|---|---:|---:|---:|---:|---:|
| `deepseek/deepseek-v4-pro` | neutral | 352 | 0.582 | 0.897 | 0.341 | 0.362 |
| `deepseek/deepseek-v4-pro` | tagged | 352 | 0.562 | 0.894 | 0.337 | 0.359 |
| `deepseek/deepseek-v4-pro` | warning | 352 | 0.574 | 0.901 | 0.337 | 0.350 |

## Reliability bins (n: accuracy at mean confidence)

| Model | Defense | [0.0, 0.5) | [0.5, 0.6) | [0.6, 0.7) | [0.7, 0.8) | [0.8, 0.9) | [0.9, 1.0] |
|---|---|---:|---:|---:|---:|---:|---:|
| `deepseek/deepseek-v4-pro` | neutral | 4: 1.00 @ 0.05 | 1: 0.00 @ 0.50 | 2: 1.00 @ 0.60 | 14: 0.43 @ 0.70 | 40: 0.60 @ 0.81 | 291: 0.58 @ 0.93 |
| `deepseek/deepseek-v4-pro` | tagged | 6: 0.33 @ 0.17 | 3: 0.33 @ 0.50 | 0 | 16: 0.44 @ 0.70 | 35: 0.57 @ 0.81 | 292: 0.58 @ 0.93 |
| `deepseek/deepseek-v4-pro` | warning | 1: 1.00 @ 0.00 | 3: 0.67 @ 0.50 | 1: 1.00 @ 0.60 | 20: 0.10 @ 0.70 | 46: 0.50 @ 0.81 | 281: 0.62 @ 0.94 |
