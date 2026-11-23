# Within-defense confidence-score shift toward the attacker's target

Runs: `runs/revision-deepseek-minimal/full` (prompt version v3).
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Shift = attacked minus clean vulnerability score (same item, model, defense), signed so that positive values move toward the attacker's target (safe for suppression, vulnerable for induction). 95% cluster-bootstrap intervals over pairs (2000 resamples, seed 20260101).

| Model | Goal | Defense | n | Pairs | Mean shift | 95% CI |
|---|---|---|---:|---:|---:|---:|
| `deepseek/deepseek-v4-pro` | induction | neutral | 528 | 176 | 0.414 | [0.358, 0.472] |
| `deepseek/deepseek-v4-pro` | induction | tagged | 528 | 176 | 0.061 | [0.010, 0.109] |
| `deepseek/deepseek-v4-pro` | induction | warning | 528 | 176 | 0.058 | [0.016, 0.102] |
| `deepseek/deepseek-v4-pro` | suppression | neutral | 528 | 176 | 0.159 | [0.105, 0.215] |
| `deepseek/deepseek-v4-pro` | suppression | tagged | 528 | 176 | 0.036 | [-0.005, 0.078] |
| `deepseek/deepseek-v4-pro` | suppression | warning | 528 | 176 | 0.058 | [0.012, 0.106] |
