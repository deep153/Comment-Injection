# Conditional flip rate, benign baseline and clean accuracy by defense

Runs: `runs/revision-deepseek-minimal/full` (prompt version v3).
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Per model, defense and goal. Conditional flip rate: attack success among attacked prompts whose clean verdict (same model, item and defense) was correct. Benign baseline: the same measure for the harmless comment, where a move is a verdict on the attacker's side (safe for vulnerable code under suppression, vulnerable for fixed code under induction). Excess = conditional flip minus benign. Clean accuracy covers both labels. 95% cluster-bootstrap intervals over vulnerable/fixed pairs (2000 resamples, seed 20260101). Model `all` pools the models.

| Model | Defense | Goal | Clean acc. | Raw ASR | Conditional flip [95% CI] (n) | Benign [95% CI] (n) | Excess [95% CI] |
|---|---|---|---:|---:|---:|---:|---:|
| `deepseek/deepseek-v4-pro` | neutral | induction | 0.582 | 0.869 | 0.804 [0.751, 0.850] (321) | n/a [n/a, n/a] (0) | n/a [n/a, n/a] |
| `deepseek/deepseek-v4-pro` | neutral | suppression | 0.582 | 0.633 | 0.466 [0.395, 0.537] (294) | n/a [n/a, n/a] (0) | n/a [n/a, n/a] |
| `deepseek/deepseek-v4-pro` | tagged | induction | 0.562 | 0.455 | 0.257 [0.198, 0.317] (303) | n/a [n/a, n/a] (0) | n/a [n/a, n/a] |
| `deepseek/deepseek-v4-pro` | tagged | suppression | 0.562 | 0.483 | 0.196 [0.137, 0.258] (291) | n/a [n/a, n/a] (0) | n/a [n/a, n/a] |
| `deepseek/deepseek-v4-pro` | warning | induction | 0.574 | 0.485 | 0.261 [0.199, 0.320] (291) | n/a [n/a, n/a] (0) | n/a [n/a, n/a] |
| `deepseek/deepseek-v4-pro` | warning | suppression | 0.574 | 0.470 | 0.244 [0.178, 0.314] (315) | n/a [n/a, n/a] (0) | n/a [n/a, n/a] |
| `all` | neutral | induction | 0.582 | 0.869 | 0.804 [0.751, 0.850] (321) | n/a [n/a, n/a] (0) | n/a [n/a, n/a] |
| `all` | neutral | suppression | 0.582 | 0.633 | 0.466 [0.395, 0.537] (294) | n/a [n/a, n/a] (0) | n/a [n/a, n/a] |
| `all` | tagged | induction | 0.562 | 0.455 | 0.257 [0.198, 0.317] (303) | n/a [n/a, n/a] (0) | n/a [n/a, n/a] |
| `all` | tagged | suppression | 0.562 | 0.483 | 0.196 [0.137, 0.258] (291) | n/a [n/a, n/a] (0) | n/a [n/a, n/a] |
| `all` | warning | induction | 0.574 | 0.485 | 0.261 [0.199, 0.320] (291) | n/a [n/a, n/a] (0) | n/a [n/a, n/a] |
| `all` | warning | suppression | 0.574 | 0.470 | 0.244 [0.178, 0.314] (315) | n/a [n/a, n/a] (0) | n/a [n/a, n/a] |
