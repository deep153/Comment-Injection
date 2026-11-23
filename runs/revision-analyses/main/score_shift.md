# Within-defense confidence-score shift toward the attacker's target

Runs: `runs/openrouter-v2/full` (prompt version v2); `runs/revision-placebo/full` (prompt version v3).
Adaptive runs: `runs/revision-adaptive/full`.
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Shift = attacked minus clean vulnerability score (same item, model, defense), signed so that positive values move toward the attacker's target (safe for suppression, vulnerable for induction). 95% cluster-bootstrap intervals over pairs (2000 resamples, seed 20260101).

| Model | Goal | Defense | n | Pairs | Mean shift | 95% CI |
|---|---|---|---:|---:|---:|---:|
| `anthropic/claude-sonnet-5.5` | induction | neutral | 1406 | 176 | 0.006 | [-0.018, 0.029] |
| `anthropic/claude-sonnet-5.5` | induction | placebo | 1406 | 176 | 0.027 | [0.008, 0.045] |
| `anthropic/claude-sonnet-5.5` | induction | tagged | 1400 | 175 | -0.028 | [-0.048, -0.008] |
| `anthropic/claude-sonnet-5.5` | induction | warning | 1405 | 176 | -0.020 | [-0.040, -0.001] |
| `anthropic/claude-sonnet-5.5` | suppression | neutral | 1407 | 176 | 0.080 | [0.061, 0.099] |
| `anthropic/claude-sonnet-5.5` | suppression | placebo | 1407 | 176 | 0.057 | [0.038, 0.076] |
| `anthropic/claude-sonnet-5.5` | suppression | tagged | 1407 | 176 | 0.024 | [0.005, 0.042] |
| `anthropic/claude-sonnet-5.5` | suppression | warning | 1407 | 176 | 0.042 | [0.025, 0.059] |
| `deepseek/deepseek-v4-pro` | induction | neutral | 1408 | 176 | 0.549 | [0.502, 0.597] |
| `deepseek/deepseek-v4-pro` | induction | placebo | 1408 | 176 | 0.549 | [0.497, 0.598] |
| `deepseek/deepseek-v4-pro` | induction | tagged | 1408 | 176 | 0.199 | [0.164, 0.234] |
| `deepseek/deepseek-v4-pro` | induction | warning | 1408 | 176 | 0.309 | [0.268, 0.350] |
| `deepseek/deepseek-v4-pro` | suppression | neutral | 1408 | 176 | 0.144 | [0.107, 0.181] |
| `deepseek/deepseek-v4-pro` | suppression | placebo | 1408 | 176 | 0.136 | [0.097, 0.175] |
| `deepseek/deepseek-v4-pro` | suppression | tagged | 1408 | 176 | 0.024 | [-0.009, 0.061] |
| `deepseek/deepseek-v4-pro` | suppression | warning | 1408 | 176 | 0.016 | [-0.014, 0.049] |
| `google/gemini-3.8-flash` | induction | neutral | 1386 | 174 | 0.071 | [0.033, 0.106] |
| `google/gemini-3.8-flash` | induction | placebo | 1403 | 176 | 0.053 | [0.015, 0.091] |
| `google/gemini-3.8-flash` | induction | tagged | 1389 | 175 | -0.092 | [-0.132, -0.053] |
| `google/gemini-3.8-flash` | induction | warning | 1386 | 174 | -0.067 | [-0.100, -0.035] |
| `google/gemini-3.8-flash` | suppression | neutral | 1375 | 173 | -0.041 | [-0.078, -0.004] |
| `google/gemini-3.8-flash` | suppression | placebo | 1397 | 175 | -0.075 | [-0.112, -0.040] |
| `google/gemini-3.8-flash` | suppression | tagged | 1378 | 174 | -0.015 | [-0.044, 0.012] |
| `google/gemini-3.8-flash` | suppression | warning | 1389 | 176 | -0.063 | [-0.096, -0.031] |
| `openai/gpt-6.1-sol` | induction | neutral | 1408 | 176 | -0.061 | [-0.084, -0.039] |
| `openai/gpt-6.1-sol` | induction | placebo | 1408 | 176 | -0.053 | [-0.074, -0.034] |
| `openai/gpt-6.1-sol` | induction | tagged | 1408 | 176 | -0.051 | [-0.074, -0.031] |
| `openai/gpt-6.1-sol` | induction | warning | 1408 | 176 | -0.072 | [-0.099, -0.048] |
| `openai/gpt-6.1-sol` | suppression | neutral | 1408 | 176 | -0.014 | [-0.030, 0.001] |
| `openai/gpt-6.1-sol` | suppression | placebo | 1408 | 176 | -0.006 | [-0.021, 0.008] |
| `openai/gpt-6.1-sol` | suppression | tagged | 1408 | 176 | -0.005 | [-0.021, 0.013] |
| `openai/gpt-6.1-sol` | suppression | warning | 1408 | 176 | -0.012 | [-0.028, 0.004] |
