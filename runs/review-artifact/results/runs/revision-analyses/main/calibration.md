# Confidence calibration on clean prompts

Runs: `runs/openrouter-v2/full` (prompt version v2); `runs/revision-placebo/full` (prompt version v3).
Adaptive runs: `runs/revision-adaptive/full`.
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Clean prompts only. Confidence is the model's stated confidence in its own verdict; accuracy is the share of correct verdicts. ECE = expected calibration error over the bins below; Brier = mean (confidence - correct)^2.

| Model | Defense | n | Accuracy | Mean confidence | ECE | Brier |
|---|---|---:|---:|---:|---:|---:|
| `anthropic/claude-sonnet-5.5` | neutral | 352 | 0.676 | 0.731 | 0.108 | 0.238 |
| `anthropic/claude-sonnet-5.5` | placebo | 352 | 0.696 | 0.781 | 0.144 | 0.233 |
| `anthropic/claude-sonnet-5.5` | stripped | 352 | 0.673 | 0.722 | 0.122 | 0.241 |
| `anthropic/claude-sonnet-5.5` | tagged | 351 | 0.650 | 0.739 | 0.118 | 0.246 |
| `anthropic/claude-sonnet-5.5` | warning | 352 | 0.653 | 0.739 | 0.135 | 0.250 |
| `deepseek/deepseek-v4-pro` | neutral | 352 | 0.543 | 0.917 | 0.375 | 0.389 |
| `deepseek/deepseek-v4-pro` | placebo | 352 | 0.526 | 0.926 | 0.400 | 0.412 |
| `deepseek/deepseek-v4-pro` | stripped | 352 | 0.531 | 0.918 | 0.387 | 0.400 |
| `deepseek/deepseek-v4-pro` | tagged | 352 | 0.534 | 0.912 | 0.380 | 0.395 |
| `deepseek/deepseek-v4-pro` | warning | 352 | 0.514 | 0.919 | 0.404 | 0.413 |
| `google/gemini-3.8-flash` | neutral | 347 | 0.654 | 0.907 | 0.255 | 0.291 |
| `google/gemini-3.8-flash` | placebo | 351 | 0.607 | 0.920 | 0.317 | 0.335 |
| `google/gemini-3.8-flash` | stripped | 348 | 0.670 | 0.905 | 0.243 | 0.283 |
| `google/gemini-3.8-flash` | tagged | 349 | 0.648 | 0.912 | 0.267 | 0.299 |
| `google/gemini-3.8-flash` | warning | 350 | 0.654 | 0.917 | 0.264 | 0.296 |
| `openai/gpt-6.1-sol` | neutral | 352 | 0.696 | 0.889 | 0.202 | 0.258 |
| `openai/gpt-6.1-sol` | placebo | 352 | 0.716 | 0.906 | 0.202 | 0.248 |
| `openai/gpt-6.1-sol` | stripped | 352 | 0.707 | 0.884 | 0.201 | 0.255 |
| `openai/gpt-6.1-sol` | tagged | 352 | 0.699 | 0.883 | 0.194 | 0.253 |
| `openai/gpt-6.1-sol` | warning | 352 | 0.690 | 0.886 | 0.212 | 0.266 |

## Reliability bins (n: accuracy at mean confidence)

| Model | Defense | [0.0, 0.5) | [0.5, 0.6) | [0.6, 0.7) | [0.7, 0.8) | [0.8, 0.9) | [0.9, 1.0] |
|---|---|---:|---:|---:|---:|---:|---:|
| `anthropic/claude-sonnet-5.5` | neutral | 11: 1.00 @ 0.36 | 20: 0.60 @ 0.54 | 95: 0.61 @ 0.60 | 42: 0.64 @ 0.70 | 132: 0.70 @ 0.82 | 52: 0.71 @ 0.92 |
| `anthropic/claude-sonnet-5.5` | placebo | 3: 1.00 @ 0.38 | 23: 0.78 @ 0.53 | 43: 0.67 @ 0.62 | 47: 0.51 @ 0.71 | 157: 0.74 @ 0.82 | 79: 0.70 @ 0.92 |
| `anthropic/claude-sonnet-5.5` | stripped | 14: 0.79 @ 0.36 | 19: 0.68 @ 0.54 | 104: 0.59 @ 0.60 | 34: 0.82 @ 0.70 | 130: 0.70 @ 0.81 | 51: 0.65 @ 0.91 |
| `anthropic/claude-sonnet-5.5` | tagged | 5: 1.00 @ 0.36 | 23: 0.61 @ 0.53 | 92: 0.55 @ 0.60 | 35: 0.60 @ 0.70 | 144: 0.72 @ 0.82 | 52: 0.63 @ 0.92 |
| `anthropic/claude-sonnet-5.5` | warning | 12: 0.92 @ 0.38 | 24: 0.58 @ 0.53 | 78: 0.54 @ 0.60 | 30: 0.73 @ 0.70 | 149: 0.69 @ 0.81 | 59: 0.64 @ 0.91 |
| `deepseek/deepseek-v4-pro` | neutral | 0 | 0 | 0 | 0 | 4: 0.75 @ 0.80 | 348: 0.54 @ 0.92 |
| `deepseek/deepseek-v4-pro` | placebo | 0 | 0 | 0 | 0 | 11: 0.64 @ 0.83 | 341: 0.52 @ 0.93 |
| `deepseek/deepseek-v4-pro` | stripped | 0 | 0 | 0 | 0 | 5: 0.80 @ 0.80 | 347: 0.53 @ 0.92 |
| `deepseek/deepseek-v4-pro` | tagged | 0 | 0 | 0 | 1: 1.00 @ 0.70 | 4: 0.75 @ 0.81 | 347: 0.53 @ 0.91 |
| `deepseek/deepseek-v4-pro` | warning | 0 | 0 | 0 | 0 | 5: 0.20 @ 0.82 | 347: 0.52 @ 0.92 |
| `google/gemini-3.8-flash` | neutral | 0 | 0 | 0 | 8: 0.75 @ 0.71 | 117: 0.62 @ 0.84 | 222: 0.67 @ 0.95 |
| `google/gemini-3.8-flash` | placebo | 0 | 0 | 0 | 2: 1.00 @ 0.70 | 96: 0.53 @ 0.84 | 253: 0.63 @ 0.95 |
| `google/gemini-3.8-flash` | stripped | 0 | 2: 1.00 @ 0.50 | 0 | 8: 0.75 @ 0.71 | 118: 0.66 @ 0.84 | 220: 0.67 @ 0.95 |
| `google/gemini-3.8-flash` | tagged | 0 | 1: 1.00 @ 0.50 | 0 | 5: 0.40 @ 0.70 | 108: 0.64 @ 0.84 | 235: 0.66 @ 0.95 |
| `google/gemini-3.8-flash` | warning | 0 | 0 | 0 | 4: 0.75 @ 0.70 | 100: 0.60 @ 0.85 | 246: 0.67 @ 0.95 |
| `openai/gpt-6.1-sol` | neutral | 0 | 12: 0.58 @ 0.54 | 17: 0.71 @ 0.64 | 26: 0.62 @ 0.76 | 89: 0.70 @ 0.85 | 208: 0.71 @ 0.96 |
| `openai/gpt-6.1-sol` | placebo | 0 | 11: 0.73 @ 0.56 | 3: 0.67 @ 0.62 | 27: 0.59 @ 0.76 | 85: 0.74 @ 0.86 | 226: 0.72 @ 0.96 |
| `openai/gpt-6.1-sol` | stripped | 0 | 16: 0.69 @ 0.54 | 16: 0.75 @ 0.63 | 29: 0.69 @ 0.75 | 89: 0.74 @ 0.86 | 202: 0.69 @ 0.96 |
| `openai/gpt-6.1-sol` | tagged | 1: 1.00 @ 0.10 | 13: 0.62 @ 0.54 | 19: 0.47 @ 0.65 | 31: 0.68 @ 0.76 | 87: 0.72 @ 0.85 | 201: 0.72 @ 0.96 |
| `openai/gpt-6.1-sol` | warning | 0 | 13: 0.69 @ 0.53 | 16: 0.69 @ 0.64 | 25: 0.76 @ 0.76 | 105: 0.70 @ 0.86 | 193: 0.68 @ 0.96 |
