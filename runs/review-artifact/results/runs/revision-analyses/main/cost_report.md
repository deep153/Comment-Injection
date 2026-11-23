# Cost per run from recorded usage

Runs: `runs/openrouter-v2/full` (prompt version v2); `runs/revision-placebo/full` (prompt version v3).
Adaptive runs: `runs/revision-adaptive/full`.
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Every recorded response row counts, including failed attempts and retries, since each was billed. OpenRouter USD is the `cost` OpenRouter charged; BYOK upstream USD is `cost_details.upstream_inference_cost` on bring-your-own-key routes, billed to the user's own provider key rather than to OpenRouter credits.

| Run | Log | Role | Model | Rows | Failed | BYOK rows | OpenRouter USD | BYOK upstream USD | Total USD |
|---|---|---|---|---:|---:|---:|---:|---:|---:|
| `runs/openrouter-v2/full` | responses.jsonl | detector | anthropic/claude-sonnet-5.5 | 17184 | 0 | 17184 | 0.0000 | 78.8581 | 78.8581 |
| `runs/openrouter-v2/full` | responses.jsonl | detector | deepseek/deepseek-v4-pro | 17189 | 0 | 0 | 4.0667 | 0.0000 | 4.0667 |
| `runs/openrouter-v2/full` | responses.jsonl | detector | google/gemini-3.8-flash | 18783 | 1092 | 17813 | 0.4968 | 91.3330 | 91.8298 |
| `runs/openrouter-v2/full` | responses.jsonl | detector | openai/gpt-6.1-sol | 17184 | 0 | 0 | 21.8003 | 0.0000 | 21.8003 |
| `runs/openrouter-v2/full` | responses.jsonl |  | **all** | 70340 | 1092 | 34997 | 26.3639 | 170.1911 | 196.5549 |
| `runs/revision-placebo/full` | responses.jsonl | detector | anthropic/claude-sonnet-5.5 | 3540 | 20 | 3540 | 0.0000 | 22.5201 | 22.5201 |
| `runs/revision-placebo/full` | responses.jsonl | detector | deepseek/deepseek-v4-pro | 3520 | 0 | 0 | 1.5106 | 0.0000 | 1.5106 |
| `runs/revision-placebo/full` | responses.jsonl | detector | google/gemini-3.8-flash | 3839 | 209 | 3628 | 0.2719 | 14.3621 | 14.6340 |
| `runs/revision-placebo/full` | responses.jsonl | detector | openai/gpt-6.1-sol | 3520 | 0 | 0 | 4.3400 | 0.0000 | 4.3400 |
| `runs/revision-placebo/full` | responses.jsonl |  | **all** | 14419 | 229 | 7168 | 6.1226 | 36.8822 | 43.0048 |
| `runs/revision-adaptive/full` | steps.jsonl | attacker | openai/gpt-6.1-sol | 2320 | 4 | 0 | 3.3215 | 0.0000 | 3.3215 |
| `runs/revision-adaptive/full` | steps.jsonl | detector | anthropic/claude-sonnet-5.5 | 562 | 1 | 561 | 0.0000 | 2.3046 | 2.3046 |
| `runs/revision-adaptive/full` | steps.jsonl | detector | deepseek/deepseek-v4-pro | 206 | 0 | 0 | 0.0957 | 0.0000 | 0.0957 |
| `runs/revision-adaptive/full` | steps.jsonl | detector | google/gemini-3.8-flash | 795 | 82 | 743 | 0.0058 | 3.0709 | 3.0767 |
| `runs/revision-adaptive/full` | steps.jsonl | detector | openai/gpt-6.1-sol | 835 | 1 | 0 | 0.9600 | 0.0000 | 0.9600 |
| `runs/revision-adaptive/full` | steps.jsonl |  | **all** | 4718 | 88 | 1304 | 4.3830 | 5.3755 | 9.7585 |

Total over all runs: at least 249.3183 USD (36.8694 OpenRouter, 212.4488 BYOK upstream).

Lower bounds: these runs were made before the runner logged failed attempts that it then retried, so billed attempts that ended in a retry are missing from their totals: `runs/openrouter-v2/full`, `runs/revision-placebo/full`.
