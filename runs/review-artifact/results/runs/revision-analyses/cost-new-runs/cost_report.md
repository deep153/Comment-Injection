# Cost per run from recorded usage

Runs: `runs/revision-placebo/full` (prompt version v3); `runs/revision-neutral-reanchor/full` (prompt version v3); `runs/revision-deepseek-minimal/full` (prompt version v3).
Replaced by a later run (--allow-replace): 352 rows of `runs/revision-neutral-reanchor/full`.
Adaptive runs: `runs/revision-adaptive/full`.
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Every recorded response row counts, including failed attempts and retries, since each was billed. OpenRouter USD is the `cost` OpenRouter charged; BYOK upstream USD is `cost_details.upstream_inference_cost` on bring-your-own-key routes, billed to the user's own provider key rather than to OpenRouter credits.

| Run | Log | Role | Model | Rows | Failed | BYOK rows | OpenRouter USD | BYOK upstream USD | Total USD |
|---|---|---|---|---:|---:|---:|---:|---:|---:|
| `runs/revision-placebo/full` | responses.jsonl | detector | anthropic/claude-sonnet-5.5 | 3540 | 20 | 3540 | 0.0000 | 22.5201 | 22.5201 |
| `runs/revision-placebo/full` | responses.jsonl | detector | deepseek/deepseek-v4-pro | 3520 | 0 | 0 | 1.5106 | 0.0000 | 1.5106 |
| `runs/revision-placebo/full` | responses.jsonl | detector | google/gemini-3.8-flash | 3839 | 209 | 3628 | 0.2719 | 14.3621 | 14.6340 |
| `runs/revision-placebo/full` | responses.jsonl | detector | openai/gpt-6.1-sol | 3520 | 0 | 0 | 4.3400 | 0.0000 | 4.3400 |
| `runs/revision-placebo/full` | responses.jsonl |  | **all** | 14419 | 229 | 7168 | 6.1226 | 36.8822 | 43.0048 |
| `runs/revision-neutral-reanchor/full` | responses.jsonl | detector | anthropic/claude-sonnet-5.5 | 354 | 2 | 354 | 0.0000 | 1.4244 | 1.4244 |
| `runs/revision-neutral-reanchor/full` | responses.jsonl | detector | deepseek/deepseek-v4-pro | 352 | 0 | 0 | 0.1301 | 0.0000 | 0.1301 |
| `runs/revision-neutral-reanchor/full` | responses.jsonl | detector | google/gemini-3.8-flash | 389 | 29 | 360 | 0.0183 | 1.7219 | 1.7402 |
| `runs/revision-neutral-reanchor/full` | responses.jsonl | detector | openai/gpt-6.1-sol | 352 | 0 | 0 | 0.3698 | 0.0000 | 0.3698 |
| `runs/revision-neutral-reanchor/full` | responses.jsonl |  | **all** | 1447 | 31 | 714 | 0.5182 | 3.1464 | 3.6646 |
| `runs/revision-deepseek-minimal/full` | responses.jsonl | detector | deepseek/deepseek-v4-pro | 4288 | 62 | 0 | 10.8739 | 0.0000 | 10.8739 |
| `runs/revision-deepseek-minimal/full` | responses.jsonl |  | **all** | 4288 | 62 | 0 | 10.8739 | 0.0000 | 10.8739 |
| `runs/revision-adaptive/full` | steps.jsonl | attacker | openai/gpt-6.1-sol | 2320 | 4 | 0 | 3.3215 | 0.0000 | 3.3215 |
| `runs/revision-adaptive/full` | steps.jsonl | detector | anthropic/claude-sonnet-5.5 | 562 | 1 | 561 | 0.0000 | 2.3046 | 2.3046 |
| `runs/revision-adaptive/full` | steps.jsonl | detector | deepseek/deepseek-v4-pro | 206 | 0 | 0 | 0.0957 | 0.0000 | 0.0957 |
| `runs/revision-adaptive/full` | steps.jsonl | detector | google/gemini-3.8-flash | 795 | 82 | 743 | 0.0058 | 3.0709 | 3.0767 |
| `runs/revision-adaptive/full` | steps.jsonl | detector | openai/gpt-6.1-sol | 835 | 1 | 0 | 0.9600 | 0.0000 | 0.9600 |
| `runs/revision-adaptive/full` | steps.jsonl |  | **all** | 4718 | 88 | 1304 | 4.3830 | 5.3755 | 9.7585 |

Total over all runs: at least 67.3018 USD (21.8977 OpenRouter, 45.4041 BYOK upstream).

Lower bounds: these runs were made before the runner logged failed attempts that it then retried, so billed attempts that ended in a retry are missing from their totals: `runs/revision-placebo/full`, `runs/revision-neutral-reanchor/full`, `runs/revision-deepseek-minimal/full`.
