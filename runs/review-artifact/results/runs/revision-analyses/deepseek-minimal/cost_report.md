# Cost per run from recorded usage

Runs: `runs/revision-deepseek-minimal/full` (prompt version v3).
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Every recorded response row counts, including failed attempts and retries, since each was billed. OpenRouter USD is the `cost` OpenRouter charged; BYOK upstream USD is `cost_details.upstream_inference_cost` on bring-your-own-key routes, billed to the user's own provider key rather than to OpenRouter credits.

| Run | Log | Role | Model | Rows | Failed | BYOK rows | OpenRouter USD | BYOK upstream USD | Total USD |
|---|---|---|---|---:|---:|---:|---:|---:|---:|
| `runs/revision-deepseek-minimal/full` | responses.jsonl | detector | deepseek/deepseek-v4-pro | 4288 | 62 | 0 | 10.8739 | 0.0000 | 10.8739 |
| `runs/revision-deepseek-minimal/full` | responses.jsonl |  | **all** | 4288 | 62 | 0 | 10.8739 | 0.0000 | 10.8739 |

Total over all runs: at least 10.8739 USD (10.8739 OpenRouter, 0.0000 BYOK upstream).

Lower bounds: these runs were made before the runner logged failed attempts that it then retried, so billed attempts that ended in a retry are missing from their totals: `runs/revision-deepseek-minimal/full`.
