# OpenRouter Evaluation Summary

## Corpus

- `halurust`: 114 items
- `manual`: 352 items
- `negative_easy`: 25 items
- `negative_hard`: 159 items
- `rustmizan`: 151 items
- Total manifest items: 801
- Total model requests: 38448

## Completion And Parsing

- Completed responses: 38448 / 38,448
- Unparseable verdicts: 877 (2.3%)
- `anthropic/claude-sonnet-5.5`: 9612 responses, 311 unparseable (3.2%)
- `openai/gpt-6-sol`: 9612 responses, 0 unparseable (0.0%)
- `google/gemini-3.8-flash`: 9612 responses, 563 unparseable (5.9%)
- `deepseek/deepseek-v4-pro`: 9612 responses, 3 unparseable (0.0%)

## Clean Neutral Accuracy

| Model | All families | Manual primary |
|---|---:|---:|
| `anthropic/claude-sonnet-5.5` | 91.9% (736/801) | 98.9% (348/352) |
| `openai/gpt-6-sol` | 86.8% (695/801) | 92.9% (327/352) |
| `google/gemini-3.8-flash` | 86.9% (696/801) | 92.0% (324/352) |
| `deepseek/deepseek-v4-pro` | 86.8% (695/801) | 97.2% (342/352) |

## Manual Comment-Injection ASR By Defense

| Model | Neutral | Warning | Tagged |
|---|---:|---:|---:|
| `anthropic/claude-sonnet-5.5` | 0.9% (10/1056) | 1.6% (17/1056) | 0.6% (6/1056) |
| `openai/gpt-6-sol` | 7.1% (75/1056) | 9.0% (95/1056) | 8.0% (85/1056) |
| `google/gemini-3.8-flash` | 4.1% (43/1056) | 2.8% (30/1056) | 0.9% (9/1056) |
| `deepseek/deepseek-v4-pro` | 23.1% (244/1056) | 15.7% (166/1056) | 11.7% (124/1056) |

## Manual Clean Pairwise Accuracy

| Model | Neutral | Warning | Tagged |
|---|---:|---:|---:|
| `anthropic/claude-sonnet-5.5` | 100.0% (173/173) | 100.0% (171/171) | 100.0% (150/150) |
| `openai/gpt-6-sol` | 94.3% (166/176) | 91.5% (161/176) | 89.8% (158/176) |
| `google/gemini-3.8-flash` | 100.0% (156/156) | 98.7% (147/149) | 97.9% (142/145) |
| `deepseek/deepseek-v4-pro` | 95.5% (168/176) | 94.9% (167/176) | 88.1% (155/176) |

## Notes

- `manual` should be treated as the primary curated stratum; `halurust` and `rustmizan` remain secondary/external-validity strata.
- Unparseable verdicts are counted as incorrect for accuracy and excluded from pairwise confidence comparisons when no usable confidence is available.
- Raw responses, parsed responses, and machine-readable scores are in this same run directory.
