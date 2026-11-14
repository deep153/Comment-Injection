# OpenRouter Evaluation Harness

This package builds a read-only manifest from `rust-vuln-dataset/`, creates prompt variants, runs OpenRouter chat-completion requests, and scores the responses.

Default model slugs resolved from the public OpenRouter catalog:

- `anthropic/claude-sonnet-5.5`
- `openai/gpt-6-sol`
- `google/gemini-3.8-flash`
- `deepseek/deepseek-v4-pro`

Example:

```sh
python3 -m openrouter_eval.build_manifest \
  --dataset-root rust-vuln-dataset \
  --out runs/openrouter-current/manifest.jsonl

python3 -m openrouter_eval.run_openrouter \
  --dataset-root rust-vuln-dataset \
  --manifest runs/openrouter-current/manifest.jsonl \
  --out-dir runs/openrouter-current/smoke \
  --limit 8 \
  --dry-run

OPENROUTER_API_KEY=... python3 -m openrouter_eval.run_openrouter \
  --dataset-root rust-vuln-dataset \
  --manifest runs/openrouter-current/manifest.jsonl \
  --out-dir runs/openrouter-current/full

python3 -m openrouter_eval.score_results \
  --run-dir runs/openrouter-current/full
```

The source dataset and paper draft are never modified. Generated manifests, requests, responses, parsed outputs, scores, and summaries belong under `runs/`.
