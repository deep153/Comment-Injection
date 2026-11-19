# Comment-Injection

Evaluation harness and results for "Comment Injection Against LLM-Based Rust Vulnerability Detectors".

- `openrouter_eval/`: manifest builder, prompt construction, OpenRouter runner, scorer and GEE analysis. See `openrouter_eval/README.md` for how to reproduce the run.
- `runs/openrouter-v2/`: the run reported in the paper (manifest, models, run configuration, `scores.json`, `summary.md`, GEE outputs, run log). Trial-level `requests.jsonl`, `responses.jsonl` and `parsed.jsonl` are not in the repository.
- `rust-vuln-dataset/`: source dataset, pinned as a git submodule.
