# OpenRouter Evaluation Harness

This package builds a read-only manifest from `rust-vuln-dataset/`, creates prompt variants, runs OpenRouter chat-completion requests, and scores the responses.

Default model slugs resolved from the public OpenRouter catalog:

- `anthropic/claude-sonnet-5.5`
- `openai/gpt-6-sol`
- `google/gemini-3.8-flash`
- `deepseek/deepseek-v4-pro`

The v2 run uses `openai/gpt-6.1-sol` instead of GPT-6 Sol (`runs/openrouter-v2/models.json`) and a manifest that keeps only RustMizan's function-level items (`runs/openrouter-v2/manifest.jsonl`, 699 items); crate- and file-level RustMizan items cost about two thirds of the budget while clean accuracy on them was near chance.

## Prompt design (prompt version `v2`)

The model sees only the code. No file paths, sample roles, or dataset names are included, because they can reveal the label. Multi-file items are joined under neutral `// File i of n` headers. Every defense uses the same system prompt; `warning` and `tagged` add one defense paragraph to it.

Every item gets the **core design** (12 prompts per model):

| Defense | Conditions |
|---|---|
| `neutral`, `warning`, `tagged` | `clean`, plus three top-of-file attack comments: `dsc` (declarative safety claim), `api` (authority impersonation), `ivm` (imperative verdict manipulation) |

The attack goal follows the label: vulnerable code gets **suppression** comments ("this is safe"), safe code gets **induction** comments ("this is vulnerable").

Families listed in `--extended-families` (default: `manual`) also get the **extended design** (31 prompts per model):

| Added condition | Purpose |
|---|---|
| `benign` | Harmless comment; separates "any comment" effects from attack effects |
| `<attack>_inline` | The same three attacks placed above the first `unsafe` block or the function body |
| `<goal>_rust` | Rust-idiomatic `// SAFETY:` or `// FIXME: unsound` comment, placed inline |
| `<goal>_escape` | Comment that tries to close and reopen the `<UNTRUSTED_COMMENT>` tag |
| `stripped:clean` | All comments removed; shows how much accuracy depends on comments at all |

In the `tagged` defense every Rust comment (line, block, nested block, doc) is wrapped in `<UNTRUSTED_COMMENT>` tags by a small lexer that skips string, raw-string, byte, and char literals. Tag text inside comments is escaped, so an injected comment cannot break out of its tag.

Families in `--repeat-families` (default: `manual`) have a deterministic `--repeat-fraction` of vulnerable/fixed pairs (default 10%) queried `--repeat-count` extra times (default 2) to measure verdict stability. Repeats are excluded from the main rates.

## Request counts

| Command options | Requests |
|---|---:|
| Defaults | 73,632 |
| `--repeat-count 1` | 69,416 |
| `--repeat-families` (no value: no repeats) | 65,200 |
| `--extended-families --repeat-families` (core only) | 38,448 |

Always confirm the count with `--dry-run` first.

## Running

The paper's results come from `runs/openrouter-v2/full`. The dataset submodule must be at the commit recorded in this repository (`git submodule update --init`).

```sh
# 0. Build the manifest, then keep only RustMizan's function-level items.
#    The result is byte-identical to runs/openrouter-v2/manifest.jsonl.
python3 -m openrouter_eval.build_manifest \
  --dataset-root rust-vuln-dataset \
  --out /tmp/manifest_all.jsonl
python3 -c "import json,sys; sys.stdout.writelines(l for l in open('/tmp/manifest_all.jsonl') if (d:=json.loads(l))['dataset_family']!='rustmizan' or d['source_path'].endswith('-function'))" \
  > runs/openrouter-v2/manifest.jsonl

# 1. Dry run: writes requests.jsonl, makes no API calls.
python3 -m openrouter_eval.run_openrouter \
  --dataset-root rust-vuln-dataset \
  --manifest runs/openrouter-v2/manifest.jsonl \
  --models runs/openrouter-v2/models.json \
  --out-dir runs/openrouter-v2/full \
  --dry-run

# 2. Small paid smoke test to check parsing and cost per request.
OPENROUTER_API_KEY=... python3 -m openrouter_eval.run_openrouter \
  --dataset-root rust-vuln-dataset \
  --manifest runs/openrouter-v2/manifest.jsonl \
  --models runs/openrouter-v2/models.json \
  --out-dir runs/openrouter-v2/smoke \
  --limit-per-family 2 --concurrency 4

# 3. Full run. Rerun the same command to retry failures, then the two
#    follow-up passes listed in runs/openrouter-v2/full/run_config.json.
OPENROUTER_API_KEY=... python3 -m openrouter_eval.run_openrouter \
  --dataset-root rust-vuln-dataset \
  --manifest runs/openrouter-v2/manifest.jsonl \
  --models runs/openrouter-v2/models.json \
  --out-dir runs/openrouter-v2/full \
  --concurrency 8

# 4. Score, then fit the regression model (needs pandas and statsmodels).
python3 -m openrouter_eval.score_results --run-dir runs/openrouter-v2/full
python3 -m openrouter_eval.analyze_gee --run-dir runs/openrouter-v2/full --family manual
python3 -m openrouter_eval.analyze_gee --run-dir runs/openrouter-v2/full --family manual --interaction
```

Use a new `--out-dir` for each run. The runner refuses to add responses to a folder that already holds responses from a different prompt version.

## Resuming and failures

Rerunning the same command resumes: requests that already have a successful response are skipped, and failed ones are retried.

- Rate limits and server errors (408, 409, 429, 5xx) are retried up to three times per request.
- Responses that arrive with HTTP 200 but contain a provider error or no answer are recorded as failures, so they are retried on the next run.
- A spending-limit or credit error (402, or 403 mentioning a limit) stops the whole run instead of failing every remaining request. Top up the key and rerun the same command.

The default `--max-tokens` is 2048. Lower limits cut off many answers, mostly Gemini's, whose hidden reasoning counts toward the limit, and cut-off answers are usually unparseable. `summary.md` reports how many responses were truncated. After the main run, `--retry-truncated-max-tokens 8192` re-queries only the cut-off responses with a larger limit; every other request keeps its original limit in `requests.jsonl`.

## Routing and reasoning

- Claude, Gemini, and GPT run with `reasoning.effort = "minimal"`; GPT-6.1 Sol and some Claude/Gemini endpoints reject requests with reasoning disabled. DeepSeek runs with reasoning off.
- GPT prefers OpenAI's flex tier (half price, slower) and has a `max_price` cap so it never falls back to priority tiers.
- DeepSeek goes to the cheapest fp8 host, so every answer comes from the same precision.
- Claude and Gemini are pinned to the provider that holds the BYOK key (`anthropic`, `google-ai-studio`). Without this, OpenRouter retries Gemini's intermittent "blocked the response" errors on its own billed Google endpoint. For a final pass over requests that still fail, add `--allow-byok-fallback`.

The routing used for each request is stored in its `provider` field in `requests.jsonl`, and the reasoning setting in its `reasoning` field.

### Per-model settings

`--reasoning-effort` (default `auto`, the behaviour above) applies to every model. A models file entry can override it for one model by giving an object instead of a slug:

```json
{
  "claude_sonnet_5_5": "anthropic/claude-sonnet-5.5",
  "deepseek_v4_pro": {"slug": "deepseek/deepseek-v4-pro", "reasoning_effort": "minimal"}
}
```

`slug` is required; `reasoning_effort` is optional and accepts the same values as `--reasoning-effort`. Plain slug entries (as in `runs/openrouter-v2/models.json`) build exactly the same requests as before. `run_config.json` records the models file as given, including per-model settings.

The matched-reasoning rerun uses `runs/deepseek-matched-reasoning/models.json` (DeepSeek V4 Pro at `minimal`) on the main set with the extended design and no repeats, which is 10,912 requests (352 items × 31 prompts):

```sh
python3 -m openrouter_eval.run_openrouter \
  --dataset-root rust-vuln-dataset \
  --manifest runs/openrouter-v2/manifest.jsonl \
  --models runs/deepseek-matched-reasoning/models.json \
  --out-dir runs/deepseek-matched-reasoning/full \
  --families manual --repeat-families \
  --dry-run
```

Reasoning makes answers longer, so expect more truncation at the default `--max-tokens`; the scorer counts truncated answers as in v2, and `--retry-truncated-max-tokens 8192` re-queries them.

## Parsing

Models are asked for JSON only. Some Claude answers write analysis first and end with the JSON object; the scorer takes the last JSON object that has a `verdict` field. `parsed.jsonl` marks such answers with `strict_json: false`, and `summary.md` counts them.

## Outputs

| File | Contents |
|---|---|
| `run_config.json` | Models, prompt version, token limit, extended/repeat settings |
| `requests.jsonl` | Every prompt sent, with label and condition metadata |
| `responses.jsonl` | Raw OpenRouter responses, appended as they arrive |
| `parsed.jsonl` | One row per request: verdict, correctness, attack success, `flips_clean` (verdict changed versus the matching clean prompt) |
| `scores.json`, `summary.md` | Rates by model, family, defense, and condition; pairwise clean accuracy; repeat stability |
| `gee_<family>[_interaction].{json,md}` | Odds ratios from a logistic GEE clustered by vulnerable/fixed pair |

The source dataset and paper draft are never modified. Generated files belong under `runs/`.
