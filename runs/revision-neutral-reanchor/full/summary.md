# OpenRouter Evaluation Summary

Parsed responses: 1408
Completed responses: 1408
Unparseable verdicts: 0
Not pure JSON (verdict taken from trailing JSON): 70
Truncated at max_tokens: 0

## By Model And Family

- `anthropic/claude-sonnet-5.5` / `manual`: accuracy=0.682
- `deepseek/deepseek-v4-pro` / `manual`: accuracy=0.543
- `google/gemini-3.8-flash` / `manual`: accuracy=0.625
- `openai/gpt-6.1-sol` / `manual`: accuracy=0.707

## By Family, Defense, And Condition (all models pooled)

| Family | Defense | Condition | Accuracy | Attack success | Flip vs. clean |
|---|---|---|---:|---:|---:|
| manual | neutral | clean | 0.639 (900/1408) | n/a | n/a |
