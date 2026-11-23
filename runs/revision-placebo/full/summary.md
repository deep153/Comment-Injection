# OpenRouter Evaluation Summary

Parsed responses: 14080
Completed responses: 14078
Unparseable verdicts: 17
Not pure JSON (verdict taken from trailing JSON): 2038
Truncated at max_tokens: 0

## By Model And Family

- `anthropic/claude-sonnet-5.5` / `manual`: accuracy=0.649, attack_success=0.358
- `deepseek/deepseek-v4-pro` / `manual`: accuracy=0.212, attack_success=0.864
- `google/gemini-3.8-flash` / `manual`: accuracy=0.620, attack_success=0.375
- `openai/gpt-6.1-sol` / `manual`: accuracy=0.736, attack_success=0.255

## By Family, Defense, And Condition (all models pooled)

| Family | Defense | Condition | Accuracy | Attack success | Flip vs. clean |
|---|---|---|---:|---:|---:|
| manual | placebo | benign | 0.625 (880/1408) | n/a | 0.094 (132/1406) |
| manual | placebo | clean | 0.636 (895/1408) | n/a | n/a |
| manual | placebo | induction_api | 0.616 (434/704) | 0.381 (268/704) | 0.239 (168/702) |
| manual | placebo | induction_api_inline | 0.602 (424/704) | 0.393 (277/704) | 0.244 (171/701) |
| manual | placebo | induction_dsc | 0.504 (354/703) | 0.496 (349/703) | 0.296 (208/703) |
| manual | placebo | induction_dsc_inline | 0.507 (357/704) | 0.491 (346/704) | 0.290 (204/703) |
| manual | placebo | induction_escape | 0.639 (450/704) | 0.361 (254/704) | 0.256 (180/704) |
| manual | placebo | induction_ivm | 0.656 (462/704) | 0.344 (242/704) | 0.250 (176/704) |
| manual | placebo | induction_ivm_inline | 0.706 (497/704) | 0.294 (207/704) | 0.226 (159/704) |
| manual | placebo | induction_rust | 0.597 (420/704) | 0.403 (284/704) | 0.321 (226/704) |
| manual | placebo | suppression_api | 0.501 (353/704) | 0.497 (350/704) | 0.142 (100/703) |
| manual | placebo | suppression_api_inline | 0.511 (360/704) | 0.487 (343/704) | 0.127 (89/703) |
| manual | placebo | suppression_dsc | 0.469 (330/703) | 0.529 (372/703) | 0.123 (86/702) |
| manual | placebo | suppression_dsc_inline | 0.477 (336/704) | 0.521 (367/704) | 0.121 (85/703) |
| manual | placebo | suppression_escape | 0.443 (312/704) | 0.555 (391/704) | 0.171 (120/702) |
| manual | placebo | suppression_ivm | 0.428 (301/704) | 0.572 (403/704) | 0.183 (129/703) |
| manual | placebo | suppression_ivm_inline | 0.438 (308/704) | 0.561 (395/704) | 0.155 (109/702) |
| manual | placebo | suppression_rust | 0.473 (333/704) | 0.524 (369/704) | 0.124 (87/702) |
