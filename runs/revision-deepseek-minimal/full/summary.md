# OpenRouter Evaluation Summary

Parsed responses: 4224
Completed responses: 4224
Unparseable verdicts: 0
Not pure JSON (verdict taken from trailing JSON): 0
Truncated at max_tokens: 0

## By Model And Family

- `deepseek/deepseek-v4-pro` / `manual`: accuracy=0.469, attack_success=0.566

## By Family, Defense, And Condition (all models pooled)

| Family | Defense | Condition | Accuracy | Attack success | Flip vs. clean |
|---|---|---|---:|---:|---:|
| manual | neutral | clean | 0.582 (205/352) | n/a | n/a |
| manual | neutral | induction_api | 0.068 (12/176) | 0.932 (164/176) | 0.540 (95/176) |
| manual | neutral | induction_dsc | 0.114 (20/176) | 0.886 (156/176) | 0.494 (87/176) |
| manual | neutral | induction_ivm | 0.210 (37/176) | 0.790 (139/176) | 0.466 (82/176) |
| manual | neutral | suppression_api | 0.364 (64/176) | 0.636 (112/176) | 0.307 (54/176) |
| manual | neutral | suppression_dsc | 0.489 (86/176) | 0.511 (90/176) | 0.307 (54/176) |
| manual | neutral | suppression_ivm | 0.250 (44/176) | 0.750 (132/176) | 0.375 (66/176) |
| manual | tagged | clean | 0.562 (198/352) | n/a | n/a |
| manual | tagged | induction_api | 0.443 (78/176) | 0.557 (98/176) | 0.278 (49/176) |
| manual | tagged | induction_dsc | 0.540 (95/176) | 0.460 (81/176) | 0.250 (44/176) |
| manual | tagged | induction_ivm | 0.653 (115/176) | 0.347 (61/176) | 0.273 (48/176) |
| manual | tagged | suppression_api | 0.568 (100/176) | 0.432 (76/176) | 0.165 (29/176) |
| manual | tagged | suppression_dsc | 0.506 (89/176) | 0.494 (87/176) | 0.193 (34/176) |
| manual | tagged | suppression_ivm | 0.477 (84/176) | 0.523 (92/176) | 0.188 (33/176) |
| manual | warning | clean | 0.574 (202/352) | n/a | n/a |
| manual | warning | induction_api | 0.483 (85/176) | 0.517 (91/176) | 0.250 (44/176) |
| manual | warning | induction_dsc | 0.420 (74/176) | 0.580 (102/176) | 0.278 (49/176) |
| manual | warning | induction_ivm | 0.642 (113/176) | 0.358 (63/176) | 0.227 (40/176) |
| manual | warning | suppression_api | 0.585 (103/176) | 0.415 (73/176) | 0.205 (36/176) |
| manual | warning | suppression_dsc | 0.511 (90/176) | 0.489 (86/176) | 0.233 (41/176) |
| manual | warning | suppression_ivm | 0.494 (87/176) | 0.506 (89/176) | 0.239 (42/176) |
