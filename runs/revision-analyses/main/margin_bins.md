# Flip rate by clean decision margin

Runs: `runs/openrouter-v2/full` (prompt version v2); `runs/revision-placebo/full` (prompt version v3).
Adaptive runs: `runs/revision-adaptive/full`.
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Clean margin = |clean vulnerability score - 0.5| for the same item, model and defense. Flip rate: share of attacked prompts whose verdict differs from the clean verdict (both parsed). Conditional flip rate: the same, restricted to items whose clean verdict was correct.

## By model (all defenses and goals)

| Model | Clean margin | Flip rate | Conditional flip rate |
|---|---|---:|---:|
| `anthropic/claude-sonnet-5.5` | [0.0, 0.1) | 0.317 (1014/3198) | 0.301 (593/1967) |
| `anthropic/claude-sonnet-5.5` | [0.1, 0.2) | 0.147 (184/1255) | 0.144 (115/799) |
| `anthropic/claude-sonnet-5.5` | [0.2, 0.3) | 0.188 (39/208) | 0.164 (21/128) |
| `anthropic/claude-sonnet-5.5` | [0.3, 0.4) | 0.085 (396/4654) | 0.072 (239/3326) |
| `anthropic/claude-sonnet-5.5` | [0.4, 0.5] | 0.015 (29/1930) | 0.021 (27/1301) |
| `deepseek/deepseek-v4-pro` | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | [0.1, 0.2) | 0.750 (6/8) | 0.750 (6/8) |
| `deepseek/deepseek-v4-pro` | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | [0.3, 0.4) | 0.552 (106/192) | 0.857 (96/112) |
| `deepseek/deepseek-v4-pro` | [0.4, 0.5] | 0.326 (3606/11064) | 0.575 (3356/5840) |
| `google/gemini-3.8-flash` | [0.0, 0.1) | 0.125 (1/8) | 0.125 (1/8) |
| `google/gemini-3.8-flash` | [0.1, 0.2) | 0.441 (60/136) | 0.385 (40/104) |
| `google/gemini-3.8-flash` | [0.2, 0.3) | 0.438 (7/16) | n/a (0/0) |
| `google/gemini-3.8-flash` | [0.3, 0.4) | 0.286 (959/3349) | 0.185 (370/2002) |
| `google/gemini-3.8-flash` | [0.4, 0.5] | 0.122 (925/7594) | 0.079 (393/4996) |
| `openai/gpt-6.1-sol` | [0.0, 0.1) | 0.165 (78/472) | 0.085 (28/328) |
| `openai/gpt-6.1-sol` | [0.1, 0.2) | 0.171 (67/392) | 0.040 (9/224) |
| `openai/gpt-6.1-sol` | [0.2, 0.3) | 0.190 (160/840) | 0.063 (35/552) |
| `openai/gpt-6.1-sol` | [0.3, 0.4) | 0.120 (350/2928) | 0.039 (81/2088) |
| `openai/gpt-6.1-sol` | [0.4, 0.5] | 0.018 (117/6632) | 0.005 (24/4696) |

## By model, defense and goal

| Model | Defense | Goal | Clean margin | Flip rate | Conditional flip rate |
|---|---|---|---|---:|---:|
| `anthropic/claude-sonnet-5.5` | neutral | induction | [0.0, 0.1) | 0.381 (177/464) | 0.303 (92/304) |
| `anthropic/claude-sonnet-5.5` | neutral | induction | [0.1, 0.2) | 0.182 (42/231) | 0.120 (21/175) |
| `anthropic/claude-sonnet-5.5` | neutral | induction | [0.2, 0.3) | 0.083 (2/24) | 0.125 (2/16) |
| `anthropic/claude-sonnet-5.5` | neutral | induction | [0.3, 0.4) | 0.145 (82/567) | 0.112 (52/463) |
| `anthropic/claude-sonnet-5.5` | neutral | induction | [0.4, 0.5] | 0.033 (4/120) | 0.033 (4/120) |
| `anthropic/claude-sonnet-5.5` | neutral | suppression | [0.0, 0.1) | 0.327 (157/480) | 0.476 (137/288) |
| `anthropic/claude-sonnet-5.5` | neutral | suppression | [0.1, 0.2) | 0.162 (22/136) | 0.236 (17/72) |
| `anthropic/claude-sonnet-5.5` | neutral | suppression | [0.2, 0.3) | 0.000 (0/8) | 0.000 (0/8) |
| `anthropic/claude-sonnet-5.5` | neutral | suppression | [0.3, 0.4) | 0.096 (47/488) | 0.154 (43/280) |
| `anthropic/claude-sonnet-5.5` | neutral | suppression | [0.4, 0.5] | 0.024 (7/295) | 0.034 (6/175) |
| `anthropic/claude-sonnet-5.5` | placebo | induction | [0.0, 0.1) | 0.324 (67/207) | 0.245 (37/151) |
| `anthropic/claude-sonnet-5.5` | placebo | induction | [0.1, 0.2) | 0.261 (48/184) | 0.206 (28/136) |
| `anthropic/claude-sonnet-5.5` | placebo | induction | [0.2, 0.3) | 0.304 (17/56) | 0.000 (0/8) |
| `anthropic/claude-sonnet-5.5` | placebo | induction | [0.3, 0.4) | 0.067 (49/736) | 0.048 (34/704) |
| `anthropic/claude-sonnet-5.5` | placebo | induction | [0.4, 0.5] | 0.018 (4/223) | 0.014 (3/215) |
| `anthropic/claude-sonnet-5.5` | placebo | suppression | [0.0, 0.1) | 0.496 (119/240) | 0.587 (108/184) |
| `anthropic/claude-sonnet-5.5` | placebo | suppression | [0.1, 0.2) | 0.131 (21/160) | 0.286 (16/56) |
| `anthropic/claude-sonnet-5.5` | placebo | suppression | [0.2, 0.3) | 0.138 (11/80) | 0.179 (10/56) |
| `anthropic/claude-sonnet-5.5` | placebo | suppression | [0.3, 0.4) | 0.096 (50/520) | 0.138 (31/224) |
| `anthropic/claude-sonnet-5.5` | placebo | suppression | [0.4, 0.5] | 0.015 (6/407) | 0.027 (6/224) |
| `anthropic/claude-sonnet-5.5` | tagged | induction | [0.0, 0.1) | 0.267 (128/480) | 0.058 (18/312) |
| `anthropic/claude-sonnet-5.5` | tagged | induction | [0.1, 0.2) | 0.026 (4/152) | 0.015 (2/136) |
| `anthropic/claude-sonnet-5.5` | tagged | induction | [0.2, 0.3) | 0.000 (0/8) | 0.000 (0/8) |
| `anthropic/claude-sonnet-5.5` | tagged | induction | [0.3, 0.4) | 0.053 (35/664) | 0.030 (18/592) |
| `anthropic/claude-sonnet-5.5` | tagged | induction | [0.4, 0.5] | 0.000 (0/96) | 0.000 (0/88) |
| `anthropic/claude-sonnet-5.5` | tagged | suppression | [0.0, 0.1) | 0.283 (129/456) | 0.420 (94/224) |
| `anthropic/claude-sonnet-5.5` | tagged | suppression | [0.1, 0.2) | 0.146 (21/144) | 0.188 (9/48) |
| `anthropic/claude-sonnet-5.5` | tagged | suppression | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `anthropic/claude-sonnet-5.5` | tagged | suppression | [0.3, 0.4) | 0.113 (55/488) | 0.104 (25/240) |
| `anthropic/claude-sonnet-5.5` | tagged | suppression | [0.4, 0.5] | 0.009 (3/319) | 0.017 (3/176) |
| `anthropic/claude-sonnet-5.5` | warning | induction | [0.0, 0.1) | 0.274 (116/423) | 0.079 (22/280) |
| `anthropic/claude-sonnet-5.5` | warning | induction | [0.1, 0.2) | 0.062 (11/176) | 0.049 (7/144) |
| `anthropic/claude-sonnet-5.5` | warning | induction | [0.2, 0.3) | 0.083 (2/24) | 0.083 (2/24) |
| `anthropic/claude-sonnet-5.5` | warning | induction | [0.3, 0.4) | 0.056 (35/623) | 0.037 (20/543) |
| `anthropic/claude-sonnet-5.5` | warning | induction | [0.4, 0.5] | 0.000 (0/159) | 0.000 (0/135) |
| `anthropic/claude-sonnet-5.5` | warning | suppression | [0.0, 0.1) | 0.270 (121/448) | 0.379 (85/224) |
| `anthropic/claude-sonnet-5.5` | warning | suppression | [0.1, 0.2) | 0.208 (15/72) | 0.469 (15/32) |
| `anthropic/claude-sonnet-5.5` | warning | suppression | [0.2, 0.3) | 0.875 (7/8) | 0.875 (7/8) |
| `anthropic/claude-sonnet-5.5` | warning | suppression | [0.3, 0.4) | 0.076 (43/568) | 0.057 (16/280) |
| `anthropic/claude-sonnet-5.5` | warning | suppression | [0.4, 0.5] | 0.016 (5/311) | 0.030 (5/168) |
| `deepseek/deepseek-v4-pro` | neutral | induction | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | neutral | induction | [0.1, 0.2) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | neutral | induction | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | neutral | induction | [0.3, 0.4) | 0.000 (0/8) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | neutral | induction | [0.4, 0.5] | 0.653 (914/1400) | 0.837 (911/1088) |
| `deepseek/deepseek-v4-pro` | neutral | suppression | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | neutral | suppression | [0.1, 0.2) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | neutral | suppression | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | neutral | suppression | [0.3, 0.4) | 0.750 (18/24) | 0.750 (18/24) |
| `deepseek/deepseek-v4-pro` | neutral | suppression | [0.4, 0.5] | 0.179 (248/1384) | 0.546 (227/416) |
| `deepseek/deepseek-v4-pro` | placebo | induction | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | placebo | induction | [0.1, 0.2) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | placebo | induction | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | placebo | induction | [0.3, 0.4) | 0.917 (22/24) | 0.917 (22/24) |
| `deepseek/deepseek-v4-pro` | placebo | induction | [0.4, 0.5] | 0.635 (879/1384) | 0.865 (872/1008) |
| `deepseek/deepseek-v4-pro` | placebo | suppression | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | placebo | suppression | [0.1, 0.2) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | placebo | suppression | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | placebo | suppression | [0.3, 0.4) | 0.484 (31/64) | 0.844 (27/32) |
| `deepseek/deepseek-v4-pro` | placebo | suppression | [0.4, 0.5] | 0.181 (243/1344) | 0.517 (215/416) |
| `deepseek/deepseek-v4-pro` | tagged | induction | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | tagged | induction | [0.1, 0.2) | 0.750 (6/8) | 0.750 (6/8) |
| `deepseek/deepseek-v4-pro` | tagged | induction | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | tagged | induction | [0.3, 0.4) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | tagged | induction | [0.4, 0.5] | 0.308 (431/1400) | 0.359 (393/1096) |
| `deepseek/deepseek-v4-pro` | tagged | suppression | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | tagged | suppression | [0.1, 0.2) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | tagged | suppression | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | tagged | suppression | [0.3, 0.4) | 0.656 (21/32) | 0.875 (21/24) |
| `deepseek/deepseek-v4-pro` | tagged | suppression | [0.4, 0.5] | 0.125 (172/1376) | 0.253 (95/376) |
| `deepseek/deepseek-v4-pro` | warning | induction | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | warning | induction | [0.1, 0.2) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | warning | induction | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | warning | induction | [0.3, 0.4) | 0.344 (11/32) | 1.000 (8/8) |
| `deepseek/deepseek-v4-pro` | warning | induction | [0.4, 0.5] | 0.406 (559/1376) | 0.482 (547/1136) |
| `deepseek/deepseek-v4-pro` | warning | suppression | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | warning | suppression | [0.1, 0.2) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | warning | suppression | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | warning | suppression | [0.3, 0.4) | 0.375 (3/8) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | warning | suppression | [0.4, 0.5] | 0.114 (160/1400) | 0.316 (96/304) |
| `google/gemini-3.8-flash` | neutral | induction | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | neutral | induction | [0.1, 0.2) | 0.562 (27/48) | 0.562 (27/48) |
| `google/gemini-3.8-flash` | neutral | induction | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | neutral | induction | [0.3, 0.4) | 0.353 (171/485) | 0.343 (117/341) |
| `google/gemini-3.8-flash` | neutral | induction | [0.4, 0.5] | 0.175 (149/853) | 0.146 (97/663) |
| `google/gemini-3.8-flash` | neutral | suppression | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | neutral | suppression | [0.1, 0.2) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | neutral | suppression | [0.2, 0.3) | 0.438 (7/16) | n/a (0/0) |
| `google/gemini-3.8-flash` | neutral | suppression | [0.3, 0.4) | 0.329 (147/447) | 0.225 (52/231) |
| `google/gemini-3.8-flash` | neutral | suppression | [0.4, 0.5] | 0.107 (98/912) | 0.071 (37/520) |
| `google/gemini-3.8-flash` | placebo | induction | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | placebo | induction | [0.1, 0.2) | 0.562 (9/16) | 0.562 (9/16) |
| `google/gemini-3.8-flash` | placebo | induction | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | placebo | induction | [0.3, 0.4) | 0.383 (144/376) | 0.331 (82/248) |
| `google/gemini-3.8-flash` | placebo | induction | [0.4, 0.5] | 0.168 (170/1011) | 0.148 (112/756) |
| `google/gemini-3.8-flash` | placebo | suppression | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | placebo | suppression | [0.1, 0.2) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | placebo | suppression | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | placebo | suppression | [0.3, 0.4) | 0.308 (120/389) | 0.108 (17/157) |
| `google/gemini-3.8-flash` | placebo | suppression | [0.4, 0.5] | 0.129 (130/1008) | 0.083 (43/520) |
| `google/gemini-3.8-flash` | tagged | induction | [0.0, 0.1) | 0.125 (1/8) | 0.125 (1/8) |
| `google/gemini-3.8-flash` | tagged | induction | [0.1, 0.2) | 0.188 (3/16) | 0.188 (3/16) |
| `google/gemini-3.8-flash` | tagged | induction | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | tagged | induction | [0.3, 0.4) | 0.198 (87/439) | 0.047 (16/343) |
| `google/gemini-3.8-flash` | tagged | induction | [0.4, 0.5] | 0.131 (121/926) | 0.030 (21/711) |
| `google/gemini-3.8-flash` | tagged | suppression | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | tagged | suppression | [0.1, 0.2) | 0.667 (16/24) | n/a (0/0) |
| `google/gemini-3.8-flash` | tagged | suppression | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | tagged | suppression | [0.3, 0.4) | 0.259 (109/421) | 0.266 (55/207) |
| `google/gemini-3.8-flash` | tagged | suppression | [0.4, 0.5] | 0.074 (69/933) | 0.053 (27/511) |
| `google/gemini-3.8-flash` | warning | induction | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | warning | induction | [0.1, 0.2) | 0.000 (0/8) | 0.000 (0/8) |
| `google/gemini-3.8-flash` | warning | induction | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | warning | induction | [0.3, 0.4) | 0.174 (72/413) | 0.038 (12/317) |
| `google/gemini-3.8-flash` | warning | induction | [0.4, 0.5] | 0.088 (85/965) | 0.026 (20/784) |
| `google/gemini-3.8-flash` | warning | suppression | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | warning | suppression | [0.1, 0.2) | 0.208 (5/24) | 0.062 (1/16) |
| `google/gemini-3.8-flash` | warning | suppression | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `google/gemini-3.8-flash` | warning | suppression | [0.3, 0.4) | 0.288 (109/379) | 0.120 (19/158) |
| `google/gemini-3.8-flash` | warning | suppression | [0.4, 0.5] | 0.104 (103/986) | 0.068 (36/531) |
| `openai/gpt-6.1-sol` | neutral | induction | [0.0, 0.1) | 0.000 (0/80) | 0.000 (0/80) |
| `openai/gpt-6.1-sol` | neutral | induction | [0.1, 0.2) | 0.136 (12/88) | 0.050 (4/80) |
| `openai/gpt-6.1-sol` | neutral | induction | [0.2, 0.3) | 0.147 (20/136) | 0.075 (9/120) |
| `openai/gpt-6.1-sol` | neutral | induction | [0.3, 0.4) | 0.150 (61/408) | 0.024 (7/296) |
| `openai/gpt-6.1-sol` | neutral | induction | [0.4, 0.5] | 0.034 (24/696) | 0.000 (0/464) |
| `openai/gpt-6.1-sol` | neutral | suppression | [0.0, 0.1) | 0.396 (19/48) | n/a (0/0) |
| `openai/gpt-6.1-sol` | neutral | suppression | [0.1, 0.2) | 0.333 (8/24) | n/a (0/0) |
| `openai/gpt-6.1-sol` | neutral | suppression | [0.2, 0.3) | 0.297 (19/64) | n/a (0/0) |
| `openai/gpt-6.1-sol` | neutral | suppression | [0.3, 0.4) | 0.062 (19/304) | 0.040 (8/200) |
| `openai/gpt-6.1-sol` | neutral | suppression | [0.4, 0.5] | 0.014 (14/968) | 0.015 (11/720) |
| `openai/gpt-6.1-sol` | placebo | induction | [0.0, 0.1) | 0.056 (4/72) | 0.056 (4/72) |
| `openai/gpt-6.1-sol` | placebo | induction | [0.1, 0.2) | 0.000 (0/16) | 0.000 (0/16) |
| `openai/gpt-6.1-sol` | placebo | induction | [0.2, 0.3) | 0.108 (13/120) | 0.045 (5/112) |
| `openai/gpt-6.1-sol` | placebo | induction | [0.3, 0.4) | 0.091 (42/464) | 0.005 (2/368) |
| `openai/gpt-6.1-sol` | placebo | induction | [0.4, 0.5] | 0.033 (24/736) | 0.004 (2/496) |
| `openai/gpt-6.1-sol` | placebo | suppression | [0.0, 0.1) | 0.333 (8/24) | n/a (0/0) |
| `openai/gpt-6.1-sol` | placebo | suppression | [0.1, 0.2) | 0.438 (7/16) | n/a (0/0) |
| `openai/gpt-6.1-sol` | placebo | suppression | [0.2, 0.3) | 0.350 (28/80) | 0.375 (3/8) |
| `openai/gpt-6.1-sol` | placebo | suppression | [0.3, 0.4) | 0.125 (27/216) | 0.132 (18/136) |
| `openai/gpt-6.1-sol` | placebo | suppression | [0.4, 0.5] | 0.004 (4/1072) | 0.005 (4/808) |
| `openai/gpt-6.1-sol` | tagged | induction | [0.0, 0.1) | 0.097 (7/72) | 0.097 (7/72) |
| `openai/gpt-6.1-sol` | tagged | induction | [0.1, 0.2) | 0.323 (31/96) | 0.047 (3/64) |
| `openai/gpt-6.1-sol` | tagged | induction | [0.2, 0.3) | 0.188 (33/176) | 0.059 (8/136) |
| `openai/gpt-6.1-sol` | tagged | induction | [0.3, 0.4) | 0.097 (38/392) | 0.014 (4/288) |
| `openai/gpt-6.1-sol` | tagged | induction | [0.4, 0.5] | 0.018 (12/672) | 0.002 (1/432) |
| `openai/gpt-6.1-sol` | tagged | suppression | [0.0, 0.1) | 0.325 (13/40) | n/a (0/0) |
| `openai/gpt-6.1-sol` | tagged | suppression | [0.1, 0.2) | 0.036 (2/56) | 0.250 (2/8) |
| `openai/gpt-6.1-sol` | tagged | suppression | [0.2, 0.3) | 0.266 (17/64) | 0.042 (1/24) |
| `openai/gpt-6.1-sol` | tagged | suppression | [0.3, 0.4) | 0.132 (40/304) | 0.116 (25/216) |
| `openai/gpt-6.1-sol` | tagged | suppression | [0.4, 0.5] | 0.007 (7/944) | 0.001 (1/728) |
| `openai/gpt-6.1-sol` | warning | induction | [0.0, 0.1) | 0.163 (17/104) | 0.163 (17/104) |
| `openai/gpt-6.1-sol` | warning | induction | [0.1, 0.2) | 0.000 (0/56) | 0.000 (0/56) |
| `openai/gpt-6.1-sol` | warning | induction | [0.2, 0.3) | 0.139 (20/144) | 0.033 (4/120) |
| `openai/gpt-6.1-sol` | warning | induction | [0.3, 0.4) | 0.175 (88/504) | 0.006 (2/352) |
| `openai/gpt-6.1-sol` | warning | induction | [0.4, 0.5] | 0.032 (19/600) | 0.000 (0/344) |
| `openai/gpt-6.1-sol` | warning | suppression | [0.0, 0.1) | 0.312 (10/32) | n/a (0/0) |
| `openai/gpt-6.1-sol` | warning | suppression | [0.1, 0.2) | 0.175 (7/40) | n/a (0/0) |
| `openai/gpt-6.1-sol` | warning | suppression | [0.2, 0.3) | 0.179 (10/56) | 0.156 (5/32) |
| `openai/gpt-6.1-sol` | warning | suppression | [0.3, 0.4) | 0.104 (35/336) | 0.065 (15/232) |
| `openai/gpt-6.1-sol` | warning | suppression | [0.4, 0.5] | 0.014 (13/944) | 0.007 (5/704) |
