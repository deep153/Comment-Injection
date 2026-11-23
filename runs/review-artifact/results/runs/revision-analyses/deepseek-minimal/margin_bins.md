# Flip rate by clean decision margin

Runs: `runs/revision-deepseek-minimal/full` (prompt version v3).
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Clean margin = |clean vulnerability score - 0.5| for the same item, model and defense. Flip rate: share of attacked prompts whose verdict differs from the clean verdict (both parsed). Conditional flip rate: the same, restricted to items whose clean verdict was correct.

## By model (all defenses and goals)

| Model | Clean margin | Flip rate | Conditional flip rate |
|---|---|---:|---:|
| `deepseek/deepseek-v4-pro` | [0.0, 0.1) | 0.333 (11/33) | 0.444 (8/18) |
| `deepseek/deepseek-v4-pro` | [0.1, 0.2) | 0.327 (49/150) | 0.422 (19/45) |
| `deepseek/deepseek-v4-pro` | [0.2, 0.3) | 0.333 (1/3) | 0.333 (1/3) |
| `deepseek/deepseek-v4-pro` | [0.3, 0.4) | 0.415 (153/369) | 0.554 (113/204) |
| `deepseek/deepseek-v4-pro` | [0.4, 0.5] | 0.273 (713/2613) | 0.351 (542/1545) |

## By model, defense and goal

| Model | Defense | Goal | Clean margin | Flip rate | Conditional flip rate |
|---|---|---|---|---:|---:|
| `deepseek/deepseek-v4-pro` | neutral | induction | [0.0, 0.1) | 0.667 (6/9) | 1.000 (6/6) |
| `deepseek/deepseek-v4-pro` | neutral | induction | [0.1, 0.2) | 0.190 (4/21) | 1.000 (3/3) |
| `deepseek/deepseek-v4-pro` | neutral | induction | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | neutral | induction | [0.3, 0.4) | 0.397 (25/63) | 0.852 (23/27) |
| `deepseek/deepseek-v4-pro` | neutral | induction | [0.4, 0.5] | 0.526 (229/435) | 0.793 (226/285) |
| `deepseek/deepseek-v4-pro` | neutral | suppression | [0.0, 0.1) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | neutral | suppression | [0.1, 0.2) | 0.476 (10/21) | 0.667 (10/15) |
| `deepseek/deepseek-v4-pro` | neutral | suppression | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | neutral | suppression | [0.3, 0.4) | 0.500 (30/60) | 0.562 (27/48) |
| `deepseek/deepseek-v4-pro` | neutral | suppression | [0.4, 0.5] | 0.300 (134/447) | 0.433 (100/231) |
| `deepseek/deepseek-v4-pro` | tagged | induction | [0.0, 0.1) | 0.333 (2/6) | 0.000 (0/3) |
| `deepseek/deepseek-v4-pro` | tagged | induction | [0.1, 0.2) | 0.370 (10/27) | 0.000 (0/3) |
| `deepseek/deepseek-v4-pro` | tagged | induction | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | tagged | induction | [0.3, 0.4) | 0.333 (21/63) | 0.407 (11/27) |
| `deepseek/deepseek-v4-pro` | tagged | induction | [0.4, 0.5] | 0.250 (108/432) | 0.248 (67/270) |
| `deepseek/deepseek-v4-pro` | tagged | suppression | [0.0, 0.1) | 0.000 (0/6) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | tagged | suppression | [0.1, 0.2) | 0.238 (5/21) | 0.278 (5/18) |
| `deepseek/deepseek-v4-pro` | tagged | suppression | [0.2, 0.3) | 0.333 (1/3) | 0.333 (1/3) |
| `deepseek/deepseek-v4-pro` | tagged | suppression | [0.3, 0.4) | 0.422 (19/45) | 0.424 (14/33) |
| `deepseek/deepseek-v4-pro` | tagged | suppression | [0.4, 0.5] | 0.157 (71/453) | 0.156 (37/237) |
| `deepseek/deepseek-v4-pro` | warning | induction | [0.0, 0.1) | 0.222 (2/9) | 0.167 (1/6) |
| `deepseek/deepseek-v4-pro` | warning | induction | [0.1, 0.2) | 0.436 (17/39) | 0.000 (0/3) |
| `deepseek/deepseek-v4-pro` | warning | induction | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | warning | induction | [0.3, 0.4) | 0.333 (30/90) | 0.407 (11/27) |
| `deepseek/deepseek-v4-pro` | warning | induction | [0.4, 0.5] | 0.215 (84/390) | 0.251 (64/255) |
| `deepseek/deepseek-v4-pro` | warning | suppression | [0.0, 0.1) | 0.333 (1/3) | 0.333 (1/3) |
| `deepseek/deepseek-v4-pro` | warning | suppression | [0.1, 0.2) | 0.143 (3/21) | 0.333 (1/3) |
| `deepseek/deepseek-v4-pro` | warning | suppression | [0.2, 0.3) | n/a (0/0) | n/a (0/0) |
| `deepseek/deepseek-v4-pro` | warning | suppression | [0.3, 0.4) | 0.583 (28/48) | 0.643 (27/42) |
| `deepseek/deepseek-v4-pro` | warning | suppression | [0.4, 0.5] | 0.191 (87/456) | 0.180 (48/267) |
