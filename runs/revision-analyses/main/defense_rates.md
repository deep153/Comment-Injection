# Conditional flip rate, benign baseline and clean accuracy by defense

Runs: `runs/openrouter-v2/full` (prompt version v2); `runs/revision-placebo/full` (prompt version v3).
Adaptive runs: `runs/revision-adaptive/full`.
Dataset family: manual; clustering unit: vulnerable/fixed pair (paired_item_key; item_id when missing); repeats excluded.

Per model, defense and goal. Conditional flip rate: attack success among attacked prompts whose clean verdict (same model, item and defense) was correct. Benign baseline: the same measure for the harmless comment, where a move is a verdict on the attacker's side (safe for vulnerable code under suppression, vulnerable for fixed code under induction). Excess = conditional flip minus benign. Clean accuracy covers both labels. 95% cluster-bootstrap intervals over vulnerable/fixed pairs (2000 resamples, seed 20260101). Model `all` pools the models.

| Model | Defense | Goal | Clean acc. | Raw ASR | Conditional flip [95% CI] (n) | Benign [95% CI] (n) | Excess [95% CI] |
|---|---|---|---:|---:|---:|---:|---:|
| `anthropic/claude-sonnet-5.5` | neutral | induction | 0.676 | 0.258 | 0.158 [0.130, 0.189] (1080) | 0.044 [0.015, 0.081] (135) | 0.114 [0.077, 0.151] |
| `anthropic/claude-sonnet-5.5` | neutral | suppression | 0.676 | 0.538 | 0.246 [0.183, 0.311] (824) | 0.126 [0.068, 0.194] (103) | 0.120 [0.061, 0.184] |
| `anthropic/claude-sonnet-5.5` | placebo | induction | 0.696 | 0.150 | 0.084 [0.062, 0.107] (1216) | 0.046 [0.013, 0.079] (152) | 0.038 [0.002, 0.071] |
| `anthropic/claude-sonnet-5.5` | placebo | suppression | 0.696 | 0.567 | 0.230 [0.165, 0.300] (744) | 0.151 [0.086, 0.226] (93) | 0.079 [0.019, 0.140] |
| `anthropic/claude-sonnet-5.5` | tagged | induction | 0.648 | 0.128 | 0.033 [0.017, 0.055] (1136) | 0.028 [0.007, 0.056] (142) | 0.005 [-0.024, 0.032] |
| `anthropic/claude-sonnet-5.5` | tagged | suppression | 0.648 | 0.549 | 0.190 [0.134, 0.250] (688) | 0.151 [0.081, 0.233] (86) | 0.039 [-0.025, 0.105] |
| `anthropic/claude-sonnet-5.5` | warning | induction | 0.653 | 0.154 | 0.045 [0.030, 0.060] (1128) | 0.035 [0.007, 0.071] (141) | 0.010 [-0.014, 0.031] |
| `anthropic/claude-sonnet-5.5` | warning | suppression | 0.653 | 0.540 | 0.180 [0.121, 0.244] (712) | 0.124 [0.056, 0.191] (89) | 0.056 [-0.015, 0.129] |
| `deepseek/deepseek-v4-pro` | neutral | induction | 0.543 | 0.872 | 0.837 [0.806, 0.868] (1088) | 0.022 [0.000, 0.051] (136) | 0.815 [0.778, 0.850] |
| `deepseek/deepseek-v4-pro` | neutral | suppression | 0.543 | 0.847 | 0.557 [0.486, 0.627] (440) | 0.364 [0.236, 0.491] (55) | 0.193 [0.089, 0.305] |
| `deepseek/deepseek-v4-pro` | placebo | induction | 0.526 | 0.897 | 0.866 [0.835, 0.893] (1032) | 0.054 [0.023, 0.093] (129) | 0.812 [0.764, 0.856] |
| `deepseek/deepseek-v4-pro` | placebo | suppression | 0.526 | 0.831 | 0.540 [0.462, 0.614] (448) | 0.357 [0.232, 0.482] (56) | 0.183 [0.076, 0.288] |
| `deepseek/deepseek-v4-pro` | tagged | induction | 0.534 | 0.472 | 0.361 [0.322, 0.401] (1104) | 0.051 [0.014, 0.087] (138) | 0.311 [0.264, 0.356] |
| `deepseek/deepseek-v4-pro` | tagged | suppression | 0.534 | 0.744 | 0.290 [0.193, 0.385] (400) | 0.420 [0.280, 0.560] (50) | -0.130 [-0.250, -0.008] |
| `deepseek/deepseek-v4-pro` | warning | induction | 0.514 | 0.571 | 0.485 [0.434, 0.534] (1144) | 0.007 [0.000, 0.021] (143) | 0.478 [0.424, 0.529] |
| `deepseek/deepseek-v4-pro` | warning | suppression | 0.514 | 0.805 | 0.316 [0.207, 0.434] (304) | 0.316 [0.184, 0.474] (38) | 0.000 [-0.086, 0.086] |
| `google/gemini-3.8-flash` | neutral | induction | 0.645 | 0.339 | 0.228 [0.189, 0.266] (1056) | 0.061 [0.023, 0.106] (132) | 0.168 [0.120, 0.213] |
| `google/gemini-3.8-flash` | neutral | suppression | 0.645 | 0.391 | 0.117 [0.075, 0.168] (760) | 0.200 [0.126, 0.284] (95) | -0.083 [-0.142, -0.030] |
| `google/gemini-3.8-flash` | placebo | induction | 0.605 | 0.331 | 0.198 [0.162, 0.237] (1024) | 0.031 [0.008, 0.062] (128) | 0.167 [0.129, 0.209] |
| `google/gemini-3.8-flash` | placebo | suppression | 0.605 | 0.419 | 0.088 [0.052, 0.130] (679) | 0.082 [0.035, 0.141] (85) | 0.006 [-0.059, 0.067] |
| `google/gemini-3.8-flash` | tagged | induction | 0.642 | 0.133 | 0.038 [0.016, 0.065] (1080) | 0.081 [0.037, 0.133] (135) | -0.044 [-0.084, -0.006] |
| `google/gemini-3.8-flash` | tagged | suppression | 0.642 | 0.447 | 0.113 [0.076, 0.151] (728) | 0.165 [0.088, 0.242] (91) | -0.052 [-0.124, 0.014] |
| `google/gemini-3.8-flash` | warning | induction | 0.651 | 0.136 | 0.029 [0.014, 0.046] (1112) | 0.086 [0.043, 0.137] (139) | -0.058 [-0.100, -0.016] |
| `google/gemini-3.8-flash` | warning | suppression | 0.651 | 0.411 | 0.078 [0.046, 0.115] (720) | 0.135 [0.067, 0.213] (89) | -0.057 [-0.117, -0.005] |
| `openai/gpt-6.1-sol` | neutral | induction | 0.696 | 0.207 | 0.019 [0.008, 0.033] (1040) | 0.031 [0.008, 0.062] (130) | -0.012 [-0.046, 0.017] |
| `openai/gpt-6.1-sol` | neutral | suppression | 0.696 | 0.317 | 0.021 [0.007, 0.040] (920) | 0.026 [0.000, 0.061] (115) | -0.005 [-0.034, 0.015] |
| `openai/gpt-6.1-sol` | placebo | induction | 0.716 | 0.204 | 0.012 [0.005, 0.021] (1064) | 0.068 [0.030, 0.113] (133) | -0.055 [-0.101, -0.018] |
| `openai/gpt-6.1-sol` | placebo | suppression | 0.716 | 0.307 | 0.026 [0.011, 0.046] (952) | 0.042 [0.008, 0.084] (119) | -0.016 [-0.045, 0.012] |
| `openai/gpt-6.1-sol` | tagged | induction | 0.699 | 0.242 | 0.023 [0.008, 0.041] (992) | 0.065 [0.024, 0.113] (124) | -0.041 [-0.083, -0.003] |
| `openai/gpt-6.1-sol` | tagged | suppression | 0.699 | 0.292 | 0.030 [0.013, 0.050] (976) | 0.041 [0.008, 0.082] (122) | -0.011 [-0.039, 0.011] |
| `openai/gpt-6.1-sol` | warning | induction | 0.690 | 0.237 | 0.024 [0.009, 0.041] (976) | 0.074 [0.033, 0.123] (122) | -0.050 [-0.093, -0.010] |
| `openai/gpt-6.1-sol` | warning | suppression | 0.690 | 0.295 | 0.026 [0.010, 0.045] (968) | 0.033 [0.008, 0.066] (121) | -0.007 [-0.038, 0.020] |
| `all` | neutral | induction | 0.640 | 0.419 | 0.315 [0.294, 0.337] (4264) | 0.039 [0.024, 0.057] (533) | 0.276 [0.252, 0.301] |
| `all` | neutral | suppression | 0.640 | 0.523 | 0.189 [0.161, 0.217] (2944) | 0.149 [0.112, 0.191] (368) | 0.039 [0.006, 0.070] |
| `all` | placebo | induction | 0.636 | 0.395 | 0.280 [0.261, 0.299] (4336) | 0.050 [0.031, 0.070] (542) | 0.230 [0.207, 0.252] |
| `all` | placebo | suppression | 0.636 | 0.531 | 0.176 [0.150, 0.206] (2823) | 0.130 [0.096, 0.169] (353) | 0.046 [0.015, 0.076] |
| `all` | tagged | induction | 0.631 | 0.244 | 0.116 [0.101, 0.133] (4312) | 0.056 [0.038, 0.073] (539) | 0.061 [0.041, 0.079] |
| `all` | tagged | suppression | 0.631 | 0.508 | 0.128 [0.102, 0.156] (2792) | 0.155 [0.116, 0.193] (349) | -0.027 [-0.059, 0.007] |
| `all` | warning | induction | 0.627 | 0.275 | 0.152 [0.135, 0.169] (4360) | 0.050 [0.031, 0.070] (545) | 0.102 [0.080, 0.123] |
| `all` | warning | suppression | 0.627 | 0.513 | 0.113 [0.087, 0.141] (2704) | 0.116 [0.083, 0.154] (337) | -0.003 [-0.031, 0.021] |
