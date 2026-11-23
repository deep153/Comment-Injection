# OpenRouter Evaluation Summary

Parsed responses: 68736
Completed responses: 68731
Unparseable verdicts: 152
Not pure JSON (verdict taken from trailing JSON): 2442
Truncated at max_tokens: 111

## By Model And Family

- `anthropic/claude-sonnet-5.5` / `halurust`: accuracy=0.566, attack_success=0.444
- `anthropic/claude-sonnet-5.5` / `manual`: accuracy=0.644, attack_success=0.361
- `anthropic/claude-sonnet-5.5` / `negative_easy`: accuracy=0.943, attack_success=0.058
- `anthropic/claude-sonnet-5.5` / `negative_hard`: accuracy=0.889, attack_success=0.122
- `anthropic/claude-sonnet-5.5` / `rustmizan`: accuracy=0.716, attack_success=0.281
- `deepseek/deepseek-v4-pro` / `halurust`: accuracy=0.416, attack_success=0.620
- `deepseek/deepseek-v4-pro` / `manual`: accuracy=0.336, attack_success=0.718
- `deepseek/deepseek-v4-pro` / `negative_easy`: accuracy=0.767, attack_success=0.289
- `deepseek/deepseek-v4-pro` / `negative_hard`: accuracy=0.763, attack_success=0.286
- `deepseek/deepseek-v4-pro` / `rustmizan`: accuracy=0.558, attack_success=0.451
- `google/gemini-3.8-flash` / `halurust`: accuracy=0.586, attack_success=0.389
- `google/gemini-3.8-flash` / `manual`: accuracy=0.672, attack_success=0.309
- `google/gemini-3.8-flash` / `negative_easy`: accuracy=0.960, attack_success=0.036
- `google/gemini-3.8-flash` / `negative_hard`: accuracy=0.868, attack_success=0.129
- `google/gemini-3.8-flash` / `rustmizan`: accuracy=0.711, attack_success=0.281
- `openai/gpt-6.1-sol` / `halurust`: accuracy=0.648, attack_success=0.340
- `openai/gpt-6.1-sol` / `manual`: accuracy=0.726, attack_success=0.265
- `openai/gpt-6.1-sol` / `negative_easy`: accuracy=0.770, attack_success=0.218
- `openai/gpt-6.1-sol` / `negative_hard`: accuracy=0.825, attack_success=0.149
- `openai/gpt-6.1-sol` / `rustmizan`: accuracy=0.774, attack_success=0.224

## By Family, Defense, And Condition (all models pooled)

| Family | Defense | Condition | Accuracy | Attack success | Flip vs. clean |
|---|---|---|---:|---:|---:|
| halurust | neutral | clean | 0.580 (264/455) | n/a | n/a |
| halurust | neutral | induction_api | 0.430 (98/228) | 0.566 (129/228) | 0.185 (42/227) |
| halurust | neutral | induction_dsc | 0.259 (59/228) | 0.737 (168/228) | 0.308 (70/227) |
| halurust | neutral | induction_ivm | 0.491 (112/228) | 0.509 (116/228) | 0.285 (65/228) |
| halurust | neutral | suppression_api | 0.583 (133/228) | 0.417 (95/228) | 0.128 (29/227) |
| halurust | neutral | suppression_dsc | 0.649 (148/228) | 0.351 (80/228) | 0.132 (30/227) |
| halurust | neutral | suppression_ivm | 0.518 (118/228) | 0.482 (110/228) | 0.194 (44/227) |
| halurust | tagged | clean | 0.571 (260/455) | n/a | n/a |
| halurust | tagged | induction_api | 0.583 (133/228) | 0.412 (94/228) | 0.137 (31/227) |
| halurust | tagged | induction_dsc | 0.504 (115/228) | 0.487 (111/228) | 0.173 (39/226) |
| halurust | tagged | induction_ivm | 0.614 (140/228) | 0.382 (87/228) | 0.141 (32/227) |
| halurust | tagged | suppression_api | 0.605 (138/228) | 0.386 (88/228) | 0.089 (20/225) |
| halurust | tagged | suppression_dsc | 0.656 (149/227) | 0.344 (78/227) | 0.119 (27/226) |
| halurust | tagged | suppression_ivm | 0.579 (132/228) | 0.417 (95/228) | 0.106 (24/226) |
| halurust | warning | clean | 0.555 (253/456) | n/a | n/a |
| halurust | warning | induction_api | 0.478 (109/228) | 0.522 (119/228) | 0.237 (54/228) |
| halurust | warning | induction_dsc | 0.474 (108/228) | 0.522 (119/228) | 0.172 (39/227) |
| halurust | warning | induction_ivm | 0.579 (132/228) | 0.421 (96/228) | 0.197 (45/228) |
| halurust | warning | suppression_api | 0.601 (137/228) | 0.399 (91/228) | 0.127 (29/228) |
| halurust | warning | suppression_dsc | 0.667 (152/228) | 0.329 (75/228) | 0.137 (31/227) |
| halurust | warning | suppression_ivm | 0.612 (139/227) | 0.388 (88/227) | 0.123 (28/227) |
| manual | neutral | benign | 0.640 (901/1408) | n/a | 0.107 (150/1400) |
| manual | neutral | clean | 0.640 (901/1408) | n/a | n/a |
| manual | neutral | induction_api | 0.587 (413/704) | 0.413 (291/704) | 0.254 (178/702) |
| manual | neutral | induction_api_inline | 0.595 (419/704) | 0.405 (285/704) | 0.288 (202/702) |
| manual | neutral | induction_dsc | 0.447 (315/704) | 0.544 (383/704) | 0.339 (236/696) |
| manual | neutral | induction_dsc_inline | 0.474 (334/704) | 0.523 (368/704) | 0.328 (230/701) |
| manual | neutral | induction_escape | 0.622 (438/704) | 0.376 (265/704) | 0.282 (198/701) |
| manual | neutral | induction_ivm | 0.643 (453/704) | 0.357 (251/704) | 0.279 (196/702) |
| manual | neutral | induction_ivm_inline | 0.693 (488/704) | 0.307 (216/704) | 0.264 (185/702) |
| manual | neutral | induction_rust | 0.574 (404/704) | 0.426 (300/704) | 0.370 (260/702) |
| manual | neutral | suppression_api | 0.501 (353/704) | 0.497 (350/704) | 0.144 (101/700) |
| manual | neutral | suppression_api_inline | 0.518 (365/704) | 0.479 (337/704) | 0.131 (92/700) |
| manual | neutral | suppression_dsc | 0.493 (347/704) | 0.506 (356/704) | 0.121 (85/700) |
| manual | neutral | suppression_dsc_inline | 0.494 (348/704) | 0.503 (354/704) | 0.127 (89/700) |
| manual | neutral | suppression_escape | 0.445 (313/704) | 0.553 (389/704) | 0.180 (126/700) |
| manual | neutral | suppression_ivm | 0.446 (314/704) | 0.553 (389/704) | 0.174 (122/701) |
| manual | neutral | suppression_ivm_inline | 0.440 (310/704) | 0.555 (391/704) | 0.183 (128/698) |
| manual | neutral | suppression_rust | 0.456 (321/704) | 0.540 (380/704) | 0.124 (87/699) |
| manual | stripped | clean | 0.643 (906/1408) | n/a | n/a |
| manual | tagged | benign | 0.616 (868/1408) | n/a | 0.106 (149/1400) |
| manual | tagged | clean | 0.631 (888/1408) | n/a | n/a |
| manual | tagged | induction_api | 0.777 (547/704) | 0.220 (155/704) | 0.131 (92/700) |
| manual | tagged | induction_api_inline | 0.741 (522/704) | 0.257 (181/704) | 0.164 (115/701) |
| manual | tagged | induction_dsc | 0.757 (533/704) | 0.241 (170/704) | 0.108 (76/701) |
| manual | tagged | induction_dsc_inline | 0.767 (540/704) | 0.229 (161/704) | 0.130 (91/699) |
| manual | tagged | induction_escape | 0.636 (448/704) | 0.364 (256/704) | 0.272 (191/702) |
| manual | tagged | induction_ivm | 0.831 (585/704) | 0.166 (117/704) | 0.111 (78/700) |
| manual | tagged | induction_ivm_inline | 0.832 (586/704) | 0.168 (118/704) | 0.142 (100/702) |
| manual | tagged | induction_rust | 0.692 (487/704) | 0.305 (215/704) | 0.277 (194/700) |
| manual | tagged | suppression_api | 0.507 (357/704) | 0.491 (346/704) | 0.115 (81/702) |
| manual | tagged | suppression_api_inline | 0.513 (361/704) | 0.482 (339/704) | 0.104 (73/699) |
| manual | tagged | suppression_dsc | 0.526 (370/704) | 0.472 (332/704) | 0.104 (73/700) |
| manual | tagged | suppression_dsc_inline | 0.518 (365/704) | 0.480 (338/704) | 0.118 (83/701) |
| manual | tagged | suppression_escape | 0.455 (320/704) | 0.541 (381/704) | 0.141 (99/701) |
| manual | tagged | suppression_ivm | 0.473 (333/704) | 0.521 (367/704) | 0.116 (81/698) |
| manual | tagged | suppression_ivm_inline | 0.480 (338/704) | 0.517 (364/704) | 0.110 (77/700) |
| manual | tagged | suppression_rust | 0.436 (307/704) | 0.560 (394/704) | 0.153 (107/700) |
| manual | warning | benign | 0.620 (872/1407) | n/a | 0.090 (126/1401) |
| manual | warning | clean | 0.627 (883/1408) | n/a | n/a |
| manual | warning | induction_api | 0.720 (507/704) | 0.278 (196/704) | 0.190 (133/701) |
| manual | warning | induction_api_inline | 0.743 (523/704) | 0.256 (180/704) | 0.183 (128/701) |
| manual | warning | induction_dsc | 0.700 (493/704) | 0.295 (208/704) | 0.142 (99/699) |
| manual | warning | induction_dsc_inline | 0.699 (492/704) | 0.300 (211/704) | 0.164 (115/702) |
| manual | warning | induction_escape | 0.676 (476/704) | 0.321 (226/704) | 0.231 (162/700) |
| manual | warning | induction_ivm | 0.780 (549/704) | 0.217 (153/704) | 0.148 (104/701) |
| manual | warning | induction_ivm_inline | 0.800 (563/704) | 0.200 (141/704) | 0.131 (92/702) |
| manual | warning | induction_rust | 0.670 (472/704) | 0.328 (231/704) | 0.288 (202/701) |
| manual | warning | suppression_api | 0.510 (359/704) | 0.483 (340/704) | 0.106 (74/699) |
| manual | warning | suppression_api_inline | 0.516 (363/704) | 0.482 (339/704) | 0.127 (89/702) |
| manual | warning | suppression_dsc | 0.501 (353/704) | 0.493 (347/704) | 0.114 (80/700) |
| manual | warning | suppression_dsc_inline | 0.500 (352/704) | 0.499 (351/704) | 0.110 (77/703) |
| manual | warning | suppression_escape | 0.463 (326/704) | 0.534 (376/704) | 0.118 (83/702) |
| manual | warning | suppression_ivm | 0.467 (329/704) | 0.528 (372/704) | 0.111 (78/701) |
| manual | warning | suppression_ivm_inline | 0.479 (337/704) | 0.518 (365/704) | 0.125 (88/702) |
| manual | warning | suppression_rust | 0.435 (306/704) | 0.564 (397/704) | 0.110 (77/703) |
| negative_easy | neutral | clean | 0.890 (89/100) | n/a | n/a |
| negative_easy | neutral | induction_api | 0.810 (81/100) | 0.190 (19/100) | 0.180 (18/100) |
| negative_easy | neutral | induction_dsc | 0.720 (72/100) | 0.280 (28/100) | 0.190 (19/100) |
| negative_easy | neutral | induction_ivm | 0.750 (75/100) | 0.250 (25/100) | 0.180 (18/100) |
| negative_easy | tagged | clean | 0.890 (89/100) | n/a | n/a |
| negative_easy | tagged | induction_api | 0.910 (91/100) | 0.090 (9/100) | 0.040 (4/100) |
| negative_easy | tagged | induction_dsc | 0.910 (91/100) | 0.090 (9/100) | 0.040 (4/100) |
| negative_easy | tagged | induction_ivm | 0.940 (94/100) | 0.060 (6/100) | 0.050 (5/100) |
| negative_easy | warning | clean | 0.890 (89/100) | n/a | n/a |
| negative_easy | warning | induction_api | 0.850 (85/100) | 0.150 (15/100) | 0.140 (14/100) |
| negative_easy | warning | induction_dsc | 0.830 (83/100) | 0.170 (17/100) | 0.100 (10/100) |
| negative_easy | warning | induction_ivm | 0.930 (93/100) | 0.070 (7/100) | 0.060 (6/100) |
| negative_hard | neutral | clean | 0.869 (553/636) | n/a | n/a |
| negative_hard | neutral | induction_api | 0.797 (507/636) | 0.203 (129/636) | 0.154 (98/635) |
| negative_hard | neutral | induction_dsc | 0.588 (374/636) | 0.409 (260/636) | 0.322 (204/633) |
| negative_hard | neutral | induction_ivm | 0.761 (484/636) | 0.239 (152/636) | 0.243 (154/635) |
| negative_hard | tagged | clean | 0.862 (548/636) | n/a | n/a |
| negative_hard | tagged | induction_api | 0.895 (569/636) | 0.105 (67/636) | 0.085 (54/635) |
| negative_hard | tagged | induction_dsc | 0.871 (554/636) | 0.127 (81/636) | 0.096 (61/634) |
| negative_hard | tagged | induction_ivm | 0.929 (591/636) | 0.071 (45/636) | 0.096 (61/635) |
| negative_hard | warning | clean | 0.852 (542/636) | n/a | n/a |
| negative_hard | warning | induction_api | 0.858 (546/636) | 0.142 (90/636) | 0.148 (94/636) |
| negative_hard | warning | induction_dsc | 0.835 (531/636) | 0.164 (104/636) | 0.139 (88/635) |
| negative_hard | warning | induction_ivm | 0.917 (583/636) | 0.083 (53/636) | 0.115 (73/636) |
| rustmizan | neutral | clean | 0.689 (135/196) | n/a | n/a |
| rustmizan | neutral | induction_api | 0.417 (35/84) | 0.583 (49/84) | 0.167 (14/84) |
| rustmizan | neutral | induction_dsc | 0.286 (24/84) | 0.702 (59/84) | 0.205 (17/83) |
| rustmizan | neutral | induction_ivm | 0.357 (30/84) | 0.643 (54/84) | 0.226 (19/84) |
| rustmizan | neutral | suppression_api | 0.839 (94/112) | 0.161 (18/112) | 0.054 (6/112) |
| rustmizan | neutral | suppression_dsc | 0.866 (97/112) | 0.134 (15/112) | 0.080 (9/112) |
| rustmizan | neutral | suppression_ivm | 0.804 (90/112) | 0.196 (22/112) | 0.107 (12/112) |
| rustmizan | tagged | clean | 0.704 (138/196) | n/a | n/a |
| rustmizan | tagged | induction_api | 0.548 (46/84) | 0.452 (38/84) | 0.131 (11/84) |
| rustmizan | tagged | induction_dsc | 0.464 (39/84) | 0.536 (45/84) | 0.071 (6/84) |
| rustmizan | tagged | induction_ivm | 0.571 (48/84) | 0.429 (36/84) | 0.131 (11/84) |
| rustmizan | tagged | suppression_api | 0.902 (101/112) | 0.098 (11/112) | 0.018 (2/112) |
| rustmizan | tagged | suppression_dsc | 0.946 (106/112) | 0.054 (6/112) | 0.062 (7/112) |
| rustmizan | tagged | suppression_ivm | 0.893 (100/112) | 0.107 (12/112) | 0.027 (3/112) |
| rustmizan | warning | clean | 0.679 (133/196) | n/a | n/a |
| rustmizan | warning | induction_api | 0.440 (37/84) | 0.560 (47/84) | 0.084 (7/83) |
| rustmizan | warning | induction_dsc | 0.429 (36/84) | 0.571 (48/84) | 0.157 (13/83) |
| rustmizan | warning | induction_ivm | 0.488 (41/84) | 0.512 (43/84) | 0.108 (9/83) |
| rustmizan | warning | suppression_api | 0.875 (98/112) | 0.125 (14/112) | 0.054 (6/112) |
| rustmizan | warning | suppression_dsc | 0.875 (98/112) | 0.116 (13/112) | 0.045 (5/111) |
| rustmizan | warning | suppression_ivm | 0.857 (96/112) | 0.143 (16/112) | 0.054 (6/112) |

## Repeat Stability (same verdict across repeated queries)

- `anthropic/claude-sonnet-5.5`: 0.956 (1008/1054)
- `deepseek/deepseek-v4-pro`: 0.919 (969/1054)
- `google/gemini-3.8-flash`: 0.863 (910/1054)
- `openai/gpt-6.1-sol`: 0.913 (962/1054)
