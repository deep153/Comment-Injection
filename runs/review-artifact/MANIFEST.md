# Anonymized review artifact

Prompt version v3. Produced by `python3 -m openrouter_eval.export_review_artifact`.

## Contents

- `code/`: the `openrouter_eval` harness package (see `code/openrouter_eval/README.md`).
- `prompts/`: rendered detector system prompts for every defense (`neutral`, `warning`, `tagged`, `placebo`, `stripped`), the user template, the default adaptive attacker system prompts and `templates.json` with every attack template and the conditions of the core and extended designs.
- `adaptive/`: adaptive-attack logs: `runs/revision-adaptive/full`.
- `results/`: aggregate tables from `runs/revision-analyses/main`, `runs/revision-analyses/deepseek-minimal`, `runs/revision-analyses/cost-new-runs`, `runs/openrouter-v2/full`, `runs/revision-placebo/full`, `runs/revision-neutral-reanchor/full`, `runs/revision-deepseek-minimal/full`.

## Scrub rules

- Adaptive `steps.jsonl` rows keep only: `request_id`, `task_id`, `step`, `role`, `attempt`, `ok`, `cost`, `attacker_output`, `candidate`, `verdict`, `confidence`, `rationale`, `correct`, `attack_success`. The `request` object keeps only: `request_id`, `role`, `task_id`, `step`, `model_key`, `model`, `messages`, `temperature`, `max_tokens`, `response_format`, `reasoning`, `variant_id`, `attacker_mode`, `repeat`, `defense`, `attack_family`, `attack_goal`, `placement`, `prompt_version`, `prompt_sha256`, `transformed_sha256`, `item_id`, `dataset_family`, `sample_role`, `case_id`, `pair_id`, `paired_item_key`, `package`, `label`, `source_path`. The `response` object is rebuilt as `ok`, `status`, `content` (the answer text), `finish_reason` and `usage` (`prompt_tokens`, `completion_tokens`, `total_tokens`, `reasoning_tokens`). Everything else is dropped, including raw provider payloads, generation ids, `provider` routing and provider names, service tiers, `is_byok` and upstream cost details, timestamps, latency and provider error bodies. `cost` is the total USD of the call.
- Adaptive `outcomes.jsonl` rows keep only: `task_id`, `item_id`, `dataset_family`, `sample_role`, `case_id`, `pair_id`, `paired_item_key`, `package`, `label`, `source_path`, `model_key`, `model`, `defense`, `attack_family`, `attack_goal`, `variant_id`, `attacker_mode`, `feedback_mode`, `attacker_model`, `prompt_version`, `query_budget`, `queries_used`, `detector_queries`, `rejected_candidates`, `attack_success`, `first_success_step`, `final_comment`, `final_placement`, `verdict`, `confidence`, `correct`, `clean_verdict`, `clean_confidence`.
- `run_config.json` files drop these keys at any depth: `allow_byok_fallback`, `byok_only`, `passes`, `provider`.
- In every exported file, absolute local paths are rewritten to `runs/...` or `rust-vuln-dataset/...` (other local paths become `<local-path>`), key-like strings and generation ids are redacted, and identifying terms are replaced with `anonymous`.
- After writing, every file is scanned for absolute local paths, key-like strings, generation ids and the identifying terms; the export fails if any remain.

## Files

| File | Source | Bytes | SHA-256 |
|---|---|---:|---|
| `adaptive/runs/revision-adaptive/full/outcomes.jsonl` | runs/revision-adaptive/full (provider metadata removed) | 1161055 | `d74de4531ce1b4a9d8c08c467933f2e4f782718a418c91b30b2807ecbc2ea96f` |
| `adaptive/runs/revision-adaptive/full/run_config.json` | runs/revision-adaptive/full (provider metadata removed) | 6196 | `bc4c9f4994ac60e0b47287b167ed742a1fded4754b872ea060d13a44199fa116` |
| `adaptive/runs/revision-adaptive/full/steps.jsonl` | runs/revision-adaptive/full (provider metadata removed) | 24248504 | `521d549c41e9ead5ea86e64247c1908bfb2a2f7a61874953762507ce1e2407a2` |
| `code/openrouter_eval/README.md` | harness code | 37842 | `1083f5bf2db905d7bd3208ed10f87bdd5e85179ad0041bb572db27da7f2c6f54` |
| `code/openrouter_eval/__init__.py` | harness code | 69 | `02b28b271d243b6d938f7c7b39eed239989497a31fef19a29715ccd47b746d5e` |
| `code/openrouter_eval/adaptive_attack.py` | harness code | 29159 | `c40d4d6c0bd86c98bc5cfe81268ab849bedab00c54165ef484b390834cecd944` |
| `code/openrouter_eval/analyze_gee.py` | harness code | 3902 | `7ede8b0992adef5f124635d963988faa0ae72df6e06ac61ec5b44091c1f1518b` |
| `code/openrouter_eval/build_manifest.py` | harness code | 8419 | `b031a162fc926a8af4ab75319ab098e9e28a1d5814373a1e72afa7ba3d1d1e24` |
| `code/openrouter_eval/common.py` | harness code | 2628 | `865438648f5e36b045781e17c16a08657339cff2d883dcfdef47159e79c12e28` |
| `code/openrouter_eval/export_review_artifact.py` | harness code | 17869 | `a8b4a97dda698472f3526da2fbb6ece340d49a484e78794fe462b62c63865cd1` |
| `code/openrouter_eval/prompts.py` | harness code | 10996 | `67db5b7ccf88e65610317a60822aa3d150559b2004e8ac75b1947b52974f4c3c` |
| `code/openrouter_eval/reconcile_requests.py` | harness code | 2920 | `2f920212fd0f2b462cd187ec141dd3013aabaf71536eb671c4ae28078d4d4587` |
| `code/openrouter_eval/revision/__init__.py` | harness code | 73 | `90c92f3cef9e09d39f15a2c2b476bd7f586dcb784e53b74d687b9859c0a1fa2d` |
| `code/openrouter_eval/revision/__main__.py` | harness code | 97 | `bbcd327f6aceff0ebf32ec8e7e8d92112efdbbf17ab50522c05c0c7b12a91854` |
| `code/openrouter_eval/revision/analyses/__init__.py` | harness code | 741 | `d4eaf6a6f3d604c5ee151fa348f591843657b0b5b6faffa220cb48c438ccaa8d` |
| `code/openrouter_eval/revision/analyses/adaptive_summary.py` | harness code | 5502 | `187b0f826d0bea1acb9de8ae509f932a61d3df813fd228265cabb4785a4053a5` |
| `code/openrouter_eval/revision/analyses/calibration.py` | harness code | 3633 | `e7346ca60a65f48c6f6d905286d3abf96da4f1a84633929fbba1cc15e5e3bb0f` |
| `code/openrouter_eval/revision/analyses/cost_report.py` | harness code | 4967 | `f09e1a909ee7f1e7b2b8e4fde9a45a7828e537143fd25cb45ad1caa2e9918a38` |
| `code/openrouter_eval/revision/analyses/defense_contrasts.py` | harness code | 6009 | `7429d9467e7d0449fe0a1ddb51bb402c5b1571d053881fce42c6a1cc9a6cced7` |
| `code/openrouter_eval/revision/analyses/defense_gee.py` | harness code | 9507 | `2c304b18fc6b9a6ce78cfb1b71952fa9596db0eda05eee33d6633f588fa76677` |
| `code/openrouter_eval/revision/analyses/defense_rates.py` | harness code | 5452 | `4c06b5bc5da241012685e56a275e79a9e6a3f45048e6bb4d19b0eaef14c9fa30` |
| `code/openrouter_eval/revision/analyses/margin_bins.py` | harness code | 3587 | `4bfef7ab342a8675c76c67250b840a85423511c08e76e10bc69b0f0439f3486d` |
| `code/openrouter_eval/revision/analyses/memorization.py` | harness code | 9457 | `c375312d0046dc383c2a310d15d07f1b8bf4edef53da364ec45fad6743e57e29` |
| `code/openrouter_eval/revision/analyses/provider_drift.py` | harness code | 4902 | `f1be5faea72f0ccb9b5a0e93bedcb1c09345db3ba728ab800b8dfff1899541b8` |
| `code/openrouter_eval/revision/analyses/rationales.py` | harness code | 9021 | `fa405d5397e4e6beccc8e4b3d1713bef3de163b76a10c6444980393167d1a0c4` |
| `code/openrouter_eval/revision/analyses/score_shift.py` | harness code | 3150 | `ec6e458fb93ba18307ad00d7dff7b625e3bad98b327789bb23cc49b9d498d584` |
| `code/openrouter_eval/revision/analyses/stripping_tost.py` | harness code | 3473 | `a6fa8d92aec31b327e5815a0607235b453be73b14a47b18f576298aba918fb11` |
| `code/openrouter_eval/revision/base.py` | harness code | 569 | `8b3b38fa4dcc445992a46714c0089db0b13601cd4c4b3117414848290c4ac039` |
| `code/openrouter_eval/revision/cli.py` | harness code | 4527 | `d610b46d0f7c8640d5de6ebdefaa542f6aaf51178047b7d4609bd3fc3303b098` |
| `code/openrouter_eval/revision/inference.py` | harness code | 1953 | `ce6cb8832fcd5754944f562a887aa8dba22aca3496030b56ab7c0bb8caee75a0` |
| `code/openrouter_eval/revision/runs.py` | harness code | 6373 | `0280ed4e12f8aa3b3805be3afee14b0ea655b41a698fc777705b17fd84e2225b` |
| `code/openrouter_eval/revision/stats.py` | harness code | 2451 | `c7c3644d29a47a3e4d650bf1ab6a3eb3f1cd7390d37af430e44f99af36511d11` |
| `code/openrouter_eval/run_openrouter.py` | harness code | 23054 | `aa79a1d8a2a498669d982479b329a52fda1fbeb75109bafa9c349f00e70eaa33` |
| `code/openrouter_eval/score_results.py` | harness code | 14200 | `9a1ad98d451fc898b2707f7ae8b4b8131fa95c05fe2af3a7071e1baa194273db` |
| `code/openrouter_eval/summarize_manifest.py` | harness code | 2369 | `1e5b5797618a73f4bba4afd6fb2dfff80abb8669f522b96454e1f9077be86392` |
| `code/pytest.ini` | harness code | 42 | `6c6ccf864e8f2d2e0223ee8e39bfde660c12435aa37d81e2b14000a6bee15003` |
| `code/tests/conftest.py` | harness code | 1585 | `407171196d36b956ce18792aa5020801adad543b03b6320989426de2e54f675d` |
| `code/tests/fixtures/v2_requests_sample.jsonl` | harness code | 26787 | `3a1534baa7fb75cc15b59fb7063a358375fc5c58f35595aac9ab129cafd48e14` |
| `code/tests/fixtures/v2_response_usage_rows.jsonl` | harness code | 3690 | `5bf2cfb002ef154113cfbe80c36b3e30d910fbfe960d90b8d4fc02c7e57411ce` |
| `code/tests/test_adaptive_attack.py` | harness code | 23083 | `489392fbf00ac13a8da9ed2caacb2ad91c2f3705e4fd2e19d69e13e5b0c8b8ff` |
| `code/tests/test_adaptive_summary.py` | harness code | 7685 | `97507294bca0199d5328578f43f1b3ef21f1ff3b8b54925a8b976e6d63a6f3f2` |
| `code/tests/test_cost_report.py` | harness code | 8624 | `52f49459ab0b650b1fa67b71929cf7cc4f263478a5b286740a0fa35124cb9949` |
| `code/tests/test_export_review_artifact.py` | harness code | 12077 | `32a6804b99b152397a968d0e1ccfcfd6de87c85df260b2543614161897cb6f35` |
| `code/tests/test_inference_contrasts.py` | harness code | 8502 | `39b2bb7c9ebebba19a7254be636a0916e019c2ce0cc106a140a703835539f857` |
| `code/tests/test_inference_gee.py` | harness code | 5063 | `a1cf4b010dcb7bc44e7228c3aed09075f12dc9ba8ef4c8983980394681b42f6a` |
| `code/tests/test_inference_tost.py` | harness code | 4519 | `d036b6e9d682b6be8f7fba11cb87ef2d86d320e114391994b4ae13c6c20132e3` |
| `code/tests/test_placebo_defense.py` | harness code | 6474 | `51adfba491c1e77cda5ba75c537a1f29ca8bc9c1a552e6fa83a690206ddbe95c` |
| `code/tests/test_post_cutoff_manifest.py` | harness code | 4557 | `d0c4eb2de5bce8f0aa17a5b0fba9699cb88888a6fd5d1c366adce6e210f5cb97` |
| `code/tests/test_provider_drift.py` | harness code | 1597 | `7d22ae559b96a4d49e4fcfbfb46690c67f6b8af93fac62ec0de4f2ff62524247` |
| `code/tests/test_rationale_memorization.py` | harness code | 12656 | `3d0e11d37925f26d4249cf7ec043082f550befdeedbddbabd2f5275ee7bbbfff` |
| `code/tests/test_reanchor_drift.py` | harness code | 4525 | `905656c40a9dfd0307b4993b851379cbce95bead55671bd19ed3584dc1c6e0f4` |
| `code/tests/test_reasoning_settings.py` | harness code | 6680 | `c2b25f86a148a35ebd444e0a67cec0a10a28ab78bde7d8ff8f3d2d20e80d7e7a` |
| `code/tests/test_reconcile_requests.py` | harness code | 3069 | `290f1ebd2e01182ec81da5b646e99b82c9b84d868637110243da76cbb43d8300` |
| `code/tests/test_revision_foundation.py` | harness code | 9674 | `333d121b10283fa45a1b4377a6dcf33e9fd5a787432675b02fa487a991da96c5` |
| `code/tests/test_spending_guard.py` | harness code | 6002 | `fd2e0af420261af3dda50a66f16604a27f7dc1d513430f64ca94f9886b983463` |
| `prompts/attacker/blind.txt` | adaptive_attack.py defaults | 1144 | `7fd813924bc168335c9510f7a5444f2981917e3775f2eec6470cf9429c4d6d57` |
| `prompts/attacker/tag_aware.txt` | adaptive_attack.py defaults | 1561 | `cb28da07b9edcd6e41749318c58a770f353beecd31cfca925db6aa70188b1646` |
| `prompts/system/neutral.txt` | prompts.py | 356 | `b545520e1d35cf7d51f4b2c60d277f62c8a9187cf1660ba8b6ba19b9c9c07017` |
| `prompts/system/placebo.txt` | prompts.py | 615 | `978b539f2e73e3916812cd214e8611ac478be1a8e0707866cc51dd264a4429c1` |
| `prompts/system/stripped.txt` | prompts.py | 356 | `b545520e1d35cf7d51f4b2c60d277f62c8a9187cf1660ba8b6ba19b9c9c07017` |
| `prompts/system/tagged.txt` | prompts.py | 631 | `f7f0fec1163b937e61c988c6aa91dcb48e42d86d268e23bc88f67e5244b0c41b` |
| `prompts/system/warning.txt` | prompts.py | 600 | `a9ea61159838f710da0e24ab43fb84eb6775983eca33d4704739e562c14ad43c` |
| `prompts/templates.json` | prompts.py | 6444 | `511f3a03048c1ef6366a1befd6412d1312ec4f1e752abce624d4a59f5ba429d7` |
| `prompts/user_template.txt` | prompts.py | 48 | `a8a7f01977800daeb73ab87025ce11d4a30b3da27ec5e783184b435829ee02db` |
| `results/runs/openrouter-v2/full/gee_manual.json` | runs/openrouter-v2/full | 2635 | `9e1d307e3e91b90683d1ee7a0aa19130196178da6b10891a6ec6b2945422fa89` |
| `results/runs/openrouter-v2/full/gee_manual.md` | runs/openrouter-v2/full | 1041 | `3d5e29d60ecd3f3141759b1c04db0dd1b0528510cf23fd61e18565c799161ee8` |
| `results/runs/openrouter-v2/full/gee_manual_interaction.json` | runs/openrouter-v2/full | 3183 | `fc080e9957c42e4f2ac1a2608ead30171cd194d82887614f49442d00d5342199` |
| `results/runs/openrouter-v2/full/gee_manual_interaction.md` | runs/openrouter-v2/full | 1292 | `bdf7947857e07a6c467c1537e6124700695a583f561bf0edde96fc6059c98289` |
| `results/runs/openrouter-v2/full/run_config.json` | runs/openrouter-v2/full (routing settings removed) | 615 | `fc3c4c567744b394cc96c67b8277d69e0fcf034bf6255ab24b795c1ba97b3be7` |
| `results/runs/openrouter-v2/full/scores.json` | runs/openrouter-v2/full | 495049 | `a6bb44c004b4f55c27ef4fa88deacb16508e7795283f1276f18aa7917242d9eb` |
| `results/runs/openrouter-v2/full/summary.md` | runs/openrouter-v2/full | 12971 | `4ce882e2b45b4786b5b166ab81cea1cc0572acaeccc763bfe11c9908483ca94a` |
| `results/runs/revision-analyses/cost-new-runs/cost_report.json` | runs/revision-analyses/cost-new-runs | 7277 | `76630e79375bc8c8b6d7e7d2ddea80dffd935270ccab2bb6f4a6d40350ededd7` |
| `results/runs/revision-analyses/cost-new-runs/cost_report.md` | runs/revision-analyses/cost-new-runs | 3626 | `1b18c0b2b08a8db99bd2bf2f199ce8e9c3b181171ccdf8a11d227fe1bec74014` |
| `results/runs/revision-analyses/deepseek-minimal/calibration.json` | runs/revision-analyses/deepseek-minimal | 4433 | `df637c7fdc4649f09d35bcd361c28fe6ccc5723d9ae98891407c0cbb4c3b32f7` |
| `results/runs/revision-analyses/deepseek-minimal/calibration.md` | runs/revision-analyses/deepseek-minimal | 1410 | `2ba119fdfcdb769491da21d90a7c5809b94030aa0f0cf82a1264625c108286eb` |
| `results/runs/revision-analyses/deepseek-minimal/cost_report.json` | runs/revision-analyses/deepseek-minimal | 1389 | `0d621dabbb61796993e524e685ea9c5eedd24b31873ba7ded0c685936814e6ed` |
| `results/runs/revision-analyses/deepseek-minimal/cost_report.md` | runs/revision-analyses/deepseek-minimal | 1247 | `96c350baba2630df31cd99a9af8e3943797e8d8cf857ce70c3ce5d77945bf632` |
| `results/runs/revision-analyses/deepseek-minimal/defense_contrasts.json` | runs/revision-analyses/deepseek-minimal | 11706 | `16086b2af31daaa219fb73d756c59438879eb929e8dcff06f3c30c4aea5b2a90` |
| `results/runs/revision-analyses/deepseek-minimal/defense_contrasts.md` | runs/revision-analyses/deepseek-minimal | 3685 | `4750916998e18c4cbae5bdc49f328709cd18772426b406b3ab063db0930cd945` |
| `results/runs/revision-analyses/deepseek-minimal/defense_gee.json` | runs/revision-analyses/deepseek-minimal | 11843 | `e0b7a0b98c1bd4fc0c736a3433e9b6be25265191e72cc5243470bd4af0aefd86` |
| `results/runs/revision-analyses/deepseek-minimal/defense_gee.md` | runs/revision-analyses/deepseek-minimal | 2608 | `0b4afdd74be460ef197e412e2ea0b28102343d90b785a7814ecf4121998d9997` |
| `results/runs/revision-analyses/deepseek-minimal/defense_rates.json` | runs/revision-analyses/deepseek-minimal | 11345 | `1aa8b9c5dd9daef710368316138b756f188a6118b8cfd50248069c09b30ad7e9` |
| `results/runs/revision-analyses/deepseek-minimal/defense_rates.md` | runs/revision-analyses/deepseek-minimal | 2486 | `a61d0e7345b28ce80fe7394ef203b85c4e7b6d380249fc9a1bff4fa4672963fb` |
| `results/runs/revision-analyses/deepseek-minimal/margin_bins.json` | runs/revision-analyses/deepseek-minimal | 16185 | `b64cbfe8dd743faec2c3fab9b4b1edbe4bb9b9b6c5f7b5917ea729129cc96a20` |
| `results/runs/revision-analyses/deepseek-minimal/margin_bins.md` | runs/revision-analyses/deepseek-minimal | 4031 | `ebf966e4e4b696bb952294b804a3dcb43f59f9868efbe8d366b7faee6c95dcbd` |
| `results/runs/revision-analyses/deepseek-minimal/memorization.json` | runs/revision-analyses/deepseek-minimal | 13738 | `aca3eaec39ee45aad758812d805f743dc5ba7f2f43a5bbb78fcba44b4a729b67` |
| `results/runs/revision-analyses/deepseek-minimal/memorization.md` | runs/revision-analyses/deepseek-minimal | 5885 | `d16477b81eca68ac92b2c7791640a32291d7609b265843928c32935355c8db30` |
| `results/runs/revision-analyses/deepseek-minimal/rationale_coding_sample.csv` | runs/revision-analyses/deepseek-minimal | 68039 | `598275862bc8ec6259c41985e1020eb9590ca90fb7347734279b5380f7cd838b` |
| `results/runs/revision-analyses/deepseek-minimal/rationales.json` | runs/revision-analyses/deepseek-minimal | 4000 | `72824c63dd5bd6b719f0401f7b978ace7f4cf883df68e9f4d5063f59829d7433` |
| `results/runs/revision-analyses/deepseek-minimal/rationales.md` | runs/revision-analyses/deepseek-minimal | 1889 | `c6067ee2493ebfa92279056e4f2ebd2540cff86da01d8ce824f9859ea9207dc7` |
| `results/runs/revision-analyses/deepseek-minimal/score_shift.json` | runs/revision-analyses/deepseek-minimal | 3082 | `9103017b353e44a9b98357b6d7fded9e6c0f5e42425a96b1a052a18a8dc9b5f8` |
| `results/runs/revision-analyses/deepseek-minimal/score_shift.md` | runs/revision-analyses/deepseek-minimal | 1168 | `1be60954b9db5a14a2edec2f5ea7e23d2e21c3fdfa57ecc48c7e42a62efd0cbf` |
| `results/runs/revision-analyses/main/adaptive_summary.json` | runs/revision-analyses/main | 13728 | `cf66d9efea44942f1f0b633f839ad60cfd1eb9c9d5e9210d6e791bce6f110012` |
| `results/runs/revision-analyses/main/adaptive_summary.md` | runs/revision-analyses/main | 2783 | `8239376be50c69c8538cda3bd2d53a4a8ff94cd6d2423f0de5835ee95ca487fe` |
| `results/runs/revision-analyses/main/calibration.json` | runs/revision-analyses/main | 26281 | `09ea7bc12af7bf81880168ef90958c9df06a335f6f9c694aab3c895973f22d53` |
| `results/runs/revision-analyses/main/calibration.md` | runs/revision-analyses/main | 4857 | `46a12c086a515303940aff0ad2627d056ad8fc7cc244121c96250d172e5946d7` |
| `results/runs/revision-analyses/main/cost_report.json` | runs/revision-analyses/main | 6384 | `5eda015591d4ba8df992dc50c0d7be40422639f20f2070f902fe093d68d8b188` |
| `results/runs/revision-analyses/main/cost_report.md` | runs/revision-analyses/main | 3121 | `f8374d9f6a3efe6be5d3c89549e2f06dd54a8eb808e441a8054f26d3516ba122` |
| `results/runs/revision-analyses/main/defense_contrasts.json` | runs/revision-analyses/main | 69775 | `056e753c29849ab794df76a22a1dbe950b96e0b4682e829858279693fad674c8` |
| `results/runs/revision-analyses/main/defense_contrasts.md` | runs/revision-analyses/main | 16994 | `00b7cb3f015bf6108425b992babb87de634d5998168bfc86dd3cbe654d59c01f` |
| `results/runs/revision-analyses/main/defense_gee.json` | runs/revision-analyses/main | 56590 | `7574a2ad26ad437f60b5fdbaeac73b0940293b999eacd7f18a57ecdf94039e9d` |
| `results/runs/revision-analyses/main/defense_gee.md` | runs/revision-analyses/main | 7510 | `d00d37099d687d40cc458b43a15cd7f1c46122efc5ed31d704c3023a3f472c4d` |
| `results/runs/revision-analyses/main/defense_rates.json` | runs/revision-analyses/main | 39908 | `74ddd3a8bf46440da88712e00fb66ebaf9318bd2fd4d057b363af746d1b42268` |
| `results/runs/revision-analyses/main/defense_rates.md` | runs/revision-analyses/main | 6943 | `62d64ae632b0c17cee9fa763532dd48973aa9611f05a1e589261fe4d069afef0` |
| `results/runs/revision-analyses/main/margin_bins.json` | runs/revision-analyses/main | 78598 | `b7414a3cedc04ddb170ba71091ba79795ca76efee9d90b4652f0230dd0fdf303` |
| `results/runs/revision-analyses/main/margin_bins.md` | runs/revision-analyses/main | 17733 | `f67939156baa92868536bc3f1e225b26f9bd30cfda5ee4877b1b5a048a88090f` |
| `results/runs/revision-analyses/main/memorization.json` | runs/revision-analyses/main | 445073 | `b79fb17588d7dc60bfe57e62cef8a970d1d7f2842cf4d09805bfdc1df2b31da0` |
| `results/runs/revision-analyses/main/memorization.md` | runs/revision-analyses/main | 134001 | `8e6236ba751bd7a34fd78a90045bdb1da099ca5630c89398b760e559c25a2f4e` |
| `results/runs/revision-analyses/main/provider_drift.json` | runs/revision-analyses/main | 4398 | `63ea12abde2b00c742daecf64c06c09d3e7f42cb7cb803f806476c9c78734f6c` |
| `results/runs/revision-analyses/main/provider_drift.md` | runs/revision-analyses/main | 1566 | `da17cf6457165eb81dc5c04552f0e4912265071b64b6985f661f346dd2dfe3f8` |
| `results/runs/revision-analyses/main/rationale_coding_sample.csv` | runs/revision-analyses/main | 404429 | `50d8f84a7339e44164f3bd1552064fe32f81a1c5e29b69e3f27072301fde8b55` |
| `results/runs/revision-analyses/main/rationales.json` | runs/revision-analyses/main | 23392 | `20af333da185fe69c685a398893552f5067e6991ce3683358064c7983c5c41cc` |
| `results/runs/revision-analyses/main/rationales.md` | runs/revision-analyses/main | 5957 | `af7c45576571ca9b3692a022465e23135bbf3fb38c56363e6dfe631127c5d82e` |
| `results/runs/revision-analyses/main/score_shift.json` | runs/revision-analyses/main | 13253 | `ceec6268bee4126bdf8835e91460c99523254aa0e6bc8d8fefbcec12a3043db6` |
| `results/runs/revision-analyses/main/score_shift.md` | runs/revision-analyses/main | 3657 | `bad929a26000658b53be79ffa020bb0cde417173280f4eb2e1225f1088be131c` |
| `results/runs/revision-analyses/main/stripping_tost.json` | runs/revision-analyses/main | 3949 | `74212ebd0485b6de69cc33aa932b7bda31ce775163b2a0c6cb6c80c6be68272e` |
| `results/runs/revision-analyses/main/stripping_tost.md` | runs/revision-analyses/main | 1260 | `14ae81ede69eec12f3a4f3711be206546b3a6611505d8f7923a0d318b6b36ede` |
| `results/runs/revision-deepseek-minimal/full/run_config.json` | runs/revision-deepseek-minimal/full (routing settings removed) | 1392 | `b53d8bbc2c798e2a784e0e2bfb2498690630a96a6bba0b0a7d5dff6962d05af4` |
| `results/runs/revision-deepseek-minimal/full/scores.json` | runs/revision-deepseek-minimal/full | 34995 | `48fec59c00f44f1a7193d41a988a4a85663180965e523c07c82fcac61424c9d2` |
| `results/runs/revision-deepseek-minimal/full/summary.md` | runs/revision-deepseek-minimal/full | 2236 | `85f3b10f28dc8a17ec3b868c185c200a93aa7ce31ec9ae7ef326f89374837e0f` |
| `results/runs/revision-neutral-reanchor/full/run_config.json` | runs/revision-neutral-reanchor/full (routing settings removed) | 1509 | `90047847c0e24929a4914cd12f102238bfa9297b0797f42c30fdec485a4d96a4` |
| `results/runs/revision-neutral-reanchor/full/scores.json` | runs/revision-neutral-reanchor/full | 11096 | `c07a3d28fa9e62cd5153b71b440aba6e9358e99ddf8503de07aef1f623e0f144` |
| `results/runs/revision-neutral-reanchor/full/summary.md` | runs/revision-neutral-reanchor/full | 657 | `912ec15323b13ae664abaff7a6ffb470efd2d751e7e8ce5ddd83407fec0b36dd` |
| `results/runs/revision-placebo/full/run_config.json` | runs/revision-placebo/full (routing settings removed) | 1510 | `5760fd6397f518ff38a1fbc97a4a5097aaf5c5844a3c11f908f8b297b1f9ed90` |
| `results/runs/revision-placebo/full/scores.json` | runs/revision-placebo/full | 78132 | `f900bcad36fed88323be1f14ea4c7844ab4c5f81eb3ffa385b2df6d4e2fd0c0f` |
| `results/runs/revision-placebo/full/summary.md` | runs/revision-placebo/full | 2342 | `1cfb1afbafd01d1b3705b2fc6afc3eb73d9c86535ad3e95e5e040c6d3fe4a742` |
