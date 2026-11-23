# GEE logistic model of attack success (manual)

Trials: 33792; clusters (base functions): 176; exchangeable working correlation.

| Term | Odds ratio | 95% CI | p |
|---|---:|---:|---:|
| `Intercept` | 1.22 | [0.92, 1.60] | 0.16 |
| `C(defense, Treatment('neutral'))[T.tagged]` | 0.62 | [0.59, 0.65] | 2.5e-73 |
| `C(defense, Treatment('neutral'))[T.warning]` | 0.68 | [0.65, 0.71] | 8.3e-65 |
| `C(style, Treatment('dsc'))[T.api]` | 0.87 | [0.83, 0.91] | 1.3e-09 |
| `C(style, Treatment('dsc'))[T.escape]` | 1.10 | [1.04, 1.17] | 0.00083 |
| `C(style, Treatment('dsc'))[T.ivm]` | 0.82 | [0.77, 0.86] | 7e-13 |
| `C(style, Treatment('dsc'))[T.rust]` | 1.19 | [1.10, 1.29] | 4.2e-05 |
| `C(model)[T.deepseek-v4-pro]` | 5.03 | [4.29, 5.89] | 4.7e-88 |
| `C(model)[T.gemini-3.8-flash]` | 0.78 | [0.70, 0.87] | 1.7e-05 |
| `C(model)[T.gpt-6.1-sol]` | 0.62 | [0.52, 0.73] | 8.9e-09 |
| `C(goal, Treatment('suppression'))[T.induction]` | 0.36 | [0.25, 0.52] | 5.3e-08 |
| `C(placement, Treatment('top'))[T.inline]` | 0.95 | [0.92, 0.99] | 0.02 |
