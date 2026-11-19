# GEE logistic model of attack success (manual)

Trials: 33792; clusters (base functions): 176; exchangeable working correlation.

| Term | Odds ratio | 95% CI | p |
|---|---:|---:|---:|
| `Intercept` | 0.86 | [0.65, 1.14] | 0.29 |
| `C(defense, Treatment('neutral'))[T.tagged]` | 0.93 | [0.88, 0.99] | 0.016 |
| `C(defense, Treatment('neutral'))[T.warning]` | 0.95 | [0.91, 1.00] | 0.042 |
| `C(style, Treatment('dsc'))[T.api]` | 0.86 | [0.82, 0.91] | 2.2e-09 |
| `C(style, Treatment('dsc'))[T.escape]` | 1.10 | [1.04, 1.17] | 0.00093 |
| `C(style, Treatment('dsc'))[T.ivm]` | 0.81 | [0.77, 0.86] | 1.7e-12 |
| `C(style, Treatment('dsc'))[T.rust]` | 1.19 | [1.10, 1.30] | 4.8e-05 |
| `C(model)[T.deepseek-v4-pro]` | 5.12 | [4.33, 6.05] | 2e-81 |
| `C(model)[T.gemini-3.8-flash]` | 0.78 | [0.69, 0.87] | 2.3e-05 |
| `C(model)[T.gpt-6.1-sol]` | 0.61 | [0.52, 0.73] | 1.9e-08 |
| `C(goal, Treatment('suppression'))[T.induction]` | 0.61 | [0.44, 0.84] | 0.0022 |
| `C(placement, Treatment('top'))[T.inline]` | 0.95 | [0.91, 0.99] | 0.022 |
| `C(defense, Treatment('neutral'))[T.tagged]:C(goal, Treatment('suppression'))[T.induction]` | 0.40 | [0.34, 0.48] | 3.6e-26 |
| `C(defense, Treatment('neutral'))[T.warning]:C(goal, Treatment('suppression'))[T.induction]` | 0.48 | [0.42, 0.55] | 2e-27 |
