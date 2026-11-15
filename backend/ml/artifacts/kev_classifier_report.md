# KEV classifier: training report

Generated 2026-11-15T21:41:37+00:00 with scikit-learn 1.9.1.

## Data

* Source: `data/vulnerabilities.db` (NVD CVSS + FIRST EPSS; label = CISA KEV membership)
* EPSS score date: 2026-11-15T12:03:04Z; KEV catalogue version: 2026.11.13
* CVEs: 406,615 (1,781 in KEV, 0.438%)
* Missing CVSS: 4,138; missing EPSS: 0
* Split: stratified 80%/20% train/test, seed 42 (train 325,292, test 81,323)

## Model selection (5-fold CV on the training split, average precision)

| Model | Mean AP | Std |
|---|---|---|
| logistic_regression | 0.3665 | 0.0343 |
| hist_gradient_boosting | 0.2609 | 0.0157 |

Selected: **logistic_regression**

## Held-out test split

| Ranker | roc_auc | average_precision | precision_at_100 | recall_at_top_1pct | recall_at_top_5pct | recall_at_top_10pct |
|---|---|---|---|---|---|---|
| model:logistic_regression | 0.9546 | 0.3164 | 0.6800 | 0.4747 | 0.7781 | 0.8567 |
| model:hist_gradient_boosting | 0.9590 | 0.2513 | 0.5100 | 0.4607 | 0.8006 | 0.8764 |
| baseline:cvss_only | 0.7514 | 0.0106 | 0.0100 | 0.0225 | 0.1264 | 0.3034 |
| baseline:epss_only | 0.9531 | 0.3075 | 0.6500 | 0.4663 | 0.7697 | 0.8736 |
| baseline:weighted_score | 0.9138 | 0.3130 | 0.6700 | 0.4775 | 0.7023 | 0.7528 |

`recall_at_top_k%`: share of all KEV CVEs in the test split that land in the top k% of the ranking.

## Using the model

```python
import joblib
from ml.features import MODEL_PATH, to_matrix
model = joblib.load(MODEL_PATH)
p_kev = model.predict_proba(to_matrix([{'cvss_score': 9.8, 'epss_score': 0.97}]))[:, 1]
```
