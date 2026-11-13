# NetAnomaly model card

This file is made by `train.py`. Do not edit it by hand.

- **Trained:** 2026-11-13 09:51:06 on `KDD+.txt` (nslkdd)
- **Split:** Official split: the first 125,973 rows of KDD+.txt are KDDTrain+ (training), the last 22,544 rows are KDDTest+ (testing).
- **Rows:** 125,973 train, 22,544 test
- **Features:** 26, all computable from a Zeek conn.log
- **Unusual-traffic detector trained on:** 53,874 normal connections from the training data

## Results

"False alarms" is the share of normal connections that got an alert. "Attacks caught" is the share of attack connections that got any alert.

| Model | Accuracy | Macro F1 | False alarms | Attacks caught |
|---|---|---|---|---|
| Random Forest, random split of training data (the old way, misleading) | 99.9% | 84.9% | 0.1% | 99.8% |
| Random Forest, real test set | 76.1% | 51.8% | 2.6% | 62.0% |
| LightGBM, real test set | 77.2% | 54.2% | 2.9% | 64.5% |
| LightGBM + calibration, real test set | 76.5% | 53.2% | 2.8% | 62.8% |

**The app uses: LightGBM.**

### Each class (LightGBM, real test set)

| Class | Precision | Recall | F1 | Rows in test |
|---|---|---|---|---|
| Normal | 67.5% | 97.1% | 79.6% | 9,711 |
| DoS | 96.3% | 82.6% | 88.9% | 7,458 |
| Probe | 82.1% | 63.4% | 71.6% | 2,421 |
| R2L | 99.3% | 10.0% | 18.1% | 2,754 |
| U2R | 70.0% | 7.0% | 12.7% | 200 |

### Confusion matrix (rows = real class, columns = predicted)

| | Normal | DoS | Probe | R2L | U2R |
|---|---|---|---|---|---|
| **Normal** | 9,427 | 75 | 205 | 2 | 2 |
| **DoS** | 1,185 | 6,162 | 111 | 0 | 0 |
| **Probe** | 722 | 163 | 1,536 | 0 | 0 |
| **R2L** | 2,473 | 0 | 2 | 275 | 4 |
| **U2R** | 169 | 0 | 17 | 0 | 14 |

### Confidence

Calibration error before calibration: 21.6%, after: 20.1% (lower is better). Calibration is fitted on held-out training rows, so it cannot fix the shift between the KDD training and test sets. Use `--calibrate` to turn it on anyway.

### Unusual-traffic detector (Isolation Forest)

- Normal test connections flagged as unusual: 1.3%
- Attack test connections flagged as unusual: 55.8%
- Attacks the classifier missed: 4,549, of which the detector flagged 1,029
- Classifier and detector together: catch 72.6% of attacks with 3.1% false alarms

## Limits

- NSL-KDD traffic is from 1998-99. Modern traffic looks different, so expect more false alarms on a real network. Train the unusual-traffic detector on your own normal traffic with `--baseline-conn` to reduce them.
- The KDD test set has attack types that are not in the training set on purpose. That is why R2L and U2R recall is low.
- Only connection-level features are used. Attacks that look like normal connections (for example many web attacks) need payload inspection, such as Suricata.

## Versions

```
{
  "python": "3.13.18",
  "scikit-learn": "1.9.1",
  "lightgbm": "4.7.0",
  "pandas": "3.1.1",
  "numpy": "2.5.4"
}
```
