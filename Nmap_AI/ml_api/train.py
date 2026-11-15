"""
train.py - train, test and save the NetAnomaly model.

Examples
  # NSL-KDD (KDD+.txt in the repo root is KDDTrain+ and KDDTest+ joined together)
  python train.py --dataset nslkdd --data ../../KDD+.txt

  # UWF-ZeekData22 (download the CSV or parquet files into one folder first)
  python train.py --dataset uwf --data data/uwf-zeekdata22/

  # Teach the "unusual traffic" detector what normal looks like on YOUR network
  python train.py --dataset nslkdd --data ../../KDD+.txt --baseline-conn my_normal_conn.log

Outputs (in --out-dir, default models/):
  netanomaly_model.joblib   the model the API loads
  model_card.json           all test results
  MODEL_CARD.md             the same results in plain English
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder

from features import (ALL_FEATURES, CATEGORICAL_FEATURES, NSL_KDD_CLASSES, NSL_KDD_COLUMNS,
                      NUMERIC_FEATURES, conn_to_features, nsl_kdd_label, read_zeek_conn)
from model import NetAnomalyModel, robust_profile

NSL_KDD_TRAIN_ROWS = 125_973  # KDDTrain+.txt
NSL_KDD_TEST_ROWS = 22_544    # KDDTest+.txt
ANOMALY_QUANTILE = 0.99       # ~1% of normal traffic gets flagged as unusual


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def load_nsl_kdd(path, test_path=None):
    """Return (X_train, y_train, X_test, y_test, note)."""
    df = pd.read_csv(path, names=NSL_KDD_COLUMNS)
    if test_path:
        test = pd.read_csv(test_path, names=NSL_KDD_COLUMNS)
        train, note = df, 'Official split: KDDTrain+ for training, KDDTest+ for testing.'
    elif len(df) == NSL_KDD_TRAIN_ROWS + NSL_KDD_TEST_ROWS:
        train, test = df.iloc[:NSL_KDD_TRAIN_ROWS], df.iloc[NSL_KDD_TRAIN_ROWS:]
        note = ('Official split: the first 125,973 rows of KDD+.txt are KDDTrain+ (training), '
                'the last 22,544 rows are KDDTest+ (testing).')
    else:
        raise SystemExit(f'{path} has {len(df)} rows. Pass the KDDTrain+ file with --data '
                         'and the KDDTest+ file with --test-data.')
    X_train = train[ALL_FEATURES].copy()
    X_test = test[ALL_FEATURES].copy()
    y_train = train['attack'].map(nsl_kdd_label)
    y_test = test['attack'].map(nsl_kdd_label)
    return X_train, y_train, X_test, y_test, note


def _read_any(path: Path) -> pd.DataFrame:
    if path.suffix == '.parquet':
        return pd.read_parquet(path)
    if path.suffix == '.csv':
        return pd.read_csv(path, low_memory=False)
    return read_zeek_conn(path)


def load_uwf(path, min_class_rows=200, seed=2004):
    """UWF-ZeekData22 / 24: labelled Zeek conn rows (label_tactic column)."""
    path = Path(path)
    files = sorted(path.glob('*.parquet')) + sorted(path.glob('*.csv')) if path.is_dir() else [path]
    if not files:
        raise SystemExit(f'No .parquet or .csv files found in {path}')
    df = pd.concat([_read_any(f) for f in files], ignore_index=True)
    label_col = next((c for c in ('label_tactic', 'mitre_attack_tactics', 'label') if c in df.columns), None)
    if label_col is None:
        raise SystemExit('Could not find a label column (expected label_tactic)')
    labels = df[label_col].fillna('none').astype(str).str.strip()
    labels = labels.where(~labels.str.lower().isin(['none', 'benign', 'normal', '']), 'Normal')
    counts = labels.value_counts()
    rare = counts[counts < min_class_rows].index
    labels = labels.where(~labels.isin(rare), 'Other attack')
    feats = conn_to_features(df)  # same function the live scorer uses
    X_train, X_test, y_train, y_test = train_test_split(
        feats, labels, test_size=0.2, random_state=seed, stratify=labels)
    note = (f'UWF data from {len(files)} file(s). Stratified 80/20 split. Tactics with fewer than '
            f'{min_class_rows} rows are grouped as "Other attack". Features were computed from the '
            'conn rows with the same code the live scorer uses.')
    return X_train, y_train, X_test, y_test, note


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def expected_calibration_error(confidence, correct, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    ece = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        mask = (confidence > lo) & (confidence <= hi)
        if mask.any():
            ece += mask.mean() * abs(correct[mask].mean() - confidence[mask].mean())
    return float(ece)


def evaluate(y_true, y_pred, classes, confidence=None):
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    normal = y_true == 'Normal'
    attack = ~normal
    report = classification_report(y_true, y_pred, labels=classes, output_dict=True, zero_division=0)
    result = {
        'accuracy': round(float(accuracy_score(y_true, y_pred)), 4),
        'macro_f1': round(float(f1_score(y_true, y_pred, labels=classes, average='macro', zero_division=0)), 4),
        'weighted_f1': round(float(f1_score(y_true, y_pred, labels=classes, average='weighted', zero_division=0)), 4),
        # binary view: did we raise an alert or not?
        'false_positive_rate': round(float((y_pred[normal] != 'Normal').mean()), 4) if normal.any() else None,
        'attack_detection_rate': round(float((y_pred[attack] != 'Normal').mean()), 4) if attack.any() else None,
        'per_class': {c: {'precision': round(report[c]['precision'], 4),
                          'recall': round(report[c]['recall'], 4),
                          'f1': round(report[c]['f1-score'], 4),
                          'support': int(report[c]['support'])} for c in classes},
        'confusion_matrix': {'labels': classes,
                             'matrix': confusion_matrix(y_true, y_pred, labels=classes).tolist()},
    }
    if confidence is not None:
        result['calibration_error'] = round(expected_calibration_error(
            np.asarray(confidence), (y_true == y_pred).astype(float)), 4)
    return result


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def make_preprocessor():
    return ColumnTransformer([
        ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), CATEGORICAL_FEATURES),
        ('num', 'passthrough', NUMERIC_FEATURES),
    ], verbose_feature_names_out=True).set_output(transform='pandas')


def make_lightgbm(seed, quick=False):
    return lgb.LGBMClassifier(
        n_estimators=150 if quick else 400, learning_rate=0.05, num_leaves=31,
        min_child_samples=10, subsample=0.8, subsample_freq=1, colsample_bytree=0.8,
        class_weight='balanced', random_state=seed, n_jobs=-1, verbose=-1)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--dataset', choices=['nslkdd', 'uwf'], default='nslkdd')
    ap.add_argument('--data', required=True, help='Training data file or folder')
    ap.add_argument('--test-data', help='Separate test file (NSL-KDD only)')
    ap.add_argument('--baseline-conn', nargs='*', default=[],
                    help='Zeek conn logs of NORMAL traffic from your own network, used to train the '
                         '"unusual traffic" detector instead of the dataset\'s normal rows')
    ap.add_argument('--out-dir', default=str(Path(__file__).parent / 'models'))
    ap.add_argument('--seed', type=int, default=2004)
    ap.add_argument('--quick', action='store_true', help='Fewer trees, for tests')
    ap.add_argument('--calibrate', action='store_true',
                    help='Use the calibrated probabilities in the saved model. Off by default because on '
                         'NSL-KDD it did not help on the real test set (see MODEL_CARD.md).')
    args = ap.parse_args(argv)

    t0 = time.time()
    print(f'Loading {args.dataset} data from {args.data} ...')
    if args.dataset == 'nslkdd':
        X_train, y_train, X_test, y_test, split_note = load_nsl_kdd(args.data, args.test_data)
        classes = NSL_KDD_CLASSES
    else:
        X_train, y_train, X_test, y_test, split_note = load_uwf(args.data, seed=args.seed)
        classes = ['Normal'] + sorted(c for c in y_train.unique() if c != 'Normal')
    print(f'  train rows: {len(X_train):,}  test rows: {len(X_test):,}')
    print('  ' + split_note)

    results = {}

    # 1) Old approach, for comparison: Random Forest, same features
    print('Training Random Forest (comparison) ...')
    rf_pre = make_preprocessor()
    rf = RandomForestClassifier(n_estimators=50 if args.quick else 200, random_state=args.seed, n_jobs=-1)
    rf.fit(rf_pre.fit_transform(X_train), y_train)
    results['random_forest'] = evaluate(y_test, rf.predict(rf_pre.transform(X_test)), classes)

    # 2) Same, but with a random split of the training data. This is how the old
    #    99.5% number was measured; we keep it only to show why it is misleading.
    Xa, Xb, ya, yb = train_test_split(X_train, y_train, test_size=0.2, random_state=args.seed, stratify=y_train)
    rf_pre2 = make_preprocessor()
    rf2 = RandomForestClassifier(n_estimators=50 if args.quick else 200, random_state=args.seed, n_jobs=-1)
    rf2.fit(rf_pre2.fit_transform(Xa), ya)
    results['random_forest_random_split'] = evaluate(yb, rf2.predict(rf_pre2.transform(Xb)), classes)

    # 3) LightGBM, then calibrate its probabilities on a held-out part of the training data
    print('Training LightGBM ...')
    X_fit, X_cal, y_fit, y_cal = train_test_split(X_train, y_train, test_size=0.2,
                                                  random_state=args.seed, stratify=y_train)
    pre = make_preprocessor()
    Xt_fit = pre.fit_transform(X_fit)
    Xt_cal, Xt_test = pre.transform(X_cal), pre.transform(X_test)
    clf = make_lightgbm(args.seed, args.quick)
    clf.fit(Xt_fit, y_fit)
    raw_proba = clf.predict_proba(Xt_test)
    raw_pred = clf.classes_[raw_proba.argmax(1)]
    results['lightgbm'] = evaluate(y_test, raw_pred, classes, raw_proba.max(1))

    print('Calibrating probabilities ...')
    calibrator = CalibratedClassifierCV(FrozenEstimator(clf), method='sigmoid')
    calibrator.fit(Xt_cal, y_cal)
    cal_proba = calibrator.predict_proba(Xt_test)
    cal_pred = calibrator.classes_[cal_proba.argmax(1)]
    results['lightgbm_calibrated'] = evaluate(y_test, cal_pred, classes, cal_proba.max(1))

    # 4) "Unusual traffic" detector trained only on normal traffic
    if args.baseline_conn:
        print(f'Training anomaly detector on your baseline logs: {args.baseline_conn}')
        base = pd.concat([conn_to_features(read_zeek_conn(p)) for p in args.baseline_conn], ignore_index=True)
        baseline_source = f'{len(base):,} connections from your own conn logs'
    else:
        base = X_fit[y_fit == 'Normal']
        baseline_source = f'{len(base):,} normal connections from the training data'
    base_fit, base_cal = train_test_split(base, test_size=0.2, random_state=args.seed)
    iforest = IsolationForest(n_estimators=200, contamination='auto', random_state=args.seed, n_jobs=-1)
    iforest.fit(pre.transform(base_fit))
    threshold = float(np.quantile(-iforest.score_samples(pre.transform(base_cal)), ANOMALY_QUANTILE))
    test_scores = -iforest.score_samples(Xt_test)
    flagged = test_scores > threshold
    y_arr = np.asarray(y_test)
    final_pred = cal_pred if args.calibrate else raw_pred
    missed_by_classifier = (y_arr != 'Normal') & (final_pred == 'Normal')
    results['anomaly_detector'] = {
        'trained_on': baseline_source,
        'normal_flagged_rate': round(float(flagged[y_arr == 'Normal'].mean()), 4),
        'attacks_flagged_rate': round(float(flagged[y_arr != 'Normal'].mean()), 4),
        'attacks_missed_by_classifier': int(missed_by_classifier.sum()),
        'of_those_caught_by_anomaly_detector': int((missed_by_classifier & flagged).sum()),
    }
    combined = (final_pred != 'Normal') | flagged
    results['combined_alerting'] = {
        'note': 'An alert is raised when the classifier says "attack" OR the anomaly detector says "unusual".',
        'attack_detection_rate': round(float(combined[y_arr != 'Normal'].mean()), 4),
        'false_positive_rate': round(float(combined[y_arr == 'Normal'].mean()), 4),
    }

    # 5) Save
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    used = 'lightgbm_calibrated' if args.calibrate else 'lightgbm'
    cal = results[used]
    metadata = {
        'model_used': used,
        'name': 'NetAnomaly LightGBM + Isolation Forest',
        'dataset': args.dataset,
        'data_file': Path(args.data).name,
        'split': split_note,
        'trained_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'train_rows': int(len(X_train)), 'test_rows': int(len(X_test)),
        'features': ALL_FEATURES,
        'anomaly_baseline': baseline_source,
        'anomaly_threshold_quantile': ANOMALY_QUANTILE,
        'versions': {'python': sys.version.split()[0], 'scikit-learn': sklearn.__version__,
                     'lightgbm': lgb.__version__, 'pandas': pd.__version__, 'numpy': np.__version__},
        'test_summary': {k: cal[k] for k in ('accuracy', 'macro_f1', 'false_positive_rate',
                                             'attack_detection_rate', 'calibration_error')},
        'results': results,
    }
    profile_rows = base if args.baseline_conn else X_fit[y_fit == 'Normal']
    final_proba_model = calibrator if args.calibrate else clf
    model = NetAnomalyModel(pre, clf, final_proba_model, iforest, threshold,
                            robust_profile(profile_rows[NUMERIC_FEATURES]), metadata)
    joblib.dump(model, out_dir / 'netanomaly_model.joblib', compress=3)
    (out_dir / 'model_card.json').write_text(json.dumps(metadata, indent=2))
    (out_dir / 'MODEL_CARD.md').write_text(model_card_markdown(metadata, classes))
    print(f'\nSaved model to {out_dir / "netanomaly_model.joblib"} ({time.time() - t0:.0f}s)')
    print_summary(results)
    return metadata


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def pct(v):
    return '-' if v is None else f'{v * 100:.1f}%'


def print_summary(results):
    print(f'\n{"model":34} {"accuracy":>9} {"macroF1":>8} {"FPR":>7} {"detect":>7}')
    for name in ('random_forest_random_split', 'random_forest', 'lightgbm', 'lightgbm_calibrated'):
        r = results[name]
        print(f'{name:34} {pct(r["accuracy"]):>9} {pct(r["macro_f1"]):>8} '
              f'{pct(r["false_positive_rate"]):>7} {pct(r["attack_detection_rate"]):>7}')
    print('anomaly detector:', results['anomaly_detector'])
    print('combined alerting:', results['combined_alerting'])


def model_card_markdown(meta, classes):
    r = meta['results']
    rows = [
        ('Random Forest, random split of training data (the old way, misleading)', r['random_forest_random_split']),
        ('Random Forest, real test set', r['random_forest']),
        ('LightGBM, real test set', r['lightgbm']),
        ('LightGBM + calibration, real test set', r['lightgbm_calibrated']),
    ]
    used = meta['model_used']
    used_name = 'LightGBM + calibration' if used == 'lightgbm_calibrated' else 'LightGBM'
    lines = [
        '# NetAnomaly model card', '',
        'This file is made by `train.py`. Do not edit it by hand.', '',
        f'- **Trained:** {meta["trained_at"]} on `{meta["data_file"]}` ({meta["dataset"]})',
        f'- **Split:** {meta["split"]}',
        f'- **Rows:** {meta["train_rows"]:,} train, {meta["test_rows"]:,} test',
        f'- **Features:** {len(meta["features"])}, all computable from a Zeek conn.log',
        f'- **Unusual-traffic detector trained on:** {meta["anomaly_baseline"]}', '',
        '## Results', '',
        '"False alarms" is the share of normal connections that got an alert. '
        '"Attacks caught" is the share of attack connections that got any alert.', '',
        '| Model | Accuracy | Macro F1 | False alarms | Attacks caught |',
        '|---|---|---|---|---|',
    ]
    for name, m in rows:
        lines.append(f'| {name} | {pct(m["accuracy"])} | {pct(m["macro_f1"])} | '
                     f'{pct(m["false_positive_rate"])} | {pct(m["attack_detection_rate"])} |')
    cal = r[used]
    lines += ['', f'**The app uses: {used_name}.**', '',
              f'### Each class ({used_name}, real test set)', '',
              '| Class | Precision | Recall | F1 | Rows in test |', '|---|---|---|---|---|']
    for c in classes:
        p = cal['per_class'][c]
        lines.append(f'| {c} | {pct(p["precision"])} | {pct(p["recall"])} | {pct(p["f1"])} | {p["support"]:,} |')
    lines += ['', '### Confusion matrix (rows = real class, columns = predicted)', '',
              '| | ' + ' | '.join(classes) + ' |', '|---' * (len(classes) + 1) + '|']
    for c, row in zip(classes, cal['confusion_matrix']['matrix']):
        lines.append(f'| **{c}** | ' + ' | '.join(f'{v:,}' for v in row) + ' |')
    a, comb = r['anomaly_detector'], r['combined_alerting']
    lines += ['', '### Confidence', '',
              f'Calibration error before calibration: {pct(r["lightgbm"].get("calibration_error"))}, '
              f'after: {pct(r["lightgbm_calibrated"].get("calibration_error"))} (lower is better). '
              'Calibration is fitted on held-out training rows, so it cannot fix the shift between the '
              'KDD training and test sets. Use `--calibrate` to turn it on anyway.', '',
              '### Unusual-traffic detector (Isolation Forest)', '',
              f'- Normal test connections flagged as unusual: {pct(a["normal_flagged_rate"])}',
              f'- Attack test connections flagged as unusual: {pct(a["attacks_flagged_rate"])}',
              f'- Attacks the classifier missed: {a["attacks_missed_by_classifier"]:,}, of which the '
              f'detector flagged {a["of_those_caught_by_anomaly_detector"]:,}',
              f'- Classifier and detector together: catch {pct(comb["attack_detection_rate"])} of attacks '
              f'with {pct(comb["false_positive_rate"])} false alarms', '',
              '## Limits', '',
              '- NSL-KDD traffic is from 1998-99. Modern traffic looks different, so expect more false '
              'alarms on a real network. Train the unusual-traffic detector on your own normal traffic '
              'with `--baseline-conn` to reduce them.',
              '- The KDD test set has attack types that are not in the training set on purpose. That is '
              'why R2L and U2R recall is low.',
              '- Only connection-level features are used. Attacks that look like normal connections '
              '(for example many web attacks) need payload inspection, such as Suricata.', '',
              '## Versions', '', '```', json.dumps(meta['versions'], indent=2), '```', '']
    return '\n'.join(lines)


if __name__ == '__main__':
    main()
