"""
model.py - the saved model and how it is used.

A NetAnomalyModel holds everything needed to score traffic:
  * the feature encoder (one-hot for protocol / service / flag)
  * a LightGBM classifier (which known attack type is this?)
  * a probability calibrator (so "80% confident" really means about 80%)
  * an Isolation Forest trained only on normal traffic (is this unusual?)
  * plain-English explanations for each alert
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from features import (ALL_FEATURES, CATEGORICAL_FEATURES, FEATURE_DESCRIPTIONS,
                      NUMERIC_FEATURES)

MODEL_FORMAT_VERSION = 2
RATE_FEATURES = {f for f in NUMERIC_FEATURES if f.endswith('_rate')}


def format_value(feature, value):
    if feature in CATEGORICAL_FEATURES:
        return str(value)
    if feature in RATE_FEATURES:
        return f'{float(value) * 100:.0f}%'
    if feature == 'duration':
        return f'{float(value):.2f}s'
    if feature == 'land':
        return 'yes' if float(value) else 'no'
    return f'{float(value):,.0f}'


class NetAnomalyModel:
    """Everything the scorer needs, saved together in one joblib file."""

    def __init__(self, preprocessor, classifier, calibrator, anomaly_detector,
                 anomaly_threshold, normal_profile, metadata):
        self.format_version = MODEL_FORMAT_VERSION
        self.features = list(ALL_FEATURES)
        self.preprocessor = preprocessor
        self.classifier = classifier
        self.calibrator = calibrator
        self.anomaly_detector = anomaly_detector
        self.anomaly_threshold = float(anomaly_threshold)
        self.normal_profile = normal_profile  # {'median': {...}, 'scale': {...}}
        self.metadata = metadata
        self.classes = [str(c) for c in calibrator.classes_]
        # map every encoded column back to the original feature name
        names = list(preprocessor.get_feature_names_out())
        self._encoded_names = names
        self._encoded_to_feature = [self._source_feature(n) for n in names]

    @staticmethod
    def _source_feature(encoded_name):
        name = encoded_name.split('__', 1)[-1]
        for cat in CATEGORICAL_FEATURES:
            if name.startswith(cat + '_'):
                return cat
        return name

    # ------------------------------------------------------------------
    def check_features(self, X: pd.DataFrame):
        missing = [c for c in self.features if c not in X.columns]
        if missing:
            raise ValueError(f'Feature columns missing: {missing}. '
                             'Build features with features.conn_to_features().')
        return X[self.features]

    def transform(self, X):
        return self.preprocessor.transform(self.check_features(X))

    def predict(self, X: pd.DataFrame) -> pd.DataFrame:
        """Return label, confidence, anomaly score and flag for each row."""
        Xt = self.transform(X)
        proba = self.calibrator.predict_proba(Xt)
        idx = proba.argmax(axis=1)
        labels = np.array(self.classes)[idx]
        anomaly_score = -self.anomaly_detector.score_samples(Xt)
        out = pd.DataFrame({
            'predicted_label': labels,
            'confidence': proba[np.arange(len(idx)), idx],
            'anomaly_score': anomaly_score,
            'is_anomaly': anomaly_score > self.anomaly_threshold,
        }, index=X.index)
        for i, c in enumerate(self.classes):
            out[f'prob_{c}'] = proba[:, i]
        return out

    # ------------------------------------------------------------------
    def explain_prediction(self, X: pd.DataFrame, labels, top_k=3):
        """Top reasons the classifier picked each row's label (TreeSHAP)."""
        if len(X) == 0:
            return []
        Xt = self.transform(X)
        contrib = self.classifier.predict(Xt, pred_contrib=True)
        n_cols = len(self._encoded_names) + 1  # +1 is the bias term
        if isinstance(contrib, list):  # some LightGBM versions return one array per class
            contrib = np.hstack(contrib)
        contrib = np.asarray(contrib)
        reasons = []
        class_index = {c: i for i, c in enumerate(self.classes)}
        for row in range(len(X)):
            k = class_index[str(labels[row])]
            block = contrib[row, k * n_cols:(k + 1) * n_cols - 1]
            per_feature = {}
            for col, value in enumerate(block):
                f = self._encoded_to_feature[col]
                per_feature[f] = per_feature.get(f, 0.0) + float(value)
            top = sorted(per_feature.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
            reasons.append([self._reason(f, X.iloc[row][f], w) for f, w in top if w > 0])
        return reasons

    def explain_anomaly(self, X: pd.DataFrame, top_k=3):
        """Which numeric features are furthest from normal traffic (robust z-score)."""
        med = self.normal_profile['median']
        scale = self.normal_profile['scale']
        reasons = []
        for _, row in X.iterrows():
            scores = {f: abs(float(row[f]) - med[f]) / scale[f] for f in NUMERIC_FEATURES}
            top = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
            reasons.append([
                {'feature': f, 'description': FEATURE_DESCRIPTIONS.get(f, f),
                 'value': format_value(f, row[f]), 'typical': format_value(f, med[f]),
                 'weight': round(s, 2)}
                for f, s in top if s > 0
            ])
        return reasons

    @staticmethod
    def _reason(feature, value, weight):
        return {'feature': feature, 'description': FEATURE_DESCRIPTIONS.get(feature, feature),
                'value': format_value(feature, value), 'weight': round(float(weight), 3)}

    # ------------------------------------------------------------------
    def info(self):
        m = self.metadata
        return {
            'name': m.get('name'),
            'trained_on': m.get('dataset'),
            'trained_at': m.get('trained_at'),
            'classes': self.classes,
            'n_features': len(self.features),
            'test_metrics': m.get('test_summary'),
            'anomaly_baseline': m.get('anomaly_baseline'),
        }


def robust_profile(X_num: pd.DataFrame):
    """Median and spread of each numeric feature in normal traffic."""
    med = X_num.median()
    q1, q3 = X_num.quantile(0.25), X_num.quantile(0.75)
    scale = (q3 - q1)
    # avoid dividing by zero: fall back to std, then to 1
    scale = scale.where(scale > 0, X_num.std()).where(lambda s: s > 0, 1.0)
    return {'median': {k: float(v) for k, v in med.items()},
            'scale': {k: float(v) for k, v in scale.items()}}
