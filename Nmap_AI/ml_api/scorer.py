"""
scorer.py - score a Zeek conn log with the NetAnomaly model.

  python scorer.py --zeek_conn results/zeek_123/conn.log --output predictions.csv

Prints one JSON object with the summary. The same logic is used by the
Flask API (app.py imports score_conn_log).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from features import conn_to_features, read_zeek_conn
from model import MODEL_FORMAT_VERSION, NetAnomalyModel

DEFAULT_MODEL_PATH = Path(__file__).parent / 'models' / 'netanomaly_model.joblib'
HIGH_CONFIDENCE = 0.8
MAX_ALERTS_RETURNED = 50

CONN_COLUMNS_OUT = {'ts': 'ts', 'uid': 'uid', 'id.orig_h': 'src_ip', 'id.orig_p': 'src_port',
                    'id.resp_h': 'dst_ip', 'id.resp_p': 'dst_port', 'proto': 'proto',
                    'service': 'zeek_service', 'conn_state': 'conn_state'}


def load_model(path=DEFAULT_MODEL_PATH) -> NetAnomalyModel:
    model = joblib.load(path)
    if not isinstance(model, NetAnomalyModel) or getattr(model, 'format_version', 0) != MODEL_FORMAT_VERSION:
        raise ValueError(f'{path} is not a NetAnomaly model (format {MODEL_FORMAT_VERSION}). '
                         'Retrain it with: python train.py --dataset nslkdd --data ../../KDD+.txt')
    trained = (model.metadata or {}).get('versions', {})
    import lightgbm, sklearn
    for name, now in (('scikit-learn', sklearn.__version__), ('lightgbm', lightgbm.__version__)):
        if trained.get(name) and trained[name] != now:
            print(f'Warning: model was trained with {name} {trained[name]} but {now} is installed. '
                  'If results look wrong, retrain with train.py.', file=sys.stderr)
    return model


def _clean(value):
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return None if np.isnan(value) else float(value)
    if isinstance(value, float) and np.isnan(value):
        return None
    return value


def score_conn_log(conn_path, model: NetAnomalyModel, output_csv=None):
    """Score one conn log. Returns a JSON-ready summary dict."""
    conn = read_zeek_conn(conn_path)
    if conn.empty:
        return {'success': True, 'total_records': 0, 'normal': 0, 'attacks': 0, 'anomalies': 0,
                'high_confidence_alerts': 0, 'attack_breakdown': {}, 'alerts': [],
                'avg_confidence': 0.0, 'max_confidence': 0.0, 'model': model.info(),
                'warning': 'The conn log has no connections. Try a longer capture.'}
    conn = conn.reset_index(drop=True)
    feats = conn_to_features(conn)
    pred = model.predict(feats)

    is_attack = pred['predicted_label'] != 'Normal'
    alert_mask = is_attack | pred['is_anomaly']
    severity = np.where(is_attack, 1.0 + pred['confidence'], pred['anomaly_score'] / max(model.anomaly_threshold, 1e-9) * 0.5)
    pred['severity'] = severity

    # Explanations only for rows that raised an alert (they are the ones people read)
    pred['reasons'] = [[] for _ in range(len(pred))]
    attack_idx = pred.index[is_attack]
    if len(attack_idx):
        reasons = model.explain_prediction(feats.loc[attack_idx], pred.loc[attack_idx, 'predicted_label'].tolist())
        for i, r in zip(attack_idx, reasons):
            pred.at[i, 'reasons'] = r
    anomaly_only_idx = pred.index[pred['is_anomaly'] & ~is_attack]
    if len(anomaly_only_idx):
        for i, r in zip(anomaly_only_idx, model.explain_anomaly(feats.loc[anomaly_only_idx])):
            pred.at[i, 'reasons'] = r

    meta = pd.DataFrame({out: conn[col] if col in conn else None for col, out in CONN_COLUMNS_OUT.items()})
    table = pd.concat([meta, feats, pred], axis=1)

    if output_csv:
        csv = table.copy()
        csv['reasons'] = csv['reasons'].map(lambda rs: '; '.join(f"{r['description']}: {r['value']}" for r in rs))
        csv.to_csv(output_csv, index=False)

    alerts_df = table[alert_mask].sort_values('severity', ascending=False).head(MAX_ALERTS_RETURNED)
    alerts = []
    for _, row in alerts_df.iterrows():
        alerts.append({
            'ts': _clean(row['ts']), 'uid': _clean(row['uid']),
            'src_ip': _clean(row['src_ip']), 'src_port': _clean(row['src_port']),
            'dst_ip': _clean(row['dst_ip']), 'dst_port': _clean(row['dst_port']),
            'proto': _clean(row['proto']), 'service': row['service'],
            'label': row['predicted_label'] if row['predicted_label'] != 'Normal' else 'Unusual',
            'kind': 'known_attack' if row['predicted_label'] != 'Normal' else 'anomaly',
            'confidence': round(float(row['confidence']), 4),
            'anomaly_score': round(float(row['anomaly_score']), 4),
            'reasons': row['reasons'],
        })

    incidents = group_incidents(table[alert_mask])

    breakdown = pred.loc[is_attack, 'predicted_label'].value_counts()
    normal_rows = pred[~is_attack]
    return {
        'success': True,
        'total_records': int(len(pred)),
        'normal': int((~is_attack).sum()),
        'attacks': int(is_attack.sum()),
        'anomalies': int(pred['is_anomaly'].sum()),
        'anomalies_not_known_attack': int(len(anomaly_only_idx)),
        'high_confidence_alerts': int((is_attack & (pred['confidence'] > HIGH_CONFIDENCE)).sum()),
        'attack_breakdown': {str(k): int(v) for k, v in breakdown.items()},
        'avg_confidence': float(pred['confidence'].mean()),
        'max_confidence': float(pred['confidence'].max()),
        'normal_high_conf': int((normal_rows['confidence'] > 0.8).sum()),
        'normal_medium_conf': int(((normal_rows['confidence'] >= 0.6) & (normal_rows['confidence'] <= 0.8)).sum()),
        'normal_low_conf': int((normal_rows['confidence'] < 0.6).sum()),
        'alerts': alerts,
        'incidents': incidents,
        'alerts_total': int(alert_mask.sum()),
        'output_csv': str(output_csv) if output_csv else None,
        'model': model.info(),
    }


def group_incidents(alert_rows: pd.DataFrame, limit=20):
    """Group alerts by (label, target host) so a scan of 300 ports is one line, not 300."""
    if alert_rows.empty:
        return []
    rows = alert_rows.copy()
    rows['label'] = rows['predicted_label'].where(rows['predicted_label'] != 'Normal', 'Unusual')
    incidents = []
    for (label, dst), g in rows.groupby(['label', 'dst_ip'], dropna=False):
        top = g.sort_values('severity', ascending=False).iloc[0]
        incidents.append({
            'label': label,
            'kind': 'anomaly' if label == 'Unusual' else 'known_attack',
            'dst_ip': _clean(dst),
            'connections': int(len(g)),
            'sources': int(g['src_ip'].nunique()),
            'top_sources': [str(x) for x in g['src_ip'].value_counts().head(3).index],
            'ports': int(g['dst_port'].nunique()),
            'first_ts': _clean(g['ts'].min()), 'last_ts': _clean(g['ts'].max()),
            'max_confidence': round(float(g['confidence'].max()), 4),
            'severity': round(float(g['severity'].max()), 4),
            'reasons': top['reasons'],
        })
    incidents.sort(key=lambda x: (x['severity'], x['connections']), reverse=True)
    return incidents[:limit]


def main(argv=None):
    ap = argparse.ArgumentParser(description='Score a Zeek conn log with the NetAnomaly model')
    ap.add_argument('--zeek_conn', required=True, help='Path to a Zeek conn log (TSV or JSON)')
    ap.add_argument('--model', default=str(DEFAULT_MODEL_PATH))
    ap.add_argument('--output', default='predictions.csv', help='Where to write the per-connection CSV')
    args = ap.parse_args(argv)
    try:
        model = load_model(args.model)
        summary = score_conn_log(args.zeek_conn, model, args.output)
    except Exception as e:  # print JSON so callers can always parse the output
        print(json.dumps({'success': False, 'error': str(e)}))
        return 1
    print(json.dumps(summary, default=_clean))
    return 0


if __name__ == '__main__':
    sys.exit(main())
