"""
scorer.py
- Parses Zeek conn.* logs (handles #fields header)
- Produces a CSV of parsed records (output)
- Optionally loads a joblib model and predicts (adds predicted_class, confidence)
- CLI: --zeek_conn <path> --model <path> --output <path>
"""
from pathlib import Path
import argparse
import joblib
import pandas as pd
import numpy as np
import sys
import json

# ---------- CONFIG ----------
WINDOW_SECONDS = 2.0
ALERT_PROB_THRESHOLD = 0.6
NUMERIC_FEATURES = [
    'duration','src_bytes','dst_bytes','wrong_fragment','urgent','hot',
    'num_failed_logins','num_compromised','root_shell','su_attempted',
    'num_root','num_file_creations','num_shells','num_access_files',
    'num_outbound_cmds','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]
CATEGORICAL_BASE = ['protocol_type', 'service', 'flag']
# ----------------------------

def read_zeek_conn(path):
    """
    Read Zeek conn.* log and return DataFrame.
    Handles header lines and '#fields' declaration.
    """
    fields = None
    rows = []
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for ln in f:
            if ln.startswith('#fields'):
                # strip '#fields' and split by tab
                parts = ln.strip().split('\t')
                # first token is '#fields'
                fields = parts[1:]
                continue
            if ln.startswith('#'):
                continue
            if not fields:
                continue
            parts = ln.rstrip('\n').split('\t')
            if len(parts) != len(fields):
                # tolerate mismatched lines by padding/truncating
                if len(parts) < len(fields):
                    parts += [''] * (len(fields) - len(parts))
                else:
                    parts = parts[:len(fields)]
            rows.append(parts)
    if not fields:
        raise ValueError("No '#fields' header found in conn log")
    df = pd.DataFrame(rows, columns=fields)
    # Try to coerce numeric columns where possible
    for col in ['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col].replace('-', np.nan), errors='coerce').fillna(0)
    return df

def build_feature_dataframe(conn_df):
    """
    Build a feature DataFrame matching NUMERIC_FEATURES + one-hot of categoricals.
    Missing numeric features are filled with 0.
    """
    feat = pd.DataFrame(index=conn_df.index)
    # map basics
    # duration
    if 'duration' in conn_df.columns:
        feat['duration'] = conn_df['duration'].astype(float)
    else:
        feat['duration'] = 0.0
    # bytes
    feat['src_bytes'] = conn_df['orig_bytes'] if 'orig_bytes' in conn_df.columns else 0
    feat['dst_bytes'] = conn_df['resp_bytes'] if 'resp_bytes' in conn_df.columns else 0

    # fill any other numeric features with zeros
    for n in NUMERIC_FEATURES:
        if n not in feat.columns:
            feat[n] = 0

    # categorical base
    proto_col = conn_df['proto'] if 'proto' in conn_df.columns else None
    svc_col = conn_df['service'] if 'service' in conn_df.columns else None
    flag_col = conn_df['conn_state'] if 'conn_state' in conn_df.columns else None

    cats = pd.DataFrame(index=conn_df.index)
    if proto_col is not None:
        cats['protocol_type'] = proto_col.fillna('-')
    if svc_col is not None:
        cats['service'] = svc_col.fillna('-')
    if flag_col is not None:
        cats['flag'] = flag_col.fillna('-')

    if not cats.empty:
        dummies = pd.get_dummies(cats.astype(str), dummy_na=False)
        # combine numeric + dummies
        final = pd.concat([feat, dummies], axis=1)
    else:
        final = feat.copy()
    # ensure no infinite or NaN
    final = final.replace([np.inf, -np.inf], 0).fillna(0)
    return final

def align_features_with_model(X, model):
    """
    Try to align X columns with model expected features.
    Uses model.feature_names_in_ when available.
    Returns X_aligned or raises ValueError.
    """
    if hasattr(model, 'feature_names_in_'):
        expected = list(model.feature_names_in_)
        missing = [c for c in expected if c not in X.columns]
        for m in missing:
            X[m] = 0
        # drop extras
        X = X.reindex(columns=expected, fill_value=0)
        return X[expected]
    # fallback: if model has n_features_in_, attempt to trim/pad
    if hasattr(model, 'n_features_in_'):
        n = model.n_features_in_
        if X.shape[1] == n:
            return X
        # if fewer, pad zeros with generic names (best-effort)
        if X.shape[1] < n:
            for i in range(n - X.shape[1]):
                X[f'_pad_{i}'] = 0
            return X.iloc[:, :n]
        # if more, drop right-most columns
        return X.iloc[:, :n]
    # last fallback: return X as-is
    return X

def main():
    parser = argparse.ArgumentParser(description='Score Zeek conn log with ML model')
    parser.add_argument('--zeek_conn', required=True, help='Path to Zeek conn log (can be conn.log or conn_*.log)')
    parser.add_argument('--model', required=False, help='Path to joblib model (optional)')
    parser.add_argument('--output', required=False, help='Output CSV path (default: predictions.csv)', default='predictions.csv')
    args = parser.parse_args()

    zeek_path = Path(args.zeek_conn)
    if not zeek_path.exists():
        print(json.dumps({'error':'zeek_conn not found','path':str(zeek_path)}))
        sys.exit(2)

    try:
        conn_df = read_zeek_conn(str(zeek_path))
    except Exception as e:
        print(json.dumps({'error':'failed_to_read_conn', 'message': str(e)}))
        sys.exit(3)

    # Save raw parsed CSV first
    out_path = Path(args.output)
    # build features
    X = build_feature_dataframe(conn_df)

    # Save feature CSV (so frontend/backend can inspect)
    try:
        X.to_csv(out_path, index=False)
    except Exception as e:
        print(json.dumps({'error':'failed_to_write_csv','message':str(e)}))
        sys.exit(4)

    result_obj = {'output_csv': str(out_path), 'n_records': int(len(X))}
    # if model provided, attempt prediction
    if args.model:
        model_path = Path(args.model)
        if not model_path.exists():
            result_obj['model_error'] = f'model not found: {model_path}'
            print(json.dumps(result_obj))
            sys.exit(0)
        try:
            model = joblib.load(str(model_path))
        except Exception as e:
            result_obj['model_error'] = f'failed to load model: {e}'
            print(json.dumps(result_obj))
            sys.exit(0)

        try:
            Xp = align_features_with_model(X.copy(), model)
            preds = None
            confidences = None
            # use predict_proba if available
            if hasattr(model, 'predict_proba'):
                probs = model.predict_proba(Xp)
                # choose class with max prob and max prob as confidence
                idx = np.argmax(probs, axis=1)
                preds = model.classes_[idx] if hasattr(model, 'classes_') else model.predict(Xp)
                confidences = probs[np.arange(len(idx)), idx]
            else:
                preds = model.predict(Xp)
                # no proba: confidence based on trees (if forest has predict_proba through wrapper)
                confidences = np.full(len(preds), 0.0)

            # attach to CSV
            out_df = X.copy()
            out_df['predicted_class'] = preds
            out_df['confidence'] = confidences
            out_df.to_csv(out_path, index=False)

            result_obj['predictions'] = str(out_path)
            result_obj['pred_count'] = int(len(out_df))
        except Exception as e:
            result_obj['model_error'] = f'prediction_failed: {e}'

    print(json.dumps(result_obj))
    sys.exit(0)

if __name__ == '__main__':
    main()
