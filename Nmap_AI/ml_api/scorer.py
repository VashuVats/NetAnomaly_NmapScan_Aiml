# score_zeek_batch.py
import argparse
import json
import time
from collections import deque, defaultdict
import joblib
import numpy as np
import pandas as pd
import os
import sys

# ---------- CONFIG ----------
WINDOW_SECONDS = 2.0    # window used to compute count/srv_count/same_srv_rate (match your training)
ALERT_PROB_THRESHOLD = 0.6  # tune based on validation
# numeric features you listed (ensure matches your training numeric_features)
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
CATEGORICAL_BASE = ['protocol_type', 'service', 'flag']  # we'll one-hot these from observed values
# ----------------------------

def load_model(model_path):
    try:
        model = joblib.load(model_path)
        return model
    except Exception as e:
        print(f"[!] Failed to load model {model_path}: {e}")
        sys.exit(1)

def read_train_columns(path):
    if not path or not os.path.exists(path):
        return None
    with open(path, 'r') as f:
        cols = [l.strip() for l in f if l.strip()]
    return cols

def parse_zeek_json_lines(path):
    """
    Reads a Zeek conn.log produced with JSON writer.
    It accepts either JSONL (one json per line) or a file that has a '[]' JSON array.
    Yields parsed dicts.
    """
    with open(path, 'r', errors='ignore') as f:
        first = f.read(2)
        f.seek(0)
        # attempt JSONL
        if first.startswith('['):
            # array of JSON objects
            data = json.load(f)
            for rec in data:
                yield rec
        else:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # some Zeek JSON lines have leading/trailing text; try to parse robustly
                try:
                    rec = json.loads(line)
                    yield rec
                except json.JSONDecodeError:
                    # try extracting first {...} chunk
                    start = line.find('{')
                    end = line.rfind('}')
                    if start != -1 and end != -1:
                        try:
                            rec = json.loads(line[start:end+1])
                            yield rec
                        except Exception:
                            continue
                    else:
                        continue

def zeek_to_base_row(rec):
    """Map Zeek conn.log fields to base row values (raw columns prior to OHE)"""
    # default safe conversions (use 0 / 'unknown' when missing)
    def safe_float(x, default=0.0):
        try:
            return float(x)
        except Exception:
            return default
    def safe_int(x, default=0):
        try:
            return int(float(x))
        except Exception:
            return default

    row = {}
    row['duration'] = safe_float(rec.get('duration', 0.0))
    row['src_bytes'] = safe_int(rec.get('orig_bytes', 0))
    row['dst_bytes'] = safe_int(rec.get('resp_bytes', 0))
    # fields that may not exist in Zeek conn.log: default to 0
    for nf in ['wrong_fragment','urgent','hot','num_failed_logins','num_compromised',
               'root_shell','su_attempted','num_root','num_file_creations','num_shells',
               'num_access_files','num_outbound_cmds',
               'serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
               'diff_srv_rate','srv_diff_host_rate',
               'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate',
               'dst_host_diff_srv_rate','dst_host_same_src_port_rate',
               'dst_host_srv_diff_host_rate','dst_host_serror_rate',
               'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate']:
        row[nf] = 0.0

    # categoricals
    row['protocol_type'] = rec.get('proto', 'unknown')
    # Zeek service can be '-' or many; default to 'unknown'
    svc = rec.get('service')
    if not svc or svc == '-':
        svc = 'unknown'
    row['service'] = svc
    # map conn_state -> flag (KDD flags are different but we keep raw conn_state)
    row['flag'] = rec.get('conn_state', 'OTH')

    # for aggregations
    row['_ts'] = safe_float(rec.get('ts', time.time()))
    row['_id_orig_h'] = rec.get('id.orig_h', None)
    row['_id_resp_h'] = rec.get('id.resp_h', None)

    return row

# Rolling aggregator for per-source computations (count, srv_count, same_srv_rate)
class RollingAggregator:
    def __init__(self, window_seconds=WINDOW_SECONDS):
        self.window = window_seconds
        self.per_host = defaultdict(lambda: deque())

    def add_and_compute(self, src_host, ts, service, dest_host):
        dq = self.per_host[src_host]
        dq.append((ts, service, dest_host))
        # remove old
        while dq and (ts - dq[0][0]) > self.window:
            dq.popleft()
        total = len(dq)
        srv_count = sum(1 for t,s,d in dq if s == service)
        same_srv_rate = srv_count / total if total > 0 else 0.0
        # dst_host_count = number of unique dest hosts in window
        dst_unique = len(set(d for _,_,d in dq if d))
        # other aggregated features can be computed similarly (placeholders used in training)
        return {
            'count': total,
            'srv_count': srv_count,
            'same_srv_rate': same_srv_rate,
            'dst_host_count': dst_unique,
            # keep other agg features zero/default unless you compute them
            'dst_host_srv_count': 0,
            'dst_host_same_srv_rate': 0.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }

def build_feature_dataframe(rows, observed_cat_values=None):
    """
    rows: list of base rows (dicts) containing numeric + categorical raw values
    observed_cat_values: dict mapping categorical -> set(values) optionally from training
    """
    df = pd.DataFrame(rows)
    # remove helper columns from df (we keep ts and hosts separately if needed)
    df_ts = df.get('_ts')
    df_src = df.get('_id_orig_h')
    df_dest = df.get('_id_resp_h')

    # Keep only the NUMERIC_FEATURES present; missing numeric fields will be filled later
    # But first handle categorical OHE for protocol_type, service, flag
    # Use observed_cat_values if provided to create consistent columns; otherwise use observed in data
    ohe_cols = []
    for cat in ['protocol_type','service','flag']:
        values = None
        if observed_cat_values and cat in observed_cat_values:
            values = list(observed_cat_values[cat])
        else:
            # use unique values in this batch
            values = sorted(df[cat].astype(str).unique().tolist())
        # create columns like protocol_type_tcp, service_http, flag_SF
        for v in values:
            col = f"{cat}__{v}"
            df[col] = (df[cat].astype(str) == str(v)).astype(int)
            ohe_cols.append(col)

    # Ensure all NUMERIC_FEATURES columns exist (fill missing with 0)
    for num in NUMERIC_FEATURES:
        if num not in df.columns:
            df[num] = 0.0

    # drop helper columns (but keep underlying numeric ones)
    # Keep ordering: numeric features first, then ohe cols (this order can be adjusted)
    final_cols = NUMERIC_FEATURES + ohe_cols
    final_df = df[final_cols].copy()

    # replace inf/nan
    final_df = final_df.replace([np.inf, -np.inf], 0).fillna(0)

    return final_df

def align_with_model_columns(df, model, train_cols_path=None):
    """
    Ensure df has exactly the columns model expects (or closest possible).
    1) If train_cols_path provided, use that exact raw column list (before preprocessing) to reorder/add zeros.
    2) Else, if model has attribute feature_names_in_, use that to reorder/add zeros.
    3) Else, try to match overlapping columns and add zeros for missing ones.
    Returns aligned_df (ordered to model expectation) and a note string.
    """
    # Try train_columns file
    if train_cols_path and os.path.exists(train_cols_path):
        with open(train_cols_path, 'r') as f:
            train_cols = [l.strip() for l in f if l.strip()]
        # add any missing train_cols to df with 0 values
        for c in train_cols:
            if c not in df.columns:
                df[c] = 0
        aligned = df[train_cols].copy()
        return aligned, f"Aligned using train_columns file ({train_cols_path}), missing cols filled with 0"
    # Try model.feature_names_in_
    feat_names = None
    try:
        if hasattr(model, 'feature_names_in_'):
            feat_names = list(model.feature_names_in_)
    except Exception:
        feat_names = None

    if feat_names:
        for c in feat_names:
            if c not in df.columns:
                df[c] = 0
        aligned = df[feat_names].copy()
        return aligned, "Aligned using model.feature_names_in_"
    # Last resort: try to use intersection (drop extra columns)
    common = [c for c in df.columns if c in getattr(model, 'coef_', {}) or c in getattr(model, 'feature_importances_', {}) or True]
    # The above line will just take all df.columns (fallback); better approach: use df.columns intersection with training columns if available
    # We do safe fallback: keep df columns, add no new ones
    return df.copy(), "No train columns or model.feature_names_in_; using available columns (may mismatch model expectation)"

def main(args):
    # Load model
    model = load_model(args.model)

    # Read training columns if provided
    train_cols = read_train_columns(args.train_cols) if args.train_cols else None

    # If user provided observed categorical values file (optional), load it - not implemented here; we rely on batch values

    # Read zeek conn log
    print("[*] Parsing Zeek conn log...")
    parsed = list(parse_zeek_json_lines(args.zeek_conn))
    if not parsed:
        print("[!] No records parsed from Zeek conn log. Exiting.")
        return

    # Convert Zeek records to base rows and compute rolling features
    agg = RollingAggregator(window_seconds=WINDOW_SECONDS)
    rows = []
    for rec in parsed:
        base = zeek_to_base_row(rec)
        # compute aggregates for this source host
        src = base.get('_id_orig_h') or base.get('_id_resp_h') or 'unknown_host'
        ts = base.get('_ts', time.time())
        svc = base.get('service', 'unknown')
        dst = base.get('_id_resp_h')
        a = agg.add_and_compute(src, ts, svc, dst)
        # update base with aggregated ones
        for k,v in a.items():
            base[k] = v
        rows.append(base)

    # Build DataFrame of features (one-hot for observed categories)
    print("[*] Building feature DataFrame (numeric + one-hot)...")
    feat_df = build_feature_dataframe(rows)

    # Align with model expected columns
    print("[*] Aligning feature columns with model expectation...")
    aligned_df, note = align_with_model_columns(feat_df, model, args.train_cols)
    print("[*] Alignment note:", note)
    # If columns mismatch model input size badly, warn user
    # Attempt prediction
    try:
        # if model pipeline was saved and expects raw features, it will handle preprocessing internally
        if hasattr(model, 'predict_proba'):
            probs = model.predict_proba(aligned_df)
            # multiclass: probs shape (n_samples, n_classes)
            # choose predicted class and confidence
            preds = model.predict(aligned_df)
            max_probs = probs.max(axis=1)
        else:
            preds = model.predict(aligned_df)
            max_probs = np.ones(len(preds))
    except Exception as e:
        print("[!] Model prediction failed:", e)
        print(" - possible causes: column mismatch or model expects different preprocessing (one-hot / scaling).")
        print(" - If you trained with separate preprocessing, ensure you saved a full Pipeline including transforms or provide train_columns.txt.")
        # try a fallback: if model has feature_importances_ length matching aligned_df columns, try converting ordering
        try:
            preds = model.predict(aligned_df.fillna(0))
            max_probs = np.ones(len(preds))
        except Exception as e2:
            print("[!] Fallback prediction also failed:", e2)
            return

    # Prepare output
    out = aligned_df.copy()
    out['pred_class'] = preds
    out['pred_confidence'] = max_probs
    # attach some original metadata for triage if present
    # we still have original parsed list order; add id/dest/ts columns if available in rows
    meta = []
    for r in rows:
        meta.append({
            'ts': r.get('_ts'),
            'id_orig_h': r.get('_id_orig_h'),
            'id_resp_h': r.get('_id_resp_h'),
            'service': r.get('service'),
            'protocol_type': r.get('protocol_type'),
            'flag': r.get('flag')
        })
    meta_df = pd.DataFrame(meta)
    out = pd.concat([meta_df.reset_index(drop=True), out.reset_index(drop=True)], axis=1)

    # Save CSV
    out_fname = args.output or 'scored_conn.csv'
    out.to_csv(out_fname, index=False)
    print(f"[*] Wrote scored output to {out_fname}")

    # Print alerts for probable attacks
    print("\n[*] Alerts (predicted attack classes != 0 OR confidence > threshold):")
    # assume class 0 = Normal, 1..4 = attack categories as you trained
    alerts = out[(out['pred_class'] != 0) | (out['pred_confidence'] >= ALERT_PROB_THRESHOLD)]
    if alerts.empty:
        print("No alerts found with current threshold/settings.")
    else:
        for idx, row in alerts.iterrows():
            print(f"ALERT: ts={row.get('ts')}, src={row.get('id_orig_h')}, dst={row.get('id_resp_h')}, svc={row.get('service')}, proto={row.get('protocol_type')}, pred_class={row.get('pred_class')}, conf={row.get('pred_confidence'):.3f}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Score Zeek conn.log JSON against a saved RF model.")
    parser.add_argument('--zeek_conn', required=True, help="Path to Zeek conn.log JSON file (JSONL or JSON array).")
    parser.add_argument('--model', required=True, help="Path to saved joblib model (e.g., network_anomaly_detection_model.joblib).")
    parser.add_argument('--train_cols', required=False, default=None, help="Optional path to newline-separated train column names file (raw columns before OHE).")
    parser.add_argument('--output', required=False, default='scored_conn.csv', help="Output CSV filename.")
    args = parser.parse_args()
    main(args)
