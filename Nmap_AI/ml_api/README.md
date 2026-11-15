# ML API - network anomaly detection

This Flask API captures traffic, turns it into Zeek connection logs, and scores each
connection with the NetAnomaly model.

## How it works

1. **Capture**: `tcpdump` saves traffic to a pcap file.
2. **Convert**: Zeek turns the pcap into `conn.log` (one row per connection).
3. **Features**: `features.py` builds 26 features for every connection. These are the
   NSL-KDD features that can be worked out from a conn log: protocol, service, state,
   bytes, and the "how many connections to this host / service in the last 2 seconds and
   last 100 connections" counters. Training and live scoring use the **same code**, so the
   model sees the same thing in both places.
4. **Predict**: `scorer.py` runs two models:
   - a **LightGBM classifier** that names known attack types (DoS, Probe, R2L, U2R), and
   - an **Isolation Forest** trained only on normal traffic, which flags anything unusual
     even if it is not a known attack.
5. **Explain**: every alert comes with its top reasons (from LightGBM's built-in SHAP values),
   for example "Share of this host's last connections that were half-open (SYN errors): 100%".
   Alerts are also grouped into **incidents** (one line per attack type and target), so a
   300-port scan shows up as one incident instead of 300 rows.

## Setup

```bash
cd Nmap_AI/ml_api
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py                 # http://127.0.0.1:5000
```

You also need **Zeek** (`zeek --version`) and **tcpdump** (`tcpdump -D`) on the machine that
captures traffic. On Windows, run the ML API inside WSL.

The model in `models/` was trained with scikit-learn 1.9.1 and LightGBM 4.7.0. If pip installs
other versions, retrain once (about 30 seconds):

```bash
python train.py --dataset nslkdd --data ../../KDD+.txt
```

## Training

`train.py` trains, tests and saves the model, and writes `models/MODEL_CARD.md` with the results.

```bash
# NSL-KDD. KDD+.txt in the repo root is KDDTrain+ (first 125,973 rows) and KDDTest+ (last 22,544)
python train.py --dataset nslkdd --data ../../KDD+.txt

# UWF-ZeekData22: real Zeek conn logs labelled with MITRE ATT&CK tactics.
# Download the CSV or parquet files from https://datasets.uwf.edu/ into one folder, then:
pip install pyarrow
python train.py --dataset uwf --data data/uwf-zeekdata22/

# Teach the "unusual traffic" detector what normal looks like on YOUR network.
# Capture a few minutes of ordinary traffic, run Zeek on it, then:
python train.py --dataset nslkdd --data ../../KDD+.txt --baseline-conn path/to/normal_conn.log
```

After retraining, restart the API or call `POST /api/analysis/reload-model`.

### Current results (NSL-KDD, real test set)

| Model | Accuracy | Macro F1 | False alarms | Attacks caught |
|---|---|---|---|---|
| Random Forest, random split (the old way, misleading) | 99.9% | 84.9% | 0.1% | 99.8% |
| Random Forest, real test set | 76.1% | 51.8% | 2.6% | 62.0% |
| **LightGBM, real test set (used by the app)** | **77.2%** | **54.2%** | 2.9% | 64.5% |
| LightGBM + unusual-traffic detector together | | | 3.1% | 72.6% |

The random-split number looks great because the test rows are almost copies of training rows.
The real NSL-KDD test set has new attack types on purpose, which is much closer to real life.
See `models/MODEL_CARD.md` for per-class results and the confusion matrix.

**Known limits:** NSL-KDD traffic is from 1998-99. R2L and U2R attacks (password guessing,
buffer overflows) are mostly invisible to connection-level features, because they look like
normal connections. Catching them needs payload inspection, for example Suricata.

## Endpoints

- `GET /health` - status, and whether the model is loaded
- `POST /api/analysis/start-tcpdump` - start a capture `{duration: 5-600, interface}`
- `POST /api/analysis/stop-tcpdump` - stop the capture
- `POST /api/analysis/score` - run Zeek on a capture `{pcap_file?}` (newest if not given)
- `POST /api/analysis/predict` - score a conn log `{conn_log?}` (newest if not given).
  Returns counts, `attack_breakdown`, `incidents`, `alerts` with reasons, and `model` info.
- `GET /api/analysis/list-files` - list captures and results
- `GET /api/analysis/download/<filename>` - download a file from `results/`
- `POST /api/analysis/reload-model` - load the model again after retraining

## Settings (environment variables)

| Name | Default | What it does |
|---|---|---|
| `ML_API_HOST` | `127.0.0.1` | Address to listen on. Keep it local unless you need remote access. |
| `ML_API_PORT` | `5000` | Port |
| `ML_MODEL_PATH` | `models/netanomaly_model.joblib` | Model file |
| `ALLOWED_INTERFACES` | (any) | Comma-separated list of interfaces capture may use |
| `FLASK_DEBUG` | off | Never turn this on when other machines can reach the API |

## Tests

```bash
pip install pytest
python -m pytest tests
```

`tests/make_sample_conn.py` writes a made-up conn log with normal traffic, a port scan and a SYN
flood (`tests/fixtures/sample_conn.log`). You can score it without Zeek:

```bash
python scorer.py --zeek_conn tests/fixtures/sample_conn.log --output predictions.csv
```

## Troubleshooting

- **Zeek not found**: install it and check `zeek --version`.
- **tcpdump permission denied**: `sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)`
- **Interface not found**: list them with `tcpdump -D`.
- **Model not found / version warning**: retrain with `train.py` as shown above.
- **No connections in the conn log**: capture for longer, or check you picked the right interface.
