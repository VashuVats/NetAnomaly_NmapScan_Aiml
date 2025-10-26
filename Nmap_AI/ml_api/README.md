# ML API - Network Anomaly Detection

This is the Python Flask API that handles network traffic capture, scoring, and ML-based anomaly detection.

## Setup

### 1. Install Dependencies

```bash
cd ml_api
pip install -r requirements.txt
```

Or use a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Prerequisites

- Python 3.8 or higher
- **Zeek** (formerly Bro) - Required for PCAP to conn.log conversion
  - Ubuntu/Debian: `sudo apt-get install zeek`
  - macOS: `brew install zeek`
  - For other systems: https://zeek.org/get-zeek/
- **tcpdump** - For network traffic capture
  - Ubuntu/Debian: `sudo apt-get install tcpdump`
  - macOS: `brew install tcpdump`
  - Windows: Use Wireshark or install via WSL
- The `network_anomaly_detection_model.joblib` file in the parent directory
- The `scorer.py` script accessible in the ml_api directory

### 3. Running the API

```bash
python app.py
```

The API will start on `http://localhost:5000`

## Workflow

The ML API follows this complete workflow:

1. **Capture**: `tcpdump` captures network traffic to a PCAP file
2. **Convert**: Zeek converts PCAP to `conn.log` format (JSON or TSV)
3. **Score**: `scorer.py` processes the Zeek log and extracts features
4. **Predict**: ML model predicts anomalies in the scored data
5. **Results**: User gets download links for scored CSV and prediction results

## Endpoints

- `GET /health` - Health check
- `POST /api/analysis/start-tcpdump` - Start traffic capture
- `POST /api/analysis/stop-tcpdump` - Stop traffic capture
- `POST /api/analysis/score` - Score captured pcap file
  - Converts PCAP → Zeek conn.log → Runs scorer.py
- `POST /api/analysis/predict` - Run ML model predictions
- `GET /api/analysis/list-files` - List result files
- `GET /api/analysis/download/<filename>` - Download result file

## Configuration

Edit `app.py` to configure:
- `PCAP_DIR` - Directory for captured files (default: `pcaps/`)
- `RESULTS_DIR` - Directory for result files (default: `results/`)
- `MODEL_PATH` - Path to the ML model (default: `../network_anomaly_detection_model.joblib`)

## Troubleshooting

### Zeek Installation Issues

1. **Zeek not found**: Make sure Zeek is installed and in your PATH
   ```bash
   zeek --version
   ```

2. **Zeek conversion fails**: Check that the PCAP file is valid
   ```bash
   zeek -r <pcap_file> -w conn.log
   ```

### tcpdump Issues

1. **Permission denied**: Run tcpdump with sudo or add user to pcap group
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
   ```

2. **Interface not found**: Check available interfaces
   ```bash
   tcpdump -D
   ```

### Model Loading Issues

1. **Model not found**: Check that `network_anomaly_detection_model.joblib` exists in parent directory
2. **Model incompatible**: Ensure the model was trained with the same feature set as `scorer.py` expects

### scorer.py Issues

1. **Import errors**: Make sure all dependencies are installed
   ```bash
   pip install joblib numpy pandas scikit-learn
   ```

2. **Column mismatch**: The model expects specific feature columns. Check that `scorer.py` and the model are compatible.

### Common Errors

- **"Failed to generate Zeek conn.log"**: PCAP file might be empty or corrupted
- **"scorer.py did not produce output"**: Check scorer.py logs for errors
- **"Model prediction failed"**: Feature columns don't match model expectations
