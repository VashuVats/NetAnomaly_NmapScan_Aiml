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
- tcpdump installed on your system
- The `network_anomaly_detection_model.joblib` file in the parent directory
- The `scorer.py` script accessible

### 3. Running the API

```bash
python app.py
```

The API will start on `http://localhost:5000`

## Endpoints

- `GET /health` - Health check
- `POST /api/analysis/start-tcpdump` - Start traffic capture
- `POST /api/analysis/stop-tcpdump` - Stop traffic capture
- `POST /api/analysis/score` - Score captured pcap file
- `POST /api/analysis/predict` - Run ML model predictions
- `GET /api/analysis/list-files` - List result files
- `GET /api/analysis/download/<filename>` - Download result file

## Configuration

Edit `app.py` to configure:
- `PCAP_DIR` - Directory for captured files
- `RESULTS_DIR` - Directory for result files
- `MODEL_PATH` - Path to the ML model

## Troubleshooting

1. **tcpdump not found**: Install tcpdump on your system
   - Ubuntu/Debian: `sudo apt-get install tcpdump`
   - macOS: `brew install tcpdump`
   - Windows: Use Wireshark or install via WSL

2. **Model not loading**: Check that `network_anomaly_detection_model.joblib` exists in parent directory

3. **Port already in use**: Change port in `app.py` (default: 5000)
