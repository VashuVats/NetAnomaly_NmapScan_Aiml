# Complete ML Integration Summary

## Overview

The NetScanAI project now has a fully integrated workflow from network traffic capture to ML-based anomaly detection.

## Architecture

```
Frontend (React)
    ↓ HTTP Requests
Node.js Backend (Express)
    ↓ Proxies to
Python Flask API (ML API)
    ↓ Runs external tools
├── tcpdump (traffic capture)
├── Zeek (PCAP → conn.log conversion)
├── scorer.py (feature extraction)
└── ML Model (anomaly detection)
```

## Complete Workflow

### Step 1: Capture Network Traffic
- User clicks "Start Capture" on the frontend
- Frontend sends POST to `/api/analysis/start-tcpdump`
- ML API starts `tcpdump` process
- Traffic is captured to a PCAP file in `ml_api/pcaps/`

### Step 2: Stop Capture
- User clicks "Stop Capture" or timeout occurs
- ML API terminates the `tcpdump` process
- PCAP file is ready for processing

### Step 3: Score Traffic (PCAP → Features)
- User clicks "Score Traffic"
- Frontend sends POST to `/api/analysis/score` with PCAP file path
- **ML API performs:**
  1. **Zeek Conversion**: Runs `zeek -r <pcap> -w conn.log`
     - Converts PCAP to Zeek conn.log format
     - Can be TSV or JSON format
  2. **Zeek Log to JSON**: Converts TSV to JSON if needed
  3. **Feature Extraction**: Runs `scorer.py --zeek_conn <file> --model <model>`
     - Parses Zeek conn.log (handles both TSV and JSON)
     - Extracts 34+ numeric features + categorical features
     - Performs one-hot encoding for categoricals
     - Computes rolling window aggregations
     - Aligns features with model expectations
     - Outputs scored CSV file
- Frontend displays download link for scored CSV

### Step 4: ML Analysis
- User clicks "Run ML Analysis"
- Frontend sends POST to `/api/analysis/predict` with CSV file path
- **ML API performs:**
  1. Loads the scored CSV
  2. Extracts feature columns
  3. Runs ML model prediction
  4. Adds predictions, confidence scores, and attack types
  5. Generates summary statistics
  6. Saves results to predictions CSV
- Frontend displays results with:
  - Total records processed
  - Normal vs Attack breakdown
  - Attack type distribution
  - High-confidence alerts
  - Download link for predictions CSV

## Key Files

### Python ML API (`Nmap_AI/ml_api/app.py`)
- Handles all ML-related endpoints
- Manages tcpdump process lifecycle
- Orchestrates Zeek conversion
- Executes scorer.py
- Runs ML model predictions

### Scorer Script (`scorer.py` / `Nmap_AI/ml_api/scorer.py`)
- Parses Zeek conn.log (TSV or JSON)
- Extracts features matching KDD99 format
- One-hot encodes categorical features
- Computes rolling aggregations
- Aligns with ML model feature expectations

### Frontend (`Nmap_AI/frontend/NMAP_AI_Scanner/src/pages/Analysis.jsx`)
- 3-step wizard interface
- Capture, Score, and ML Analysis steps
- Real-time progress updates
- Error handling
- Download functionality

### Backend Controller (`Nmap_AI/backend/controllers/analysisController.js`)
- Proxies requests to Python ML API
- Handles CORS
- Manages request/response format

## Prerequisites

### System Requirements
1. **Python 3.8+** with packages:
   - flask, flask-cors
   - joblib, numpy, pandas, scikit-learn
   
2. **Zeek** (network analysis framework)
   - Convert PCAP to conn.log format
   - Installation: `` or `brew install zeek`
   
3. **tcpdump** (packet capture)
   - Capture network traffic
   - Installation: `apt-get install tcpdump`

4. **ML Model**
   - `network_anomaly_detection_model.joblib` in project root
   - Trained on KDD99 dataset

## Usage

1. **Start all services:**
   ```bash
   # Terminal 1: ML API
   cd Nmap_AI/ml_api
   python app.py
   
   # Terminal 2: Node.js Backend
   cd Nmap_AI/backend
   npm start
   
   # Terminal 3: React Frontend
   cd Nmap_AI/frontend/NMAP_AI_Scanner
   npm run dev
   ```

2. **Open browser**: http://localhost:5173

3. **Navigate to ML Analysis**: Click "ML Analysis" in header

4. **Complete workflow:**
   - Capture traffic for 30 seconds
   - Stop capture
   - Click "Score Traffic"
   - Click "Run ML Analysis"
   - View results and download files

## Error Handling

The system includes comprehensive error handling:
- **Network interface detection**: Auto-detects available interfaces
- **Empty PCAP handling**: Validates captured traffic
- **Zeek conversion errors**: Fallback and detailed error messages
- **Feature extraction errors**: Validates Zeek log format
- **Model prediction errors**: Validates feature alignment
- **Timeout protection**: 5-minute timeouts on long operations

## Outputs

### Scored CSV
Contains original Zeek features + extracted ML features + scoring metadata

### Predictions CSV  
Contains all scored features + predictions + confidence scores + attack types + summary statistics

## Future Enhancements

1. **Real-time streaming**: Process packets as they arrive
2. **Multiple model support**: Switch between different ML models
3. **Advanced visualizations**: Network graphs, timeline views
4. **Alert system**: Email/SMS notifications for high-confidence attacks
5. **Batch processing**: Analyze multiple PCAP files at once
