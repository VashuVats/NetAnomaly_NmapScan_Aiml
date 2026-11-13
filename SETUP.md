# NetScan AI - Complete Setup Guide

## Overview

NetScan AI is a comprehensive network security analysis platform with two main components:
1. **Nmap Scanner** - AI-powered network scanning with Gemini integration
2. **ML Analysis** - Machine learning-based anomaly detection for network traffic

## Architecture

```
┌─────────────────┐
│   Frontend      │  React + Vite (Port 3000)
│   (React)       │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│   Node.js Backend                       │  Express (Port 3001)
│   - /api/scan (Nmap)                   │
│   - /api/ai-summary (Gemini)           │
│   - /api/analysis (ML Proxy)           │
└────────┬────────────────────────────────┘
         │
         │ Proxies to
         ▼
┌─────────────────────────────────────────┐
│   Python ML API                         │  Flask (Port 5000)
│   - tcpdump management                  │
│   - scorer.py execution                 │
│   - ML model predictions                │
└─────────────────────────────────────────┘
```

## Prerequisites

### System Requirements
- **Node.js** (v18 or higher)
- **Python** (3.8 or higher)
- **tcpdump** (for network capture)
- **Nmap** (for network scanning)

### Install System Tools

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y nmap tcpdump python3 python3-pip
```

**macOS:**
```bash
brew install nmap tcpdump python@3.11
```

**Windows:**
- Install Nmap: https://nmap.org/download.html
- Install Wireshark (includes tcpdump)
- Install Python: https://www.python.org/downloads/

## Setup Instructions

### 1. Backend Setup

```bash
cd Nmap_AI/backend

# Install dependencies
npm install

# Create .env file
cp ../env.example .env

# Edit .env and add your Gemini API key
# GEMINI_API_KEY=your_api_key_here
# GEMINI_MODEL=gemini-flash-latest
# NODE_ENV=development
# PORT=3001
# ML_API_URL=http://localhost:5000
# NVD_API_KEY=            (optional, free, makes CVE lookups faster)
```

Never commit `.env`. It is in `.gitignore`.

### 2. Frontend Setup

```bash
cd Nmap_AI/frontend/NMAP_AI_Scanner

# Install dependencies
npm install

# Optional. In development Vite forwards /api to http://localhost:3001 by itself.
# VITE_API_URL=http://localhost:3001
```

The app has a light and a dark theme (switch in the top right; "Auto" follows your system).

### 3. ML API Setup

```bash
cd Nmap_AI/ml_api

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 4. Model

A trained model is already in `Nmap_AI/ml_api/models/netanomaly_model.joblib`.
If pip installed different scikit-learn or LightGBM versions, retrain it once (about 30 seconds):

```bash
cd Nmap_AI/ml_api
python train.py --dataset nslkdd --data ../../KDD+.txt
```

See `Nmap_AI/ml_api/README.md` for training on UWF-ZeekData22 or on your own normal traffic.

## Running the Application

### Option 1: Manual Start (Recommended for Development)

**Terminal 1 - ML API:**
```bash
cd Nmap_AI/ml_api
source venv/bin/activate  # or venv\Scripts\activate on Windows
python app.py
```

**Terminal 2 - Node.js Backend:**
```bash
cd Nmap_AI/backend
npm start
```

**Terminal 3 - React Frontend:**
```bash
cd Nmap_AI/frontend/NMAP_AI_Scanner
npm run dev
```

### Option 2: Using Docker (Future Enhancement)

```bash
docker-compose up
```

## Access the Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:3001
- **ML API**: http://localhost:5000

## Testing

### Test Nmap Scanner
1. Go to http://localhost:3000
2. Enter a target (e.g., `scanme.nmap.org`)
3. Select scan type
4. Click "Start Scan"
5. View results and AI analysis

### Test ML Analysis
1. Go to http://localhost:3000/analysis
2. Configure capture duration and interface
3. Click "Start Capture"
4. Wait for capture to complete
5. Click "Run Scorer"
6. Click "Run ML Model"
7. View analysis results

## Troubleshooting

### Port Already in Use

**Change ML API Port:**
Set an environment variable before starting it:
```bash
ML_API_PORT=5001 python app.py
```

**Change Backend Port:**
Edit `Nmap_AI/backend/.env`:
```
PORT=3002
```

**Change Frontend Port:**
Edit `Nmap_AI/frontend/NMAP_AI_Scanner/vite.config.js`:
```javascript
server: { port: 3001 }
```

### tcpdump Permission Errors

**Linux/Mac:**
```bash
sudo chmod +s /usr/sbin/tcpdump
```

Or run with sudo (less secure):
```bash
sudo python app.py
```

### Model Not Found

Check that `models/netanomaly_model.joblib` exists in `Nmap_AI/ml_api`, or retrain it with
`python train.py --dataset nslkdd --data ../../KDD+.txt`.

### Gemini API Errors

1. Get API key from: https://aistudio.google.com/apikey
2. If you see "model not available", set `GEMINI_MODEL` in `.env` to a current model name.
3. Add to `Nmap_AI/backend/.env`:
```
GEMINI_API_KEY=your_key_here
```

## Development Tips

### Adding New Features

1. **Backend API**: Add routes in `Nmap_AI/backend/routes/`
2. **Frontend**: Add components in `Nmap_AI/frontend/NMAP_AI_Scanner/src/components/`
3. **ML Processing**: Modify `Nmap_AI/ml_api/app.py`

### Debugging

**Backend Logs:**
```bash
cd Nmap_AI/backend
DEBUG=* npm start
```

**ML API Logs:**
Already has debug mode enabled in development

**Frontend DevTools:**
Open browser DevTools and check Console tab

## Production Deployment

### Backend
```bash
cd Nmap_AI/backend
NODE_ENV=production npm start
```

### Frontend
```bash
cd Nmap_AI/frontend/NMAP_AI_Scanner
npm run build
# Serve the dist/ directory with nginx or similar
```

### ML API
```bash
cd Nmap_AI/ml_api
source venv/bin/activate
# Use a production WSGI server like gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## License

MIT License - See LICENSE file for details
