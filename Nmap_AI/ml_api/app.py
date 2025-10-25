import os
import subprocess
import json
import time
import signal
import sys
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import joblib
import pandas as pd
import numpy as np

app = Flask(__name__)
CORS(app)

# Configuration
PCAP_DIR = Path('pcaps')
RESULTS_DIR = Path('results')
MODEL_PATH = Path('../network_anomaly_detection_model.joblib')

# Ensure directories exist
PCAP_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

# Load model once at startup
try:
    model = joblib.load(MODEL_PATH)
    print(f"✅ Model loaded successfully from {MODEL_PATH}")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    model = None

# Global variable to store tcpdump process
tcpdump_process = None

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'timestamp': time.time()
    })

@app.route('/api/analysis/start-tcpdump', methods=['POST'])
def start_tcpdump():
    """Start tcpdump to capture network traffic"""
    global tcpdump_process
    
    try:
        data = request.json or {}
        duration = data.get('duration', 30)  # default 30 seconds
        interface = data.get('interface', 'eth0')  # default interface
        
        # Stop any existing tcpdump
        if tcpdump_process:
            try:
                tcpdump_process.terminate()
                tcpdump_process.wait(timeout=5)
            except:
                pass
        
        # Generate unique pcap filename
        timestamp = int(time.time())
        pcap_file = PCAP_DIR / f'capture_{timestamp}.pcap'
        
        # Start tcpdump
        cmd = ['tcpdump', '-i', interface, '-w', str(pcap_file), '-s', '0']
        tcpdump_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Schedule automatic stop after duration
        def stop_after_duration():
            time.sleep(duration)
            if tcpdump_process:
                tcpdump_process.terminate()
        
        import threading
        timer = threading.Thread(target=stop_after_duration, daemon=True)
        timer.start()
        
        return jsonify({
            'success': True,
            'message': f'tcpdump started for {duration} seconds',
            'pcap_file': str(pcap_file),
            'pid': tcpdump_process.pid,
            'duration': duration
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/analysis/stop-tcpdump', methods=['POST'])
def stop_tcpdump():
    """Stop currently running tcpdump"""
    global tcpdump_process
    
    try:
        if tcpdump_process:
            tcpdump_process.terminate()
            tcpdump_process.wait(timeout=5)
            tcpdump_process = None
            return jsonify({
                'success': True,
                'message': 'tcpdump stopped successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'No tcpdump process running'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/analysis/score', methods=['POST'])
def score_pcap():
    """Run scorer.py on pcap file and return results"""
    try:
        data = request.json or {}
        pcap_file = data.get('pcap_file')
        
        if not pcap_file or not Path(pcap_file).exists():
            return jsonify({
                'success': False,
                'error': 'Invalid pcap file path'
            }), 400
        
        # Convert pcap to Zeek format first
        # For now, we'll assume the scorer.py handles this or you have a conversion tool
        # Run scorer.py
        output_file = RESULTS_DIR / f'scored_{int(time.time())}.csv'
        
        cmd = [
            sys.executable,
            'scorer.py',
            '--zeek_conn', pcap_file,  # Adjust based on your actual usage
            '--model', str(MODEL_PATH),
            '--output', str(output_file)
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode == 0 and output_file.exists():
            return jsonify({
                'success': True,
                'message': 'Scoring completed',
                'output_file': str(output_file),
                'logs': result.stdout
            })
        else:
            return jsonify({
                'success': False,
                'error': result.stderr or 'Scoring failed'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/analysis/predict', methods=['POST'])
def predict():
    """Run ML model predictions on scored data"""
    if model is None:
        return jsonify({
            'success': False,
            'error': 'Model not loaded'
        }), 500
    
    try:
        data = request.json or {}
        csv_file = data.get('csv_file')
        
        if not csv_file or not Path(csv_file).exists():
            return jsonify({
                'success': False,
                'error': 'Invalid CSV file path'
            }), 400
        
        # Load the scored data
        df = pd.read_csv(csv_file)
        
        # Extract features (adjust columns based on your model)
        feature_columns = [col for col in df.columns if col not in ['pred_class', 'pred_confidence']]
        X = df[feature_columns]
        
        # Make predictions
        predictions = model.predict(X)
        probabilities = model.predict_proba(X)
        
        # Add predictions to dataframe
        df['predicted_class'] = predictions
        df['confidence'] = probabilities.max(axis=1)
        
        # Class names
        class_names = ['Normal', 'DoS', 'Probe', 'Privilege', 'Access']
        df['attack_type'] = df['predicted_class'].apply(lambda x: class_names[x] if x < len(class_names) else 'Unknown')
        
        # Save results
        output_file = RESULTS_DIR / f'predictions_{int(time.time())}.csv'
        df.to_csv(output_file, index=False)
        
        # Generate summary statistics
        summary = {
            'total_records': len(df),
            'normal': int((df['predicted_class'] == 0).sum()),
            'attacks': int((df['predicted_class'] != 0).sum()),
            'attack_breakdown': df[df['predicted_class'] != 0]['attack_type'].value_counts().to_dict(),
            'high_confidence_alerts': int((df['confidence'] > 0.8).sum())
        }
        
        return jsonify({
            'success': True,
            'message': 'Predictions completed',
            'output_file': str(output_file),
            'summary': summary
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@app.route('/api/analysis/download/<filename>', methods=['GET'])
def download_file(filename):
    """Download generated files"""
    try:
        file_path = RESULTS_DIR / filename
        if file_path.exists() and file_path.is_file():
            return send_file(file_path, as_attachment=True)
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analysis/list-files', methods=['GET'])
def list_files():
    """List all available result files"""
    try:
        files = []
        for file_path in RESULTS_DIR.glob('*'):
            if file_path.is_file():
                files.append({
                    'name': file_path.name,
                    'size': file_path.stat().st_size,
                    'modified': file_path.stat().st_mtime
                })
        files.sort(key=lambda x: x['modified'], reverse=True)
        return jsonify({'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting ML API Server...")
    print(f"📁 PCAP Directory: {PCAP_DIR.absolute()}")
    print(f"📁 Results Directory: {RESULTS_DIR.absolute()}")
    print(f"🤖 Model Path: {MODEL_PATH.absolute()}")
    app.run(host='0.0.0.0', port=5000, debug=True)
