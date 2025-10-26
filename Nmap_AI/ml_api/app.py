import os
import sys
import time
import json
import subprocess
import gzip
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import joblib
import pandas as pd
import numpy as np
import shutil
import stat
from shutil import which

app = Flask(__name__)
CORS(app)

# Configuration
BASE_DIR = Path(__file__).parent.resolve()
PCAP_DIR = (BASE_DIR / 'pcaps')
RESULTS_DIR = (BASE_DIR / 'results')
# prefer a saved joblib model in the parent project root (adjust via env if needed)
MODEL_PATH = BASE_DIR / 'network_anomaly_detection_model.joblib'

# Ensure directories exist (create parents, use absolute paths)
PCAP_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
for d in [PCAP_DIR, RESULTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)
    if os.name != 'nt':  # For Linux/WSL
        import stat
        os.chmod(str(d), stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

print(f"Directories initialized:\nPCAPs: {PCAP_DIR}\nResults: {RESULTS_DIR}")

# Load model once at startup (safe load)
model = None
try:
    if MODEL_PATH.exists():
        model = joblib.load(MODEL_PATH)
        print(f"✅ Model loaded successfully from {MODEL_PATH}")
    else:
        print(f"⚠️ Model path does not exist: {MODEL_PATH}")
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
    """Convert PCAP to Zeek logs"""
    try:
        # Find newest PCAP file
        pcaps = list(PCAP_DIR.glob('*.pcap'))
        if not pcaps:
            return jsonify({'error': 'No PCAP files found'}), 400

        candidate = max(pcaps, key=lambda p: p.stat().st_mtime)

        # Create unique output directory with timestamp inside RESULTS_DIR
        timestamp = int(time.time())
        output_dir = RESULTS_DIR / f'zeek_{timestamp}'
        output_dir.mkdir(parents=True, exist_ok=True)

        # Ensure output_dir permissions allow Zeek to write
        if os.name != 'nt':
            os.chmod(str(output_dir), stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

        # Locate zeek binary
        zeek_bin = which('zeek') or '/usr/bin/zeek'  # fallback common path
        if not Path(zeek_bin).exists():
            return jsonify({'error': f'Zeek binary not found. Checked: {zeek_bin}'}), 500

        # Run Zeek with working dir = output_dir so logs land there
        zeek_cmd = [
            zeek_bin,
            '-C',                      # no checksums
            '-r', str(candidate.absolute())  # full path to pcap
        ]

        print(f"Running Zeek:\nCommand: {' '.join(zeek_cmd)}\nPCAP: {candidate}\nOutput dir: {output_dir}")

        result = subprocess.run(
            zeek_cmd,
            capture_output=True,
            text=True,
            cwd=str(output_dir),
            check=False  # capture failure and show stdout/stderr
        )

        # Debug info
        print("Zeek returncode:", result.returncode)
        print("Zeek stdout:", result.stdout)
        print("Zeek stderr:", result.stderr)
        files_after = [f.name for f in output_dir.glob('*')]
        print("Files in output_dir:", files_after)

        # Look for any conn log file (supports conn.log, conn_*.log, conn.log.gz, conn_*.log.gz)
        conn_candidates = list(output_dir.glob('conn*.log')) + list(output_dir.glob('conn*.log.*')) + list(output_dir.glob('conn*.log.gz'))
        conn_log = conn_candidates[0] if conn_candidates else None

        if not conn_log:
            # If not found in output_dir, also check PCAP_DIR and RESULTS_DIR root (legacy runs)
            legacy = list(PCAP_DIR.glob('conn*.log')) + list(RESULTS_DIR.glob('conn*.log*'))
            conn_log = legacy[0] if legacy else None

        if not conn_log:
            return jsonify({
                'error': 'Zeek did not produce conn log',
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'output_dir_files': files_after,
                'pcap': str(candidate)
            }), 500

        # Move (or rename) conn_log into a consistent results path (use shutil.move to handle cross-fs)
        final_log = output_dir / f'conn_{timestamp}.log'
        try:
            shutil.move(str(conn_log), str(final_log))
        except Exception as e:
            # fallback: copy then remove
            shutil.copy2(str(conn_log), str(final_log))
            try:
                conn_log.unlink()
            except Exception:
                pass

        return jsonify({
            'success': True,
            'message': 'Zeek analysis completed',
            'conn_log': str(final_log),
            'pcap_analyzed': str(candidate),
            'zeek_returncode': result.returncode,
            'zeek_stdout': result.stdout[:2000],
            'zeek_stderr': result.stderr[:2000]
        })

    except subprocess.CalledProcessError as e:
        return jsonify({
            'error': 'Zeek command failed',
            'stdout': e.stdout,
            'stderr': e.stderr
        }), 500
    except Exception as e:
        import traceback
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@app.route('/api/analysis/predict', methods=['POST'])
def predict():
    """
    Run scorer.py on a Zeek conn log and (optionally) run the ML model.
    Returns the JSON printed by scorer.py plus helpful fields.
    """
    try:
        data = request.json or {}
        conn_log = data.get('conn_log')

        # Resolve conn_log: provided path or newest in results/ or pcaps/
        candidate = None
        if conn_log:
            p = Path(conn_log)
            if not p.exists():
                p = (RESULTS_DIR / Path(conn_log).name)
            if not p.exists():
                p = (PCAP_DIR / Path(conn_log).name)
            if p.exists():
                candidate = p.resolve()

        if candidate is None:
            # prefer newest conn_*.log in RESULTS_DIR, fallback to PCAP_DIR
            conn_files = sorted(list(RESULTS_DIR.glob('conn*.log')) + list(RESULTS_DIR.glob('conn*.log.*')),
                                key=lambda p: p.stat().st_mtime, reverse=True)
            if not conn_files:
                conn_files = sorted(list(PCAP_DIR.glob('conn*.log')) + list(PCAP_DIR.glob('conn*.log.*')),
                                    key=lambda p: p.stat().st_mtime, reverse=True)
            if not conn_files:
                return jsonify({'success': False, 'error': 'No conn log found on server'}), 400
            candidate = conn_files[0].resolve()

        if not candidate.exists():
            return jsonify({'success': False, 'error': f'conn log not found: {str(candidate)}'}), 400

        # Prepare scorer command
        timestamp = int(time.time())
        output_csv = RESULTS_DIR / f'predictions_{timestamp}.csv'
        scorer_py = Path(__file__).parent / 'scorer.py'
        if not scorer_py.exists():
            return jsonify({'success': False, 'error': f'scorer.py not found at {scorer_py}'}), 500

        cmd = [
            sys.executable,
            str(scorer_py),
            '--zeek_conn', str(candidate),
            '--output', str(output_csv)
        ]
        # include model if present
        if MODEL_PATH and Path(MODEL_PATH).exists():
            cmd += ['--model', str(MODEL_PATH)]

        # Run scorer.py and capture stdout (it returns JSON)
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        stdout = (proc.stdout or '').strip()
        stderr = (proc.stderr or '').strip()

        # Attempt to parse JSON output
        parsed = None
        try:
            # scorer.py prints a single JSON object to stdout
            parsed = json.loads(stdout) if stdout else {}
        except Exception:
            parsed = {'raw_stdout': stdout, 'raw_stderr': stderr}

        # Add helpful metadata
        parsed_meta = {
            'success': proc.returncode == 0,
            'returncode': proc.returncode,
            'scorer_stdout': stdout[:4000],
            'scorer_stderr': stderr[:4000],
            'zeek_conn': str(candidate),
            'output_csv': str(output_csv),
        }
        # merge parsed (preferring parsed keys)
        if isinstance(parsed, dict):
            parsed_meta.update(parsed)
        else:
            parsed_meta['scorer_output'] = parsed

        # If scorer wrote the CSV, ensure it exists
        if output_csv.exists():
            parsed_meta['output_csv'] = str(output_csv)
        else:
            # if scorer reported a different output path, include it
            if 'output_csv' in parsed_meta and Path(parsed_meta['output_csv']).exists():
                parsed_meta['output_csv'] = parsed_meta['output_csv']
            else:
                parsed_meta['warning'] = 'Output CSV not found after scorer run'

        status_code = 200 if proc.returncode == 0 else 500
        return jsonify(parsed_meta), status_code

    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

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

@app.route('/api/analysis/reload-model', methods=['POST'])
def reload_model():
    """Reload joblib model from disk (admin)"""
    global model, MODEL_PATH
    try:
        path = Path(os.environ.get('ML_MODEL_PATH', str(MODEL_PATH)))
        if not path.exists():
            return jsonify({'success': False, 'error': f'Model file not found: {path}'}), 400
        model = joblib.load(path)
        return jsonify({'success': True, 'message': f'Model reloaded from {path}'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting ML API Server...")
    print(f"📁 PCAP Directory: {PCAP_DIR.absolute()}")
    print(f"📁 Results Directory: {RESULTS_DIR.absolute()}")
    print(f"🤖 Model Path: {MODEL_PATH.absolute()}")
    app.run(host='0.0.0.0', port=5000, debug=True)
