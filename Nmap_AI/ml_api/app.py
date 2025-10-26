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

        # Copy conn_log to a consistent results path (keep original)
        final_log = output_dir / f'conn_{timestamp}.log'
        try:
            # Always copy, never move - preserve original file
            shutil.copy2(str(conn_log), str(final_log))
            print(f"✅ Copied conn log: {conn_log} -> {final_log}")
        except Exception as e:
            print(f"❌ Error copying conn log: {e}")
            return jsonify({
                'error': f'Failed to copy conn log: {str(e)}',
                'conn_log': str(conn_log),
                'final_log': str(final_log)
            }), 500

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
            print(f"🔍 Looking for conn_log: {p}")
            if not p.exists():
                p = (RESULTS_DIR / Path(conn_log).name)
                print(f"🔍 Trying RESULTS_DIR: {p}")
            if not p.exists():
                p = (PCAP_DIR / Path(conn_log).name)
                print(f"🔍 Trying PCAP_DIR: {p}")
            if p.exists():
                candidate = p.resolve()
                print(f"✅ Found conn_log: {candidate}")
            else:
                print(f"❌ conn_log not found: {conn_log}")

        if candidate is None:
            # Look for conn logs in RESULTS_DIR subdirectories first, then PCAP_DIR
            conn_files = []
            
            print(f"🔍 Searching for conn logs in RESULTS_DIR subdirectories...")
            # First, look in RESULTS_DIR subdirectories (zeek_* folders)
            for zeek_dir in RESULTS_DIR.glob('zeek_*'):
                if zeek_dir.is_dir():
                    found_logs = list(zeek_dir.glob('conn*.log'))
                    print(f"🔍 Found {len(found_logs)} logs in {zeek_dir}")
                    conn_files.extend(found_logs)
            
            print(f"🔍 Searching for conn logs directly in RESULTS_DIR...")
            # Then look directly in RESULTS_DIR
            direct_logs = list(RESULTS_DIR.glob('conn*.log'))
            print(f"🔍 Found {len(direct_logs)} logs in RESULTS_DIR")
            conn_files.extend(direct_logs)
            
            # Finally, fallback to PCAP_DIR
            if not conn_files:
                print(f"🔍 Searching for conn logs in PCAP_DIR...")
                conn_files = sorted(list(PCAP_DIR.glob('conn*.log')) + list(PCAP_DIR.glob('conn*.log.*')),
                                    key=lambda p: p.stat().st_mtime, reverse=True)
                print(f"🔍 Found {len(conn_files)} logs in PCAP_DIR")
            
            if not conn_files:
                print("❌ No conn logs found anywhere!")
                return jsonify({'success': False, 'error': 'No conn log found on server'}), 400
            
            # Sort by modification time and pick newest
            conn_files = sorted(conn_files, key=lambda p: p.stat().st_mtime, reverse=True)
            candidate = conn_files[0].resolve()
            print(f"✅ Selected newest conn_log: {candidate}")

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

        # If scorer wrote the CSV, ensure it exists and analyze results
        if output_csv.exists():
            parsed_meta['output_csv'] = str(output_csv)
            
            # Analyze the CSV results to provide meaningful statistics
            try:
                df = pd.read_csv(output_csv)
                
                # Calculate statistics
                total_records = len(df)
                normal_count = len(df[df['predicted_class'] == 0]) if 'predicted_class' in df.columns else 0
                attack_count = len(df[df['predicted_class'] != 0]) if 'predicted_class' in df.columns else 0
                
                # High confidence alerts (only for attack classes with confidence > 0.8)
                high_conf_alerts = 0
                if 'confidence' in df.columns and 'predicted_class' in df.columns:
                    # Only count as high confidence alerts if:
                    # 1. It's an attack (predicted_class != 0)
                    # 2. Confidence is truly high (> 0.8)
                    attack_records = df[df['predicted_class'] != 0]
                    high_conf_alerts = len(attack_records[attack_records['confidence'] > 0.8])
                
                # Attack type breakdown
                attack_breakdown = {}
                if 'predicted_class' in df.columns:
                    attack_types = df[df['predicted_class'] != 0]['predicted_class'].value_counts()
                    attack_type_names = {0: 'Normal', 1: 'DoS', 2: 'Probe', 3: 'R2L', 4: 'U2R'}
                    attack_breakdown = {attack_type_names.get(k, f'Class_{k}'): int(v) for k, v in attack_types.items()}
                
                # Calculate confidence statistics
                avg_confidence = float(df['confidence'].mean()) if 'confidence' in df.columns else 0.0
                max_confidence = float(df['confidence'].max()) if 'confidence' in df.columns else 0.0
                
                # Count confidence levels for normal traffic
                normal_high_conf = 0
                normal_medium_conf = 0
                normal_low_conf = 0
                
                if 'confidence' in df.columns and 'predicted_class' in df.columns:
                    normal_records = df[df['predicted_class'] == 0]
                    if len(normal_records) > 0:
                        normal_high_conf = len(normal_records[normal_records['confidence'] > 0.8])
                        normal_medium_conf = len(normal_records[(normal_records['confidence'] >= 0.6) & (normal_records['confidence'] <= 0.8)])
                        normal_low_conf = len(normal_records[normal_records['confidence'] < 0.6])

                # Add calculated statistics to response
                parsed_meta.update({
                    'total_records': int(total_records),
                    'normal': int(normal_count),
                    'attacks': int(attack_count),
                    'high_confidence_alerts': int(high_conf_alerts),
                    'attack_breakdown': attack_breakdown,
                    'avg_confidence': avg_confidence,
                    'max_confidence': max_confidence,
                    'normal_high_conf': int(normal_high_conf),
                    'normal_medium_conf': int(normal_medium_conf),
                    'normal_low_conf': int(normal_low_conf)
                })
                
            except Exception as e:
                parsed_meta['analysis_error'] = f'Failed to analyze CSV results: {str(e)}'
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
        
        # List files in RESULTS_DIR
        for file_path in RESULTS_DIR.glob('*'):
            if file_path.is_file():
                files.append({
                    'name': file_path.name,
                    'path': str(file_path),
                    'size': file_path.stat().st_size,
                    'modified': file_path.stat().st_mtime,
                    'type': 'result_file'
                })
        
        # List conn logs in subdirectories
        for zeek_dir in RESULTS_DIR.glob('zeek_*'):
            if zeek_dir.is_dir():
                for conn_file in zeek_dir.glob('conn*.log'):
                    files.append({
                        'name': conn_file.name,
                        'path': str(conn_file),
                        'size': conn_file.stat().st_size,
                        'modified': conn_file.stat().st_mtime,
                        'type': 'conn_log',
                        'directory': zeek_dir.name
                    })
        
        # List PCAP files
        for pcap_file in PCAP_DIR.glob('*.pcap'):
            files.append({
                'name': pcap_file.name,
                'path': str(pcap_file),
                'size': pcap_file.stat().st_size,
                'modified': pcap_file.stat().st_mtime,
                'type': 'pcap_file'
            })
        
        files.sort(key=lambda x: x['modified'], reverse=True)
        return jsonify({
            'files': files,
            'total_files': len(files),
            'conn_logs': len([f for f in files if f['type'] == 'conn_log']),
            'pcap_files': len([f for f in files if f['type'] == 'pcap_file'])
        })
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
