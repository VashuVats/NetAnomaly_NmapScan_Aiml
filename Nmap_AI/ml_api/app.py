import os
import sys
import time
import json
import subprocess
import gzip
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import shutil
import stat
import re
import threading
from shutil import which

from scorer import load_model, score_conn_log

app = Flask(__name__)
# Only the Node backend and the local frontend should call this API.
CORS(app, origins=os.environ.get('ML_API_CORS_ORIGINS', 'http://localhost:3000,http://localhost:3001').split(','))

# Capture limits
MIN_CAPTURE_SECONDS = 5
MAX_CAPTURE_SECONDS = 600
INTERFACE_RE = re.compile(r'^[A-Za-z0-9_.:\-]{1,64}$')
SAFE_FILENAME_RE = re.compile(r'^[A-Za-z0-9_.\-]{1,128}$')


def allowed_interfaces():
    raw = os.environ.get('ALLOWED_INTERFACES', '').strip()
    return [i.strip() for i in raw.split(',') if i.strip()]


def validate_interface(name):
    """Return an error message if the interface name is not allowed, else None."""
    if not isinstance(name, str) or not INTERFACE_RE.match(name):
        return 'Invalid interface name'
    allowed = allowed_interfaces()
    if allowed and name not in allowed:
        return f'Interface not allowed. Allowed: {", ".join(allowed)}'
    return None

# Configuration
BASE_DIR = Path(__file__).parent.resolve()
PCAP_DIR = (BASE_DIR / 'pcaps')
RESULTS_DIR = (BASE_DIR / 'results')
MODEL_PATH = Path(os.environ.get('ML_MODEL_PATH', str(BASE_DIR / 'models' / 'netanomaly_model.joblib')))

# Ensure directories exist
for d in [PCAP_DIR, RESULTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)
    if os.name != 'nt':  # Zeek and tcpdump may run as another user on Linux/WSL
        os.chmod(str(d), stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

print(f"Directories initialized:\nPCAPs: {PCAP_DIR}\nResults: {RESULTS_DIR}")

# Load the model once at startup
model = None
model_error = None


def load_current_model():
    global model, model_error
    try:
        model = load_model(MODEL_PATH)
        model_error = None
        print(f"Model loaded from {MODEL_PATH}")
    except FileNotFoundError:
        model, model_error = None, (f'Model file not found: {MODEL_PATH}. Train one with: '
                                    'python train.py --dataset nslkdd --data ../../KDD+.txt')
        print(model_error)
    except Exception as e:
        model, model_error = None, f'Could not load model: {e}'
        print(model_error)


load_current_model()

# Global variable to store tcpdump process
tcpdump_process = None

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'model_error': model_error,
        'model': model.info() if model is not None else None,
        'timestamp': time.time()
    })

@app.route('/api/analysis/start-tcpdump', methods=['POST'])
def start_tcpdump():
    """Start tcpdump to capture network traffic"""
    global tcpdump_process
    
    try:
        data = request.json or {}
        try:
            duration = int(data.get('duration', 30))
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'duration must be a whole number of seconds'}), 400
        if not MIN_CAPTURE_SECONDS <= duration <= MAX_CAPTURE_SECONDS:
            return jsonify({'success': False, 'error': f'duration must be between {MIN_CAPTURE_SECONDS} and {MAX_CAPTURE_SECONDS} seconds'}), 400
        interface = data.get('interface', 'eth0')
        iface_error = validate_interface(interface)
        if iface_error:
            return jsonify({'success': False, 'error': iface_error}), 400
        
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
        
        # Schedule automatic stop after duration (only stop the process we started)
        proc = tcpdump_process

        def stop_after_duration():
            time.sleep(duration)
            if proc.poll() is None:
                proc.terminate()

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
        # Use the requested capture (by file name, inside PCAP_DIR) or the newest one
        requested = (request.json or {}).get('pcap_file') if request.is_json else None
        if requested:
            candidate = PCAP_DIR / Path(str(requested)).name
            if not candidate.is_file():
                return jsonify({'error': f'Capture not found: {candidate.name}'}), 400
        else:
            pcaps = list(PCAP_DIR.glob('*.pcap'))
            if not pcaps:
                return jsonify({'error': 'No capture files found. Start a capture first.'}), 400
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
        app.logger.exception('Zeek step failed')
        return jsonify({'error': str(e)}), 500

def resolve_conn_log(requested):
    """Find the conn log to score: the requested one (only inside our folders) or the newest."""
    roots = [RESULTS_DIR.resolve(), PCAP_DIR.resolve()]
    if requested:
        name = Path(str(requested)).name
        candidates = [Path(str(requested))] + [r / name for r in roots] + list(RESULTS_DIR.glob(f'zeek_*/{name}'))
        for c in candidates:
            try:
                c = c.resolve()
            except OSError:
                continue
            if c.is_file() and any(root in c.parents for root in roots):
                return c
        return None
    logs = list(RESULTS_DIR.glob('zeek_*/conn*.log')) + list(RESULTS_DIR.glob('conn*.log')) + list(PCAP_DIR.glob('conn*.log'))
    return max(logs, key=lambda p: p.stat().st_mtime).resolve() if logs else None


@app.route('/api/analysis/predict', methods=['POST'])
def predict():
    """Score a Zeek conn log with the model and return a summary, alerts and incidents."""
    if model is None:
        return jsonify({'success': False, 'error': model_error or 'Model not loaded'}), 503
    data = request.json or {}
    conn_log = resolve_conn_log(data.get('conn_log'))
    if conn_log is None:
        return jsonify({'success': False, 'error': 'No conn log found. Capture traffic and run Zeek first.'}), 400
    output_csv = RESULTS_DIR / f'predictions_{int(time.time())}.csv'
    try:
        summary = score_conn_log(conn_log, model, output_csv)
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e), 'zeek_conn': conn_log.name}), 400
    except Exception as e:
        app.logger.exception('Scoring failed')
        return jsonify({'success': False, 'error': f'Scoring failed: {e}'}), 500
    summary['zeek_conn'] = str(conn_log)
    summary['output_csv'] = output_csv.name
    return jsonify(summary)

@app.route('/api/analysis/download/<filename>', methods=['GET'])
def download_file(filename):
    """Download generated files"""
    try:
        # Only plain file names inside RESULTS_DIR (no paths, no "..")
        if not SAFE_FILENAME_RE.match(filename or '') or filename.startswith('.'):
            return jsonify({'error': 'Invalid file name'}), 400
        file_path = (RESULTS_DIR / filename).resolve()
        if file_path.parent != RESULTS_DIR.resolve():
            return jsonify({'error': 'Invalid file name'}), 400
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
    """Reload the model from disk after retraining."""
    load_current_model()
    if model is None:
        return jsonify({'success': False, 'error': model_error}), 500
    return jsonify({'success': True, 'model': model.info()})

if __name__ == '__main__':
    print("🚀 Starting ML API Server...")
    print(f"📁 PCAP Directory: {PCAP_DIR.absolute()}")
    print(f"📁 Results Directory: {RESULTS_DIR.absolute()}")
    print(f"🤖 Model Path: {MODEL_PATH.absolute()}")
    # Debug mode lets anyone who can reach the port run code, so it is off unless asked for.
    host = os.environ.get('ML_API_HOST', '127.0.0.1')
    port = int(os.environ.get('ML_API_PORT', '5000'))
    debug = os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true')
    app.run(host=host, port=port, debug=debug)
