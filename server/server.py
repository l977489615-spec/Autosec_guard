import sys
import subprocess
import tempfile
import os
import json
import importlib.util
import traceback
import time
from flask import Flask, request, jsonify
from flask_cors import CORS

# This server must be running on the device connected to the vehicle (e.g., Raspberry Pi/Laptop)
# Run with: python3 server.py

app = Flask(__name__)
CORS(app)  # Allow React Frontend to communicate

# Path to the Pocs directory
POCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pocs')

@app.route('/api/health', methods=['GET'])
def health_check():
    """Check if the execution engine is online."""
    return jsonify({"status": "online", "system": sys.platform, "pocs_dir": POCS_DIR})

@app.route('/api/list_pocs', methods=['GET'])
def list_pocs():
    """List all available PoC plugin files in Pocs/ directory with metadata."""
    pocs = []
    if not os.path.isdir(POCS_DIR):
        return jsonify({"error": "Pocs directory not found", "path": POCS_DIR}), 404

    for filename in sorted(os.listdir(POCS_DIR)):
        if filename.endswith('.py') and not filename.startswith('__') and filename != 'iv_plugin_base.py':
            filepath = os.path.join(POCS_DIR, filename)
            poc_info = {
                "filename": filename,
                "filepath": filepath,
                "size": os.path.getsize(filepath)
            }
            # Try to extract metadata from the file
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    poc_info['content'] = content
                    # Extract CVE from results["cve_id"]
                    if 'cve_id' in content:
                        for line in content.splitlines():
                            if 'cve_id' in line and '=' in line:
                                cve = line.split('=')[-1].strip().strip('"\'')
                                poc_info['cve_id'] = cve
                                break
                    # Extract class name
                    for line in content.splitlines():
                        if line.strip().startswith('class ') and '(' in line:
                            poc_info['class_name'] = line.strip().split('(')[0].replace('class ', '').strip()
                            break
            except Exception:
                pass
            pocs.append(poc_info)

    return jsonify({"pocs": pocs, "total": len(pocs)})

@app.route('/api/fingerprint', methods=['POST'])
def fingerprint_os():
    """Detects target OS by quickly scanning signature ports (8000 for Qconn, 5555 for ADB)"""
    data = request.json
    target_ip = data.get('ip')
    
    if not target_ip or target_ip == 'N/A':
        return jsonify({"os": "unknown", "details": "No generic IP provided"})
        
    os_detected = "linux" # Default fallback for generalized car logic
    details = "Defaulting to generic Linux/Unknown"
    
    # 1. Quick probe port 8000 for QNX Qconn
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        if sock.connect_ex((target_ip, 8000)) == 0:
            os_detected = "qnx"
            details = "QNX Qconn service detected on port 8000"
        sock.close()
    except:
        pass
        
    # 2. Quick probe port 5555 for Android ADB
    if os_detected != "qnx":
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((target_ip, 5555)) == 0:
                os_detected = "android"
                details = "Android ADB service detected on port 5555"
            sock.close()
        except:
            pass

    return jsonify({
        "os": os_detected,
        "details": details
    })

@app.route('/api/run_poc', methods=['POST'])
def run_poc():
    """Run a specific PoC plugin by filename with given parameters."""
    data = request.json
    poc_filename = data.get('filename')
    params = data.get('params', {})

    if not poc_filename:
        return jsonify({"error": "No PoC filename provided"}), 400

    poc_path = os.path.join(POCS_DIR, poc_filename)
    if not os.path.exists(poc_path):
        return jsonify({"error": f"PoC file not found: {poc_filename}"}), 404

    print(f"[*] Running PoC: {poc_filename} with params: {params}")
    start_time = time.time()

    try:
        # Load the plugin module dynamically
        spec = importlib.util.spec_from_file_location(poc_filename.replace('.py', ''), poc_path)
        module = importlib.util.module_from_spec(spec)
        
        # Ensure iv_plugin_base can be imported
        base_path = os.path.join(POCS_DIR, 'iv_plugin_base.py')
        if os.path.exists(base_path):
            base_spec = importlib.util.spec_from_file_location('iv_plugin_base', base_path)
            base_module = importlib.util.module_from_spec(base_spec)
            sys.modules['iv_plugin_base'] = base_module
            base_spec.loader.exec_module(base_module)
        
        spec.loader.exec_module(module)
        
        # Find the plugin class (first class that inherits from IVIVulnerabilityPlugin)
        plugin_class = None
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and attr_name not in ['IVIVulnerabilityPlugin'] and hasattr(attr, 'run_verify'):
                plugin_class = attr
                break

        if not plugin_class:
            return jsonify({"error": "No valid plugin class found in file"}), 400

        # Instantiate and run
        plugin = plugin_class(params)
        
        # Capture stdout
        import io
        from contextlib import redirect_stdout, redirect_stderr
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        
        with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
            plugin.run_verify()

        elapsed = round(time.time() - start_time, 2)
        stdout_text = stdout_capture.getvalue()
        stderr_text = stderr_capture.getvalue()

        response = {
            "success": True,
            "logs": stdout_text.splitlines() if stdout_text else [],
            "errors": stderr_text.splitlines() if stderr_text else [],
            "vulnerable": plugin.results.get('vulnerable', False),
            "evidence": plugin.results.get('evidence', ''),
            "cve_id": plugin.results.get('cve_id', ''),
            "elapsed_seconds": elapsed
        }
        return jsonify(response)

    except Exception as e:
        elapsed = round(time.time() - start_time, 2)
        return jsonify({
            "success": False,
            "logs": [],
            "errors": [str(e), traceback.format_exc()],
            "vulnerable": False,
            "elapsed_seconds": elapsed
        })

@app.route('/api/execute', methods=['POST'])
def execute_script():
    """Receives a Python script string, executes it locally, and returns stdout/stderr."""
    data = request.json
    script_content = data.get('script')
    
    if not script_content:
        return jsonify({"error": "No script content provided"}), 400

    print(f"[*] Received execution request. Script size: {len(script_content)} bytes")
    start_time = time.time()

    # Create a temporary file to run the script
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_script:
        temp_script.write(script_content)
        temp_script_path = temp_script.name

    try:
        # EXECUTE THE SCRIPT REAL-TIME
        # We capture stdout/stderr to stream back to the UI
        # Timeout set to 120s to prevent hanging
        process = subprocess.run(
            [sys.executable, temp_script_path],
            capture_output=True,
            text=True,
            timeout=120 
        )

        output = process.stdout
        errors = process.stderr
        return_code = process.returncode
        elapsed = round(time.time() - start_time, 2)

        response = {
            "success": return_code == 0,
            "logs": output.splitlines() if output else [],
            "errors": errors.splitlines() if errors else [],
            "return_code": return_code,
            "elapsed_seconds": elapsed
        }
        
        # Determine vulnerability based on script output keywords
        # The script itself should print specific markers like "[+] VULNERABLE"
        if "[+] VULNERABLE" in output or "Vulnerability confirmed" in output or "【漏洞存在】" in output:
             response["vulnerable"] = True
        else:
             response["vulnerable"] = False

        return jsonify(response)

    except subprocess.TimeoutExpired:
        elapsed = round(time.time() - start_time, 2)
        return jsonify({
            "success": False, 
            "logs": ["[-] Execution Timed Out (120s limit reached)"], 
            "errors": ["Timeout"],
            "vulnerable": False,
            "elapsed_seconds": elapsed
        })
    except Exception as e:
        elapsed = round(time.time() - start_time, 2)
        return jsonify({
            "success": False, 
            "logs": [], 
            "errors": [str(e)],
            "vulnerable": False,
            "elapsed_seconds": elapsed
        })
    finally:
        # Cleanup temp file
        if os.path.exists(temp_script_path):
            os.remove(temp_script_path)

if __name__ == '__main__':
    print(f"[*] AutoSec Execution Engine starting on port 5002...")
    print(f"[*] PoCs directory: {POCS_DIR}")
    print(f"[*] Available PoC files: {len([f for f in os.listdir(POCS_DIR) if f.endswith('.py') and f != 'iv_plugin_base.py' and not f.startswith('__')])}")
    # Bind to 0.0.0.0 to allow access if frontend is on a different device
    app.run(host='0.0.0.0', port=5002, debug=True)
