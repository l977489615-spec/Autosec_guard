import sys
import subprocess
import tempfile
import os
import json
import importlib.util
import traceback
import time
import logging
import bcrypt
import jwt
import datetime
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from functools import wraps

# This server must be running on the device connected to the vehicle (e.g., Raspberry Pi/Laptop)
# Run with: python3 server.py

# ==========================================
# Configure Logging
# ==========================================
LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)
log_file = os.path.join(LOGS_DIR, 'autosec.log')

# Setup Rotating File Handler (Max 5MB per file, keep 3 backups)
handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
handler.setFormatter(formatter)

# Configure the root logger
logger = logging.getLogger('AutosecServer')
logger.setLevel(logging.INFO)
logger.addHandler(handler)
# Also log to stdout
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": "*"}})  # Allow React Frontend to communicate

# Path to the Pocs directory
POCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pocs')

# ==========================================
# Application Configuration
# ==========================================

# Secret Key for JWT
app.config['SECRET_KEY'] = 'autosec_super_secret_key_change_in_production'

# Database Configuration (MySQL)
# Default format: mysql+pymysql://username:password@server/db
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:1@localhost/autosec_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ==========================================
# Database Models
# ==========================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user') # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at.isoformat()
        }

class ScanHistory(db.Model):
    __tablename__ = 'scan_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_id = db.Column(db.String(100), nullable=True) # E.g., global scan frontend ID
    target_ip = db.Column(db.String(50), nullable=True)
    target_mac = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), nullable=False) # 'completed', 'failed', 'running'
    started_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    results_json = db.Column(db.Text, nullable=True) # Full JSON data of results
    risk_score = db.Column(db.Integer, default=0)

    user = db.relationship('User', backref=db.backref('scans', lazy=True))

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.user.username if self.user else "Unknown",
            "session_id": self.session_id,
            "target_ip": self.target_ip,
            "target_mac": self.target_mac,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "risk_score": self.risk_score,
            "results_json": json.loads(self.results_json) if self.results_json else []
        }

# ==========================================
# Authentication Helpers
# ==========================================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith("Bearer "):
            return jsonify({'message': 'Token is missing or invalid format!'}), 401
        
        token = token.split(" ")[1]
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                return jsonify({'message': 'Token corresponds to a non-existent user!'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401

        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'admin':
            return jsonify({'message': 'Admin privileges required!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# ==========================================
# Auth Endpoints
# ==========================================

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists!"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # First user gets admin privileges automatically
    role = 'admin' if User.query.count() == 0 else 'user'
    
    new_user = User(username=username, password_hash=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()
    logger.info(f"New user registered: {username} (Role: {role})")

    return jsonify({"message": "User created successfully!", "role": role}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Could not verify", "WWWW-Authenticate": "Basic auth='Login required'"}), 401

    user = User.query.filter_by(username=data.get('username')).first()
    if not user:
        return jsonify({"message": "User not found!"}), 404

    if bcrypt.checkpw(data.get('password').encode('utf-8'), user.password_hash.encode('utf-8')):
        token = jwt.encode({
            'user_id': user.id,
            'role': user.role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        logger.info(f"User logged in: {user.username}")
        return jsonify({'token': token, 'user': user.to_dict()})

    return jsonify({"message": "Invalid password!"}), 401

@app.route('/api/profile', methods=['GET', 'PUT'])
@token_required
def profile(current_user):
    if request.method == 'GET':
        return jsonify({"user": current_user.to_dict()})
        
    if request.method == 'PUT':
        data = request.json
        new_username = data.get('new_username')
        new_password = data.get('new_password')
        
        updates_made = False
        
        if new_username and new_username != current_user.username:
            # Check if username is already taken by someone else
            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user:
                return jsonify({"message": "Username already exists!"}), 400
            current_user.username = new_username
            updates_made = True
            
        if new_password:
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            current_user.password_hash = hashed_password
            updates_made = True
            
        if updates_made:
            db.session.commit()
            logger.info(f"User {current_user.id} updated their profile.")
            return jsonify({"message": "Profile updated successfully!", "user": current_user.to_dict()}), 200
            
        return jsonify({"message": "No changes requested."}), 200

# ==========================================
# Admin Endpoints
# ==========================================

@app.route('/api/admin/users', methods=['GET'])
@cross_origin()
@token_required
@admin_required
def admin_get_users(current_user):
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({"users": [user.to_dict() for user in users]})

@app.route('/api/admin/users', methods=['POST'])
@cross_origin()
@token_required
@admin_required
def admin_create_user(current_user):
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')

    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists!"}), 400

    if role not in ['admin', 'user']:
        return jsonify({"message": "Invalid role specified!"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    new_user = User(username=username, password_hash=hashed_password, role=role)
    
    db.session.add(new_user)
    db.session.commit()
    logger.info(f"Admin {current_user.username} created new user: {username} ({role})")

    return jsonify({"message": "User created successfully!", "user": new_user.to_dict()}), 201

@app.route('/api/admin/users/<int:user_id>', methods=['PUT', 'OPTIONS'])
@cross_origin()
@token_required
@admin_required
def admin_update_user(current_user, user_id):
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    target_user = User.query.get(user_id)
    if not target_user:
        return jsonify({"message": "User not found!"}), 404

    data = request.json
    new_username = data.get('username')
    new_password = data.get('password')
    new_role = data.get('role')

    updates_made = False

    if new_username and new_username != target_user.username:
        if User.query.filter_by(username=new_username).first():
            return jsonify({"message": "Username already exists!"}), 400
        target_user.username = new_username
        updates_made = True

    if new_role and new_role in ['admin', 'user'] and new_role != target_user.role:
        # Prevent admin from accidentally demoting themselves if they are the only admin
        if target_user.id == current_user.id and new_role == 'user':
            admin_count = User.query.filter_by(role='admin').count()
            if admin_count <= 1:
                return jsonify({"message": "Cannot demote the only remaining administrator!"}), 400
        target_user.role = new_role
        updates_made = True

    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        target_user.password_hash = hashed_password
        updates_made = True

    if updates_made:
        db.session.commit()
        logger.info(f"Admin {current_user.username} updated user ID {user_id}")
        return jsonify({"message": "User updated successfully!", "user": target_user.to_dict()}), 200

    return jsonify({"message": "No changes requested."}), 200

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE', 'OPTIONS'])
@cross_origin()
@token_required
@admin_required
def admin_delete_user(current_user, user_id):
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    target_user = User.query.get(user_id)
    if not target_user:
        return jsonify({"message": "User not found!"}), 404

    if target_user.id == current_user.id:
        return jsonify({"message": "Cannot delete your own active admin account!"}), 400

    username = target_user.username
    
    # Cascade delete scan history
    ScanHistory.query.filter_by(user_id=user_id).delete()
    
    db.session.delete(target_user)
    db.session.commit()
    
    logger.warning(f"Admin {current_user.username} DELETED user: {username}")
    return jsonify({"message": f"User {username} deleted successfully!"}), 200

@app.route('/api/health', methods=['GET'])
def health_check():
    """Check if the execution engine is online."""
    return jsonify({"status": "online", "system": sys.platform, "pocs_dir": POCS_DIR})

@app.route('/api/list_pocs', methods=['GET'])
def list_pocs():
    """List all available PoC plugin files in pocs/ directory tree with metadata."""
    pocs = []
    if not os.path.isdir(POCS_DIR):
        return jsonify({"error": "Pocs directory not found", "path": POCS_DIR}), 404

    for dirpath, dirnames, filenames in os.walk(POCS_DIR):
        # Ignore hidden directories and .venv
        dirnames[:] = [d for d in dirnames if not d.startswith('.') and d != '.venv' and d != '__pycache__']
        
        for filename in sorted(filenames):
            if filename.endswith('.py') and not filename.startswith('__') and filename != 'iv_plugin_base.py':
                filepath = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(filepath, POCS_DIR)
                poc_info = {
                    "filename": rel_path,
                    "filepath": filepath,
                    "size": os.path.getsize(filepath),
                    "category_dir": os.path.basename(dirpath) if dirpath != POCS_DIR else "root"
                }
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        poc_info['content'] = content
                        if 'cve_id' in content:
                            for line in content.splitlines():
                                if 'cve_id' in line and '=' in line:
                                    cve = line.split('=')[-1].strip().strip('"\'')
                                    poc_info['cve_id'] = cve
                                    break
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
    # Optional authorization to link scan to a user
    current_user = None
    token = request.headers.get('Authorization')
    if token and token.startswith("Bearer "):
        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            pass

    data = request.json
    poc_filename = data.get('filename')
    params = data.get('params', {}).copy() # Use a copy to avoid mutating source if needed
    session_id = data.get('session_id', 'manual')

    # Parameter mapping for plugin compatibility (ip -> target_ip, port -> target_port)
    if 'ip' in params and 'target_ip' not in params:
        params['target_ip'] = params['ip']
    if 'port' in params and 'target_port' not in params:
        params['target_port'] = params['port']
    if 'bluetooth_mac' in params and 'target_mac' not in params:
        params['target_mac'] = params['bluetooth_mac']

    if not poc_filename:
        return jsonify({"error": "No PoC filename provided"}), 400

    # Support both "category/filename.py" and bare "filename.py" lookups
    poc_path = os.path.join(POCS_DIR, poc_filename)
    if not os.path.exists(poc_path):
        # Fallback: search subdirectories for the basename
        basename = os.path.basename(poc_filename)
        found = False
        for dirpath, _, filenames in os.walk(POCS_DIR):
            if basename in filenames:
                poc_path = os.path.join(dirpath, basename)
                found = True
                break
        if not found:
            logger.warning(f"PoC file not found: {poc_filename}")
            return jsonify({"error": f"PoC file not found: {poc_filename}"}), 404

    logger.info(f"Starting PoC Execution: {poc_filename} w/ Params: {params}")
    start_time = time.time()

    try:
        # Load the plugin module dynamically
        # Ensure iv_plugin_base can be imported by adding POCS_DIR to sys.path
        if POCS_DIR not in sys.path:
            sys.path.insert(0, POCS_DIR)
            
        spec = importlib.util.spec_from_file_location(poc_filename.replace('.py', ''), poc_path)
        module = importlib.util.module_from_spec(spec)
        
        # Explicitly load iv_plugin_base as well
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
            "elapsed_seconds": elapsed,
            "poc_id": poc_filename
        }
        
        status_msg = "VULNERABLE" if response["vulnerable"] else "SECURE"
        logger.info(f"PoC Result [{poc_filename}]: {status_msg} (Elapsed: {elapsed}s)")
        
        # Save to database if authenticated
        if current_user:
            try:
                history = ScanHistory(
                    user_id=current_user.id,
                    session_id=session_id,
                    target_ip=params.get('target_ip'),
                    target_mac=params.get('target_mac'),
                    status='completed',
                    completed_at=datetime.datetime.utcnow(),
                    results_json=json.dumps(response),
                    risk_score=10 if response["vulnerable"] else 0
                )
                db.session.add(history)
                db.session.commit()
            except Exception as dbe:
                logger.error(f"Failed to save scan history: {str(dbe)}")

        return jsonify(response)

    except Exception as e:
        elapsed = round(time.time() - start_time, 2)
        tb = traceback.format_exc()
        logger.error(f"Exception in PoC [{poc_filename}]: {str(e)}\n{tb}")
        return jsonify({
            "success": False,
            "logs": [],
            "errors": [str(e), traceback.format_exc()],
            "vulnerable": False,
            "elapsed_seconds": elapsed
        })

@app.route('/api/history', methods=['GET'])
@token_required
def get_history(current_user):
    """Get scan history with RBAC (Admin sees all, User sees own)"""
    if current_user.role == 'admin':
        # Admin sees all history, ordered by newest first
        scans = ScanHistory.query.order_by(ScanHistory.started_at.desc()).limit(100).all()
    else:
        # User sees only their own history
        scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.started_at.desc()).limit(100).all()
    
    return jsonify({"history": [scan.to_dict() for scan in scans]})

@app.route('/api/execute', methods=['POST'])
def execute_script():
    """Receives a Python script string, executes it locally, and returns stdout/stderr."""
    data = request.json
    script_content = data.get('script')
    
    if not script_content:
        logger.warning("Received execute_script request with no script content.")
        return jsonify({"error": "No script content provided"}), 400

    logger.info(f"Received interactive execution request (Script size: {len(script_content)} bytes)")
    start_time = time.time()

    # Create a temporary file to run the script
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_script:
        temp_script.write(script_content)
        temp_script_path = temp_script.name

    try:
        # Add POCS_DIR to PYTHONPATH so the script can import iv_plugin_base
        env = os.environ.copy()
        current_pythonpath = env.get('PYTHONPATH', '')
        env['PYTHONPATH'] = f"{POCS_DIR}{os.pathsep}{current_pythonpath}" if current_pythonpath else POCS_DIR

        # EXECUTE THE SCRIPT REAL-TIME
        # We capture stdout/stderr to stream back to the UI
        # Timeout set to 120s to prevent hanging
        process = subprocess.run(
            [sys.executable, temp_script_path],
            capture_output=True,
            text=True,
            timeout=120,
            env=env
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
        logger.error(f"Execute Script Timeout (120s limit reached)")
        return jsonify({
            "success": False, 
            "logs": ["[-] Execution Timed Out (120s limit reached)"], 
            "errors": ["Timeout"],
            "vulnerable": False,
            "elapsed_seconds": elapsed
        })
    except Exception as e:
        elapsed = round(time.time() - start_time, 2)
        tb = traceback.format_exc()
        logger.error(f"Execute Script Exception: {str(e)}\n{tb}")
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
    logger.info(f"AutoSec Execution Engine starting on port 5002...")
    logger.info(f"PoCs directory: {POCS_DIR}")
    
    poc_count = 0
    categories = []
    for dp, dn, fn in os.walk(POCS_DIR):
        # Ignore hidden directories and .venv
        dn[:] = [d for d in dn if not d.startswith('.') and d != '.venv' and d != '__pycache__']
        if dp != POCS_DIR:
            categories.append(os.path.basename(dp))
        for f in fn:
            if f.endswith('.py') and f != 'iv_plugin_base.py' and not f.startswith('__'):
                poc_count += 1
                
    logger.info(f"Available PoC files: {poc_count} across {len(categories)} categories: {', '.join(sorted(categories))}")
    # Bind to 0.0.0.0 to allow access if frontend is on a different device
    # Disable flask default click logger to favor our custom logger
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='0.0.0.0', port=5002, debug=True, use_reloader=False)
