import sys
import subprocess
from typing import List, Dict, Any, Tuple
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
import re
import socket
import requests
import ast
import uuid
import base64
import hashlib
from logging.handlers import RotatingFileHandler
from pathlib import Path
from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from cryptography.fernet import Fernet, InvalidToken
from config import get_config, get_runtime_data_dir, get_runtime_warnings

def _get_utc_now() -> datetime.datetime:
    """Helper to return a naive UTC datetime, consistent across the app and DB."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
from assessment_engine import (
    build_structured_report,
    assess_physical_impact,
    generate_attack_graph,
    simulate_remediation,
)
from benchmark_suite import (
    load_benchmark_suite as load_benchmark_suite_data,
    score_benchmark_suite as run_benchmark_suite,
    score_session_against_benchmark as evaluate_session_against_benchmark,
)
from poc_worker import get_poc_worker
from poc_catalog import list_available_poc_names, resolve_poc_path, resolve_poc_source
from local_requirements import (
    classify_poc_execution_mode,
    local_capability_flags,
)
from poc_security import extract_poc_security_profile, should_require_disruptive_approval
from poc_execution_service import normalize_poc_params, resolve_target_label
from auth_service import resolve_user_from_bearer

# This server must be running on the device connected to the vehicle (e.g., Raspberry Pi/Laptop)
# Run with: python3 server.py

# ==========================================
# Configure Logging
# ==========================================
RUNTIME_DATA_DIR = get_runtime_data_dir()
LOGS_DIR = str(RUNTIME_DATA_DIR / 'logs')
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

SERVER_DIR = Path(__file__).resolve().parent
if getattr(sys, "frozen", False):
    SERVER_DIR = Path(getattr(sys, "_MEIPASS", SERVER_DIR))

WEB_DIST_CANDIDATES = [
    SERVER_DIR / 'web_dist',
    SERVER_DIR.parent / 'client' / 'dist',
    Path(sys.argv[0]).resolve().parent / 'web_dist' if sys.argv and sys.argv[0] else Path.cwd() / 'web_dist',
]

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": "*"}})  # Allow React Frontend to communicate

CONFIG = get_config()
RUNTIME_WARNINGS = get_runtime_warnings(CONFIG)

# Path to the Pocs directory
POCS_DIR = str(SERVER_DIR / 'pocs')
# ==========================================
# Application Configuration
# ==========================================

# Secret Key for JWT
app.config['SECRET_KEY'] = CONFIG.secret_key

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = CONFIG.database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

def _extract_session_target_ip(session: dict) -> str:
    connection = session.get("connection") or {}
    return str(
        session.get("targetIp")
        or session.get("target_ip")
        or connection.get("ip")
        or ""
    ).strip()


def _extract_session_report_date(session: dict) -> str:
    value = str(session.get("startTime") or session.get("started_at") or "").strip()
    return value or _get_utc_now().strftime('%Y-%m-%d %H:%M:%S')


def _extract_result_identifier(item: dict, index: int) -> str:
    for key in ("poc_name", "pocPath", "pocId", "name"):
        value = str(item.get(key) or "").strip()
        if value:
            return value
    return f"manual_scan_item_{index}"


def _extract_result_evidence(item: dict) -> str:
    for key in ("evidence", "details", "description", "error"):
        value = str(item.get(key) or "").strip()
        if value:
            return value
    return "No evidence recorded."


def _normalize_manual_execution_items(session: dict) -> list[dict]:
    execution_items: list[dict] = []
    for index, raw_item in enumerate(session.get("results") or [], start=1):
        item = raw_item if isinstance(raw_item, dict) else {}
        poc_name = _extract_result_identifier(item, index)
        vulnerable = bool(item.get("vulnerable"))
        evidence = _extract_result_evidence(item)
        execution_items.append({
            "step": index,
            "poc_name": poc_name,
            "status": "vulnerable" if vulnerable else "completed",
            "vulnerable": vulnerable,
            "evidence": evidence if vulnerable else "",
            "error": "" if vulnerable else str(item.get("error") or "").strip(),
            "details": evidence,
            "severity": str(item.get("severity") or "UNKNOWN").strip() or "UNKNOWN",
            "branch": "global_scan",
        })
    return execution_items


def _normalize_manual_findings(session: dict, execution_items: list[dict]) -> list[dict]:
    target_ip = _extract_session_target_ip(session)
    findings: list[dict] = []
    for item in execution_items:
        if not item.get("vulnerable"):
            continue
        findings.append({
            "id": item["poc_name"],
            "trace_id": str(session.get("id") or session.get("session_id") or ""),
            "poc_id": item["poc_name"],
            "poc_name": item["poc_name"],
            "target_ip": target_ip,
            "vulnerable": True,
            "severity": item.get("severity") or "UNKNOWN",
            "domain": "global_scan",
            "evidence": item.get("details") or item.get("evidence") or "",
            "error": "",
            "source": "global_scan",
            "detected_at": _get_utc_now().strftime('%Y-%m-%dT%H:%M:%SZ'),
            "description": item.get("details") or item.get("evidence") or "",
            "details": item.get("details") or item.get("evidence") or "",
            "name": item["poc_name"],
            "pocId": item["poc_name"],
        })
    return findings


def _build_manual_assessment_context(session: dict) -> tuple[str, str, str]:
    target_ip = _extract_session_target_ip(session)
    target_name = str(session.get("targetName") or target_ip or "Unknown Target").strip()
    execution_items = _normalize_manual_execution_items(session)
    findings = _normalize_manual_findings(session, execution_items)

    session_summary = json.dumps({
        'session_id': session.get('id') or session.get('session_id'),
        'target_name': target_name,
        'target_ip': target_ip,
        'mode': session.get('mode') or 'batch',
        'risk_score': session.get('riskScore'),
        'result_count': len(execution_items),
        'finding_count': len(findings),
    }, ensure_ascii=False, indent=2)

    execution_result = json.dumps({'items': execution_items}, ensure_ascii=False, indent=2)
    finding_result = json.dumps(findings, ensure_ascii=False, indent=2)

    context = (
        "【扫描来源】Global Scan / History Report Generation\n"
        "【说明】以下内容来自人工触发或计划任务触发的全局扫描结果，已统一转换为 Assessment Agent 可消费的执行结果上下文。\n\n"
        "【会话摘要(JSON)】\n"
        f"{session_summary}\n\n"
        "【执行结果(JSON)】\n"
        f"{execution_result}\n\n"
        "【漏洞发现(JSON)】\n"
        f"{finding_result}"
    )
    return target_name, target_ip, context


def _normalize_ai_config(payload: dict | None) -> dict:
    payload = payload or {}
    return {
        "base_url": str(payload.get("base_url") or payload.get("baseUrl") or "").strip(),
        "api_key": str(payload.get("api_key") or payload.get("apiKey") or "").strip(),
        "report_model": str(payload.get("report_model") or payload.get("reportModel") or "").strip(),
        "fast_model": str(payload.get("fast_model") or payload.get("fastModel") or "").strip(),
        "strong_model": str(payload.get("strong_model") or payload.get("strongModel") or "").strip(),
    }


def _ai_config_fernet() -> Fernet:
    digest = hashlib.sha256(app.config['SECRET_KEY'].encode('utf-8')).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _serialize_ai_config(payload: dict | None) -> dict:
    normalized = _normalize_ai_config(payload)
    return {
        "baseUrl": normalized["base_url"],
        "apiKey": normalized["api_key"],
        "reportModel": normalized["report_model"],
        "fastModel": normalized["fast_model"],
        "strongModel": normalized["strong_model"],
    }


def _encrypt_ai_config(payload: dict | None) -> str:
    serialized = json.dumps(_serialize_ai_config(payload), ensure_ascii=False)
    return _ai_config_fernet().encrypt(serialized.encode('utf-8')).decode('utf-8')


def _decrypt_ai_config(encrypted_payload: str | None) -> dict:
    if not encrypted_payload:
        return {}
    try:
        raw = _ai_config_fernet().decrypt(encrypted_payload.encode('utf-8')).decode('utf-8')
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return {
                "baseUrl": str(parsed.get("baseUrl") or "").strip(),
                "apiKey": str(parsed.get("apiKey") or "").strip(),
                "reportModel": str(parsed.get("reportModel") or "").strip(),
                "fastModel": str(parsed.get("fastModel") or "").strip(),
                "strongModel": str(parsed.get("strongModel") or "").strip(),
            }
    except (InvalidToken, ValueError, TypeError, json.JSONDecodeError):
        return {}
    return {}


def _load_user_ai_config(user_id: int) -> dict:
    record = UserAiConfig.query.filter_by(user_id=user_id).first()
    if not record:
        return {}
    return _decrypt_ai_config(record.encrypted_payload)


def _save_user_ai_config(user_id: int, payload: dict | None) -> dict:
    record = UserAiConfig.query.filter_by(user_id=user_id).first()
    encrypted_payload = _encrypt_ai_config(payload)
    if record is None:
        record = UserAiConfig(user_id=user_id, encrypted_payload=encrypted_payload)
        db.session.add(record)
    else:
        record.encrypted_payload = encrypted_payload
    return _decrypt_ai_config(encrypted_payload)


def _validate_ai_config(payload: dict | None) -> tuple[dict, str | None]:
    config = _normalize_ai_config(payload)
    if not config["api_key"]:
        return config, "AI API key is required."
    if not config["base_url"]:
        return config, "AI base_url is required."
    return config, None


def _generate_unified_assessment_report(session: dict, ai_config: dict) -> str:
    normalized_ai_config, error = _validate_ai_config(ai_config)
    if error:
        return f"AI 报告功能未启用：{error}"

    try:
        from agent_orchestrator import generate_assessment_report

        target_name, target_ip, context = _build_manual_assessment_context(session)
        report_model = normalized_ai_config["report_model"] or normalized_ai_config["strong_model"] or normalized_ai_config["fast_model"] or "qwen-max"
        logger.info(
            "Unified assessment report requested for %s (%s) with model=%s",
            target_name,
            target_ip or "n/a",
            report_model,
        )
        return generate_assessment_report(
            target_ip=target_ip or "Unknown Target",
            target_name=target_name,
            llm_config=normalized_ai_config,
            context=context,
            report_date=_extract_session_report_date(session),
        )
    except Exception as exc:
        logger.error(f"Unified assessment report generation failed: {exc}", exc_info=True)
        return "与模型接口通信时发生错误，请检查当前用户的 AI 配置、网络和 API Key。"


# ==========================================
# Database Models
# ==========================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user') # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=_get_utc_now)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at.isoformat()
        }


class UserAiConfig(db.Model):
    __tablename__ = 'user_ai_configs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False, index=True)
    encrypted_payload = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=_get_utc_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=_get_utc_now, onupdate=_get_utc_now, nullable=False)

    user = db.relationship('User', backref=db.backref('ai_config_record', uselist=False, lazy=True))

class ScanHistory(db.Model):
    __tablename__ = 'scan_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_id = db.Column(db.String(100), nullable=True) # E.g., global scan frontend ID
    target_ip = db.Column(db.String(50), nullable=True)
    target_mac = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), nullable=False) # 'completed', 'failed', 'running'
    started_at = db.Column(db.DateTime, default=_get_utc_now)
    completed_at = db.Column(db.DateTime, nullable=True)
    results_json = db.Column(db.Text, nullable=True) # Full JSON data of results
    logs = db.Column(db.Text, nullable=True) # Dedicated column for logs
    risk_score = db.Column(db.Integer, default=0)

    user = db.relationship('User', backref=db.backref('scans', lazy=True))

    def to_dict(self):
        payload = json.loads(self.results_json) if self.results_json else {}
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.user.username if self.user else "Unknown",
            "session_id": self.session_id,
            "target_ip": self.target_ip,
            "target_mac": self.target_mac,
            "status": self.status,
            "started_at": self.started_at.strftime('%Y-%m-%dT%H:%M:%SZ') if self.started_at else None,
            "completed_at": self.completed_at.strftime('%Y-%m-%dT%H:%M:%SZ') if self.completed_at else None,
            "risk_score": self.risk_score,
            "results_json": payload,
            "logs": json.loads(self.logs) if self.logs else [],
            "findings": payload.get("findings", []) if isinstance(payload, dict) else [],
            "phase_records": payload.get("phase_records", []) if isinstance(payload, dict) else [],
            "structured": payload.get("structured", {}) if isinstance(payload, dict) else {},
        }

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False) # e.g., 'run_disruptive_poc', 'login'
    target = db.Column(db.String(100), nullable=True)
    details_json = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=_get_utc_now)
    ip_address = db.Column(db.String(50), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "target": self.target,
            "details": json.loads(self.details_json) if self.details_json else {},
            "timestamp": self.timestamp.strftime('%Y-%m-%dT%H:%M:%SZ') if self.timestamp else None,
            "ip_address": self.ip_address
        }

class SupervisorMetricSnapshot(db.Model):
    __tablename__ = 'supervisor_metric_snapshots'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_id = db.Column(db.String(100), nullable=False, index=True)
    target_ip = db.Column(db.String(50), nullable=True)
    model_profile = db.Column(db.String(120), nullable=True)
    metrics_json = db.Column(db.Text, nullable=False)
    adjustments_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=_get_utc_now, index=True)

    user = db.relationship('User', backref=db.backref('supervisor_snapshots', lazy=True))

    def to_dict(self):
        metrics = json.loads(self.metrics_json) if self.metrics_json else {}
        adjustments = json.loads(self.adjustments_json) if self.adjustments_json else []
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.user.username if self.user else "Unknown",
            "session_id": self.session_id,
            "target_ip": self.target_ip,
            "model_profile": self.model_profile,
            "metrics": metrics,
            "adjustments": adjustments,
            "created_at": self.created_at.strftime('%Y-%m-%dT%H:%M:%SZ') if self.created_at else None,
        }


class ExecutionArtifact(db.Model):
    __tablename__ = 'execution_artifacts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_id = db.Column(db.String(100), nullable=False, index=True)
    trace_id = db.Column(db.String(120), nullable=True, index=True)
    artifact_type = db.Column(db.String(40), nullable=False, index=True)
    poc_filename = db.Column(db.String(255), nullable=True, index=True)
    poc_name = db.Column(db.String(255), nullable=True)
    target_ip = db.Column(db.String(50), nullable=True)
    target_mac = db.Column(db.String(50), nullable=True)
    payload_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=_get_utc_now, index=True)

    user = db.relationship('User', backref=db.backref('execution_artifacts', lazy=True))

    def to_dict(self):
        payload = json.loads(self.payload_json) if self.payload_json else {}
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.user.username if self.user else "Unknown",
            "session_id": self.session_id,
            "trace_id": self.trace_id,
            "artifact_type": self.artifact_type,
            "poc_filename": self.poc_filename,
            "poc_name": self.poc_name,
            "target_ip": self.target_ip,
            "target_mac": self.target_mac,
            "payload": payload,
            "created_at": self.created_at.strftime('%Y-%m-%dT%H:%M:%SZ') if self.created_at else None,
        }


def _extract_poc_security_profile(poc_path: str) -> dict:
    source_text = None
    if not os.path.exists(poc_path):
        _, _, source_text = resolve_poc_source(POCS_DIR, os.path.relpath(poc_path, POCS_DIR))
    return extract_poc_security_profile(poc_path, source_text=source_text)


def _should_require_disruptive_approval(profile: dict, params: dict) -> bool:
    return should_require_disruptive_approval(profile, params)


def _build_execution_artifact_payload(**kwargs) -> dict:
    payload = dict(kwargs)
    payload.setdefault("created_at", _get_utc_now().strftime('%Y-%m-%dT%H:%M:%SZ'))
    return payload


def _persist_execution_artifact(
    *,
    user_id: int,
    session_id: str,
    artifact_type: str,
    payload: dict,
    trace_id: str = None,
    poc_filename: str = None,
    poc_name: str = None,
    target_ip: str = None,
    target_mac: str = None,
    replace_existing: bool = False,
):
    if not session_id:
        return None

    if replace_existing:
        ExecutionArtifact.query.filter_by(
            user_id=user_id,
            session_id=session_id,
            artifact_type=artifact_type,
        ).delete(synchronize_session=False)

    artifact = ExecutionArtifact(
        user_id=user_id,
        session_id=session_id,
        trace_id=trace_id,
        artifact_type=artifact_type,
        poc_filename=poc_filename,
        poc_name=poc_name,
        target_ip=target_ip,
        target_mac=target_mac,
        payload_json=json.dumps(payload, ensure_ascii=False),
    )
    db.session.add(artifact)
    return artifact


def _build_poc_registry_entry(filepath: str, source_text: str | None = None, rel_path_override: str | None = None) -> dict:
    rel_path = rel_path_override or os.path.relpath(filepath, POCS_DIR)
    category_dir = os.path.dirname(rel_path).split('/', 1)[0] if '/' in rel_path else "root"
    entry = {
        "filename": rel_path,
        "filepath": filepath,
        "category": os.path.basename(os.path.dirname(filepath)) if os.path.exists(filepath) and os.path.dirname(filepath) != POCS_DIR else category_dir,
        "size": os.path.getsize(filepath) if os.path.exists(filepath) else len(source_text or ""),
        "poc_name": os.path.basename(filepath),
        "class_name": None,
        "cve_id": "",
        "severity": "",
        "protocol": "",
        "target_os": [],
        "required_params": [],
        "destructive_level": "Safe",
        "is_disruptive": False,
        "status": "unknown",
    }

    try:
        if source_text is None:
            with open(filepath, "r", encoding="utf-8") as handle:
                source_text = handle.read()
        content = source_text
        entry["content"] = _truncate_poc_for_display(content)
        tree = ast.parse(content, filename=filepath)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            entry["class_name"] = node.name
            for body_item in node.body:
                if not isinstance(body_item, ast.Assign):
                    continue
                try:
                    value = ast.literal_eval(body_item.value)
                except Exception:
                    continue
                for target_node in body_item.targets:
                    if isinstance(target_node, ast.Name):
                        name = target_node.id
                        if name == "meta_poc_name":
                            entry["poc_name"] = value
                        elif name == "meta_cve_id":
                            entry["cve_id"] = value
                        elif name == "meta_severity":
                            entry["severity"] = value
                        elif name == "meta_protocol":
                            entry["protocol"] = value
                        elif name == "meta_target_os":
                            entry["target_os"] = value
                        elif name == "meta_required_params":
                            entry["required_params"] = value
                        elif name == "meta_destructive_level":
                            entry["destructive_level"] = value
                        elif name == "is_disruptive":
                            entry["is_disruptive"] = bool(value)
            break
        if entry["is_disruptive"] or str(entry["destructive_level"]).lower() in {"restart", "dataloss", "brick"}:
            entry["status"] = "approval_required"
        elif entry["severity"] in {"High", "Critical"}:
            entry["status"] = "review_recommended"
        else:
            entry["status"] = "ready"
    except Exception as exc:
        entry["parse_error"] = str(exc)

    return entry


def _scan_poc_registry() -> dict:
    entries = []
    source = "filesystem"
    seen: set[str] = set()

    if os.path.isdir(POCS_DIR):
        for dirpath, dirnames, filenames in os.walk(POCS_DIR):
            dirnames[:] = [d for d in dirnames if not d.startswith('.') and d != '.venv' and d != '__pycache__']
            for filename in sorted(filenames):
                if filename.endswith('.py') and not filename.startswith('__') and filename != 'iv_plugin_base.py':
                    filepath = os.path.join(dirpath, filename)
                    rel_path = os.path.relpath(filepath, POCS_DIR)
                    seen.add(rel_path)
                    entries.append(_build_poc_registry_entry(filepath))

    for rel_path in list_available_poc_names(POCS_DIR):
        if rel_path in seen:
            continue
        virtual_path, normalized, source_text = resolve_poc_source(POCS_DIR, rel_path)
        if not virtual_path or not normalized or not source_text:
            continue
        source = "embedded" if not entries else "filesystem+embedded"
        entries.append(_build_poc_registry_entry(virtual_path, source_text=source_text, rel_path_override=normalized))

    counts = {
        "total": len(entries),
        "approval_required": sum(1 for item in entries if item.get("status") == "approval_required"),
        "review_recommended": sum(1 for item in entries if item.get("status") == "review_recommended"),
        "ready": sum(1 for item in entries if item.get("status") == "ready"),
    }
    return {"entries": entries, "counts": counts, "source": source if entries else "missing"}


def _normalize_scoring_key(value) -> str:
    return str(value or "").strip().lower().replace(" ", "_")


def _score_session_against_benchmark(session_payload: dict, benchmark: dict) -> dict:
    return evaluate_session_against_benchmark(session_payload, benchmark)

# ==========================================
# Authentication Helpers
# ==========================================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'OPTIONS':
            return '', 200
            
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
        if request.method == 'OPTIONS':
            return '', 200
        if current_user is None:
            return jsonify({'message': 'Authentication required!'}), 401
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
            'exp': _get_utc_now() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        logger.info(f"User logged in: {user.username}")
        user_payload = user.to_dict()
        user_payload["ai_config"] = _load_user_ai_config(user.id)
        return jsonify({'token': token, 'user': user_payload})

    return jsonify({"message": "Invalid password!"}), 401

@app.route('/api/profile', methods=['GET', 'PUT'])
@token_required
def profile(current_user):
    if request.method == 'GET':
        user_payload = current_user.to_dict()
        user_payload["ai_config"] = _load_user_ai_config(current_user.id)
        return jsonify({"user": user_payload})
        
    if request.method == 'PUT':
        data = request.json
        new_username = data.get('new_username')
        new_password = data.get('new_password')
        ai_config = data.get('ai_config')
        
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

        if isinstance(ai_config, dict):
            _save_user_ai_config(current_user.id, ai_config)
            updates_made = True
            
        if updates_made:
            db.session.commit()
            logger.info(f"User {current_user.id} updated their profile.")
            user_payload = current_user.to_dict()
            user_payload["ai_config"] = _load_user_ai_config(current_user.id)
            return jsonify({"message": "Profile updated successfully!", "user": user_payload}), 200
            
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


def _web_dist_dir() -> Path | None:
    for candidate in WEB_DIST_CANDIDATES:
        if candidate.exists() and (candidate / 'index.html').exists():
            return candidate
    return None


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path: str):
    if path.startswith('api/'):
        return jsonify({"message": "API endpoint not found"}), 404

    web_dist = _web_dist_dir()
    if not web_dist:
        return jsonify({
            "message": "Frontend bundle not found.",
            "hint": "Run the workstation packaging script or npm run build in client/.",
        }), 404

    requested = web_dist / path
    if path and requested.exists() and requested.is_file():
        return send_from_directory(web_dist, path)
    return send_from_directory(web_dist, 'index.html')


@app.route('/api/health', methods=['GET'])
def health_check():
    """Check if the execution engine is online."""
    return jsonify({
        "status": "online",
        "system": sys.platform,
        "product": "AutoSec Guard Edge Workstation",
        "product_mode": "edge-local",
        "pocs_dir": POCS_DIR,
        "data_dir": str(RUNTIME_DATA_DIR),
        "web_dist": str(_web_dist_dir() or ""),
        "database": app.config['SQLALCHEMY_DATABASE_URI'].split(':', 1)[0],
        "ai_reports_enabled": True,
        "warnings": RUNTIME_WARNINGS,
    })


@app.route('/api/local/capabilities', methods=['GET'])
@token_required
def local_capabilities(current_user):
    """Report hardware and host capabilities for this local vehicle-side workstation."""
    try:
        from local_capability_probe import probe as probe_local_capabilities

        capabilities = probe_local_capabilities()
        return jsonify({
            "mode": "edge-local",
            "host": socket.gethostname(),
            "capabilities": capabilities,
            "capability_flags": local_capability_flags(capabilities),
            "checked_at": _get_utc_now().strftime('%Y-%m-%dT%H:%M:%SZ'),
            "operator": current_user.username,
        })
    except Exception as exc:
        logger.error(f"Local capability probe failed: {exc}", exc_info=True)
        return jsonify({"message": "Local capability probe failed", "error": str(exc)}), 500


@app.route('/api/report/generate', methods=['POST'])
@token_required
def generate_report(current_user):
    """Generate AI security report on the server side to avoid exposing LLM credentials in the browser."""
    data = request.json or {}
    session = data.get('session')
    ai_config = data.get('ai_config') or {}
    if not isinstance(ai_config, dict) or not any(str(ai_config.get(key) or "").strip() for key in ("api_key", "apiKey", "base_url", "baseUrl")):
        ai_config = _load_user_ai_config(current_user.id)

    if not session or not isinstance(session, dict):
        return jsonify({"message": "session payload is required"}), 400

    _, ai_error = _validate_ai_config(ai_config)
    if ai_error:
        return jsonify({"message": ai_error}), 400

    normalized_ai_config = _normalize_ai_config(ai_config)
    selected_model = normalized_ai_config["report_model"] or normalized_ai_config["strong_model"] or normalized_ai_config["fast_model"] or "qwen-max"
    logger.info(
        "AI report requested by %s for %s using unified assessment agent (model=%s)",
        current_user.username,
        session.get('targetName') or 'Unknown Target',
        selected_model,
    )
    report = _generate_unified_assessment_report(session, normalized_ai_config)
    return jsonify({
        "report": report,
        "provider": "user-configured-openai-compatible",
        "generated_at": _get_utc_now().strftime('%Y-%m-%dT%H:%M:%SZ'),
    })


def _get_session_payload(data: dict) -> dict:
    session = data.get('session')
    return session if isinstance(session, dict) else data


def _build_history_results_payload(data: dict) -> dict:
    return {
        "targetName": data.get('targetName', 'Unknown Target'),
        "results": data.get('results', []),
        "aiReport": data.get('aiReport'),
        "connection": data.get('connection', {}),
        "mode": data.get("mode", "batch"),
        "assessment": data.get('assessment', {}),
        "findings": data.get('findings', []),
        "phase_records": data.get('phase_records', []),
        "structured": data.get('structured', {}),
    }

def _build_supervisor_model_profile(structured: dict) -> str:
    if not isinstance(structured, dict):
        return "unknown"
    planner = structured.get("planner", {}) if isinstance(structured.get("planner", {}), dict) else {}
    supervisor = structured.get("supervisor", {}) if isinstance(structured.get("supervisor", {}), dict) else {}
    events = supervisor.get("events", []) if isinstance(supervisor.get("events", []), list) else []
    if events:
        return "planner+supervisor"
    if planner.get("steps"):
        return "planner"
    return "baseline"


def _truncate_poc_for_display(content: str) -> str:
    """
    Extracts the module-level docstring from a Python script for safe display.
    Prevents leakage of exploit logic.
    """
    if not content:
        return ""
    
    content = content.strip()
    
    # Try using AST to get the docstring cleanly
    try:
        import ast
        tree = ast.parse(content)
        doc = ast.get_docstring(tree)
        if doc:
            return f'"""\n{doc.strip()}\n"""\n\n# ... [Exploit logic hidden] ...'
    except Exception:
        pass

    # Fallback to manual triple-quote extraction if AST fails or docstring is missing
    for quote in ['"""', "'''"]:
        if content.startswith(quote):
            second_quote_idx = content.find(quote, len(quote))
            if second_quote_idx != -1:
                return content[:second_quote_idx + len(quote)].strip() + "\n\n# ... [Rest of code hidden] ..."

    # Second fallback: take first 15 lines if no obvious docstring
    lines = content.splitlines()
    if len(lines) > 15:
        return "\n".join(lines[:15]) + "\n\n# ... [Rest of code hidden] ..."
        
    return content


@app.route('/api/attack-graph/generate', methods=['POST'])
@token_required
def attack_graph_generate(current_user):
    session = _get_session_payload(request.json or {})
    graph = generate_attack_graph(session)
    logger.info(f"Attack graph generated by {current_user.username} for {session.get('targetName') or session.get('target_ip') or 'Unknown Target'}")
    return jsonify(graph)


@app.route('/api/physical-impact/assess', methods=['POST'])
@token_required
def physical_impact_assess(current_user):
    session = _get_session_payload(request.json or {})
    result = assess_physical_impact(session)
    logger.info(f"Physical impact assessed by {current_user.username}")
    return jsonify(result)


@app.route('/api/remediation/simulate', methods=['POST'])
@token_required
def remediation_simulate(current_user):
    session = _get_session_payload(request.json or {})
    result = simulate_remediation(session)
    logger.info(f"Remediation simulation generated by {current_user.username}")
    return jsonify(result)


@app.route('/api/report/structured', methods=['POST'])
@token_required
def structured_report(current_user):
    session = _get_session_payload(request.json or {})
    report = build_structured_report(session)
    logger.info(f"Structured report generated by {current_user.username}")
    return jsonify(report)

@app.route('/api/auto_discovery', methods=['GET'])
@cross_origin()
def auto_discovery():
    """Hackathon: Zero-Config Discovery of local interfaces and possible targets."""
    interfaces = {
        "wifi": "wlan0mon",
        "can": "PCAN_USBBUS1",
        "bluetooth_mac": "",
        "target_ip": "192.168.100.1" 
    }
    
    # 动态获取当前本机的IP并猜测目标主机（通常为网关或网段首节点）
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        ip_parts = local_ip.split('.')
        ip_parts[-1] = '1'
        interfaces['target_ip'] = '.'.join(ip_parts)
    except Exception:
        pass

    import sys
    if sys.platform == 'darwin':
        # macOS 真实网卡嗅探
        interfaces['wifi'] = 'en0'
        try:
            bt_info = subprocess.check_output(['system_profiler', 'SPBluetoothDataType']).decode('utf-8')
            if 'Address: ' in bt_info:
                # Extract first MAC found
                mac = bt_info.split('Address: ')[1][:17]
                interfaces['bluetooth_mac'] = mac
            else:
                interfaces['bluetooth_mac'] = 'A1:B2:C3:00:FF:AA'
        except Exception:
            interfaces['bluetooth_mac'] = 'A1:B2:C3:00:FF:AA'
    else:
        # Linux 物理环境嗅探
        try:
            ip_link = subprocess.check_output(['ifconfig']).decode('utf-8')
            if '' in ip_link: interfaces['can'] = 'PCAN_USBBUS1'
            elif 'vcan0' in ip_link: interfaces['can'] = 'vcan0'
        except Exception: pass
            
        try:
            iwconfig = subprocess.check_output(['iwconfig'], stderr=subprocess.STDOUT).decode('utf-8')
            for line in iwconfig.splitlines():
                if 'Mode:Monitor' in line:
                    interfaces['wifi'] = line.split()[0]
                    break
        except Exception: pass
            
        try:
            hciconfig = subprocess.check_output(['hciconfig']).decode('utf-8')
            if 'hci0' in hciconfig:
                interfaces['bluetooth_mac'] = 'AA:BB:CC:DD:EE:FF'
        except Exception:
            interfaces['bluetooth_mac'] = '00:11:22:33:44:55'
        
    return jsonify({
        "status": "success", 
        "interfaces": interfaces,
        "message": "Discovery Agent completed physical topology mapping."
    })

@app.route('/api/list_pocs', methods=['GET'])
def list_pocs():
    """List all available PoC plugin files in pocs/ directory tree with metadata."""
    pocs = []
    for rel_path in list_available_poc_names(POCS_DIR):
        filepath, normalized, content = resolve_poc_source(POCS_DIR, rel_path)
        if not filepath or not normalized:
            continue
        category_dir = os.path.dirname(normalized).split('/', 1)[0] if '/' in normalized else "root"
        poc_info = {
            "filename": normalized,
            "filepath": filepath,
            "size": os.path.getsize(filepath) if os.path.exists(filepath) else len(content or ""),
            "category_dir": category_dir,
            "packaged": not os.path.exists(filepath),
        }
        try:
            if content is None:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
            poc_info['content'] = _truncate_poc_for_display(content)

            import ast
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    poc_info['class_name'] = node.name
                    for item in node.body:
                        if isinstance(item, ast.Assign):
                            for target in item.targets:
                                if isinstance(target, ast.Name):
                                    name = target.id
                                    if name in ['is_disruptive', 'meta_poc_name', 'meta_cve_id', 'meta_severity', 'meta_protocol', 'meta_destructive_level', 'meta_target_os', 'meta_required_params']:
                                        try:
                                            poc_info[name] = ast.literal_eval(item.value)
                                        except Exception:
                                            pass

                    if not poc_info.get('meta_cve_id') and 'cve_id' in content:
                        for line in content.splitlines():
                            if 'cve_id' in line and '=' in line:
                                cve = line.split('=')[-1].strip().strip('"\'')
                                poc_info['meta_cve_id'] = cve
                                break
                    break
        except Exception as e:
            logger.error(f"Error parsing {filepath}: {e}")

        if 'is_disruptive' not in poc_info:
             poc_info['is_disruptive'] = False
        profile = _extract_poc_security_profile(filepath)
        poc_info["manual_confirmation_required"] = _should_require_disruptive_approval(profile, {})
        poc_info.update(classify_poc_execution_mode(POCS_DIR, filepath, profile, normalized))
        pocs.append(poc_info)

    return jsonify({"pocs": pocs, "total": len(pocs)})


@app.route('/api/poc-registry', methods=['GET'])
@token_required
def get_poc_registry(current_user):
    """Return a normalized PoC capability registry with aggregate status counts."""
    try:
        registry = _scan_poc_registry()
        if current_user.role != 'admin':
            registry["entries"] = [
                entry for entry in registry["entries"]
                if entry.get("status") != "approval_required"
            ]
            registry["counts"]["approval_required"] = sum(
                1 for entry in registry["entries"] if entry.get("status") == "approval_required"
            )
            registry["counts"]["total"] = len(registry["entries"])
        return jsonify(registry)
    except Exception as exc:
        logger.error(f"Failed to build poc registry: {exc}")
        return jsonify({"message": str(exc)}), 500

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
    current_user = resolve_user_from_bearer(
        request.headers.get('Authorization'),
        app.config['SECRET_KEY'],
        User,
    )

    data = request.json
    poc_filename = data.get('filename')
    params = normalize_poc_params(data.get('params', {}))
    session_id = data.get('session_id', 'manual')

    if not poc_filename:
        return jsonify({"error": "No PoC filename provided"}), 400

    poc_path, normalized_filename, poc_code = resolve_poc_source(POCS_DIR, poc_filename)
    if not poc_path:
        logger.warning(f"PoC file not found: {poc_filename}")
        return jsonify({"error": f"PoC file not found: {poc_filename}"}), 404
    poc_filename = normalized_filename

    logger.info(f"Starting PoC Execution: {poc_filename} w/ Params: {params}")
    trace_id = data.get("trace_id") or session_id or uuid.uuid4().hex
    
    try:
        target = resolve_target_label(params)
        security_profile = _extract_poc_security_profile(poc_path)
        requires_approval = _should_require_disruptive_approval(security_profile, params)

        # 记录所有高危/强干扰执行
        if requires_approval:
            user_id = current_user.id if current_user else None
            audit = AuditLog(
                user_id=user_id,
                action='run_disruptive_poc',
                target=target,
                details_json=json.dumps({
                    "poc": poc_filename,
                    "params": params,
                    "security_profile": security_profile,
                    "trace_id": trace_id,
                    "reason": "approval_required",
                }, ensure_ascii=False),
                ip_address=request.remote_addr
            )
            db.session.add(audit)
            db.session.commit()
            return jsonify({
                "success": False,
                "error": "High-risk PoC execution requires explicit approval.",
                "requires_approval": True,
                "trace_id": trace_id,
                "security_profile": security_profile,
            }), 403
    except Exception as e:
        logger.error(f"Failed to record audit log: {e}")

    start_time = time.time()

    try:
        worker = get_poc_worker(data.get("worker_mode"))
        plan = worker.prepare(
            poc_path,
            params,
            trace_id=trace_id,
            session_id=session_id,
            poc_code=poc_code if poc_code and not os.path.exists(poc_path) else None,
            timeout_seconds=int(params.get("sandbox_timeout_seconds", 60)),
        )
        run_result = worker.run_once(plan)
        elapsed = run_result.get("elapsed_seconds", round(time.time() - start_time, 2))
        all_logs = run_result.get("logs", [])
        plugin_results = run_result.get("plugin_results", {})
        sandbox_profile = run_result.get("sandbox_profile", plan.sandbox_profile)
        security_profile = run_result.get("security_profile", plan.security_profile)
        worker_mode = run_result.get("worker_mode", plan.worker_mode)

        response = {
            "success": bool(run_result.get("success")),
            "logs": all_logs,
            "errors": [plugin_results.get("error")] if "error" in plugin_results else [],
            "vulnerable": plugin_results.get('vulnerable', False),
            "evidence": plugin_results.get('evidence', ''),
            "cve_id": plugin_results.get('cve_id', ''),
            "elapsed_seconds": elapsed,
            "poc_id": poc_filename,
            "trace_id": trace_id,
            "security_profile": security_profile,
            "sandbox_profile": sandbox_profile,
            "worker_mode": worker_mode,
        }
        if current_user:
            try:
                _persist_execution_artifact(
                    user_id=current_user.id,
                    session_id=session_id,
                    artifact_type="poc_run",
                    trace_id=trace_id,
                    poc_filename=poc_filename,
                    poc_name=security_profile.get("poc_name") or poc_filename,
                    target_ip=params.get("target_ip"),
                    target_mac=params.get("target_mac") or params.get("bluetooth_mac"),
                    payload=_build_execution_artifact_payload(
                        request_type="run_poc",
                        params=params,
                        logs=all_logs,
                        result=response,
                        plugin_results=plugin_results,
                        sandbox_profile=response["sandbox_profile"],
                        security_profile=security_profile,
                        worker_mode=worker_mode,
                    ),
                )
                db.session.commit()
            except Exception as artifact_exc:
                db.session.rollback()
                logger.error(f"Failed to persist execution artifact: {artifact_exc}")

        status_msg = "VULNERABLE" if response["vulnerable"] else "SECURE"
        if not response["success"]:
            status_msg = "ERROR"
        logger.info(f"PoC Result [{poc_filename}]: {status_msg} (Elapsed: {elapsed}s)")

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

@app.route('/api/run_poc_stream', methods=['POST', 'OPTIONS'])
@cross_origin()
def run_poc_stream():
    """SSE streaming endpoint: 实时逐行推送 PoC 执行日志到前端 System Console"""
    if request.method == 'OPTIONS':
        return '', 200

    data = request.json
    poc_filename = data.get('filename')
    params = normalize_poc_params(data.get('params', {}))
    session_id = data.get('session_id', 'manual')

    if not poc_filename:
        return jsonify({"error": "No PoC filename provided"}), 400

    poc_path, normalized_filename, poc_code = resolve_poc_source(POCS_DIR, poc_filename)
    if not poc_path:
        return jsonify({"error": f"PoC file not found: {poc_filename}"}), 404
    poc_filename = normalized_filename

    trace_id = data.get("trace_id") or data.get("session_id") or uuid.uuid4().hex
    security_profile = _extract_poc_security_profile(poc_path)
    if _should_require_disruptive_approval(security_profile, params):
        try:
            audit = AuditLog(
                user_id=None,
                action='run_disruptive_poc',
                target=resolve_target_label(params),
                details_json=json.dumps({
                    "poc": poc_filename,
                    "params": params,
                    "security_profile": security_profile,
                    "trace_id": trace_id,
                    "mode": "stream",
                    "reason": "approval_required",
                }, ensure_ascii=False),
                ip_address=request.remote_addr
            )
            db.session.add(audit)
            db.session.commit()
        except Exception as e:
            logger.error(f"Failed to record stream approval audit log: {e}")
        return jsonify({
            "success": False,
            "error": "High-risk PoC execution requires explicit approval.",
            "requires_approval": True,
            "trace_id": trace_id,
            "security_profile": security_profile,
        }), 403

    # Audit Logging
    try:
        target = resolve_target_label(params)
        if security_profile.get("is_disruptive"):
            audit = AuditLog(
                user_id=None,
                action='run_disruptive_poc',
                target=target,
                details_json=json.dumps({
                    "poc": poc_filename,
                    "params": params,
                    "mode": "stream",
                    "security_profile": security_profile,
                    "trace_id": trace_id,
                }, ensure_ascii=False),
                ip_address=request.remote_addr
            )
            db.session.add(audit)
            db.session.commit()
    except Exception as e:
        logger.error(f"Failed to record stream audit log: {e}")

    def generate():
        worker = get_poc_worker(data.get("worker_mode"))
        plan = worker.prepare(
            poc_path,
            params,
            trace_id=trace_id,
            session_id=session_id,
            poc_code=poc_code if poc_code and not os.path.exists(poc_path) else None,
            timeout_seconds=int(params.get("sandbox_timeout_seconds", 60)),
        )
        emitted_logs: list[str] = []
        try:
            for event in worker.iter_stream(plan):
                if event.get("type") == "log":
                    emitted_logs.append(event.get("message", ""))
                    yield f"data: {json.dumps(event)}\n\n" + (" " * 1024) + "\n\n"
                    time.sleep(0.01)
                    continue

                result = {
                    "type": "result",
                    "success": bool(event.get("success")),
                    "vulnerable": event.get("vulnerable", False),
                    "evidence": event.get("evidence", ""),
                    "cve_id": event.get("cve_id", ""),
                    "elapsed_seconds": event.get("elapsed_seconds", 0),
                    "errors": event.get("errors", []),
                    "trace_id": trace_id,
                    "security_profile": event.get("security_profile", security_profile),
                    "sandbox_profile": event.get("sandbox_profile", plan.sandbox_profile),
                    "worker_mode": event.get("worker_mode", plan.worker_mode),
                }
                if request.headers.get('Authorization'):
                    try:
                        current_user = resolve_user_from_bearer(
                            request.headers.get('Authorization'),
                            app.config['SECRET_KEY'],
                            User,
                        )
                        if current_user:
                            _persist_execution_artifact(
                                user_id=current_user.id,
                                session_id=session_id,
                                artifact_type="poc_run",
                                trace_id=trace_id,
                                poc_filename=poc_filename,
                                poc_name=plan.security_profile.get("poc_name") or poc_filename,
                                target_ip=params.get("target_ip"),
                                target_mac=params.get("target_mac") or params.get("bluetooth_mac"),
                                payload=_build_execution_artifact_payload(
                                    request_type="run_poc_stream",
                                    params=params,
                                    logs=emitted_logs,
                                    result=result,
                                    plugin_results=event.get("plugin_results", {}),
                                    raw_result_json=json.dumps(event.get("plugin_results", {}), ensure_ascii=False),
                                    sandbox_profile=result["sandbox_profile"],
                                    security_profile=result["security_profile"],
                                    worker_mode=result["worker_mode"],
                                ),
                            )
                            db.session.commit()
                    except Exception as artifact_exc:
                        db.session.rollback()
                        logger.error(f"Failed to persist stream artifact: {artifact_exc}")
                status_msg = "VULNERABLE" if result["vulnerable"] else "SECURE"
                if not result["success"]:
                    status_msg = "ERROR"
                logger.info(f"PoC Stream [{poc_filename}]: {status_msg} (Elapsed: {result['elapsed_seconds']}s)")
                yield f"data: {json.dumps(result)}\n\n" + (" " * 1024) + "\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'result', 'success': False, 'errors': [str(e)]})}\n\n"

    return app.response_class(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
        'Access-Control-Allow-Origin': '*',
    })


@app.route('/api/save_session', methods=['POST', 'OPTIONS'])
@cross_origin()
@token_required
def save_session(current_user):
    """Save a full scan session (multiple results + final report) to history."""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
        
    data = request.json
    if not data:
        return jsonify({"message": "No data provided"}), 400
        
    session_id = data.get('id')
    target_name = data.get('targetName', 'Unknown Target')
    results = data.get('results', [])
    logs = data.get('logs', [])
    risk_score = data.get('riskScore', 0)
    ai_report = data.get('aiReport')
    connection = data.get('connection', {})
    assessment = data.get('assessment', {})
    findings = data.get('findings', [])
    phase_records = data.get('phase_records', [])
    structured = data.get('structured', {})
    structured_trace_id = structured.get("trace_id") if isinstance(structured, dict) else None
    supervisor = structured.get('supervisor', {}) if isinstance(structured, dict) else {}
    results_payload = _build_history_results_payload({
        **data,
        "aiReport": ai_report,
        "connection": connection,
        "assessment": assessment,
        "findings": findings,
        "phase_records": phase_records,
        "structured": structured,
    })
    
    # Check if a history record already exists
    history = ScanHistory.query.filter_by(session_id=session_id, user_id=current_user.id).first()
    supervisor_snapshot = SupervisorMetricSnapshot.query.filter_by(session_id=session_id, user_id=current_user.id).first()
    
    try:
        if history:
            # Update existing record
            history.results_json = json.dumps(results_payload)
            history.logs = json.dumps(logs)
            history.completed_at = _get_utc_now()
            history.risk_score = risk_score
        else:
            # Create a new history record
            history = ScanHistory(
                user_id=current_user.id,
                session_id=session_id,
                target_ip=connection.get('ip'),
                target_mac=connection.get('bluetoothMac') or connection.get('canInterface'),
                status='completed',
                completed_at=_get_utc_now(),
                results_json=json.dumps(results_payload),
                logs=json.dumps(logs), # Added logs here
                risk_score=risk_score
            )
            db.session.add(history)

        if supervisor:
            metrics_payload = supervisor.get("metrics", {}) if isinstance(supervisor, dict) else {}
            adjustments_payload = supervisor.get("adjustments", []) if isinstance(supervisor, dict) else []
            model_profile = _build_supervisor_model_profile(structured)
            if supervisor_snapshot:
                supervisor_snapshot.target_ip = connection.get('ip')
                supervisor_snapshot.model_profile = model_profile
                supervisor_snapshot.metrics_json = json.dumps(metrics_payload)
                supervisor_snapshot.adjustments_json = json.dumps(adjustments_payload)
                supervisor_snapshot.created_at = _get_utc_now()
            else:
                supervisor_snapshot = SupervisorMetricSnapshot(
                    user_id=current_user.id,
                    session_id=session_id,
                    target_ip=connection.get('ip'),
                    model_profile=model_profile,
                    metrics_json=json.dumps(metrics_payload),
                    adjustments_json=json.dumps(adjustments_payload),
                )
                db.session.add(supervisor_snapshot)

        # First-class evidence artifacts: keep findings, phase records, and structured snapshots queryable.
        ExecutionArtifact.query.filter_by(
            user_id=current_user.id,
            session_id=session_id,
            artifact_type='session_summary',
        ).delete(synchronize_session=False)
        ExecutionArtifact.query.filter_by(
            user_id=current_user.id,
            session_id=session_id,
            artifact_type='structured_snapshot',
        ).delete(synchronize_session=False)
        ExecutionArtifact.query.filter_by(
            user_id=current_user.id,
            session_id=session_id,
            artifact_type='phase_record',
        ).delete(synchronize_session=False)
        ExecutionArtifact.query.filter_by(
            user_id=current_user.id,
            session_id=session_id,
            artifact_type='finding',
        ).delete(synchronize_session=False)

        _persist_execution_artifact(
            user_id=current_user.id,
            session_id=session_id,
            artifact_type='session_summary',
            trace_id=structured_trace_id,
            target_ip=connection.get('ip'),
            target_mac=connection.get('bluetoothMac') or connection.get('canInterface'),
            payload=_build_execution_artifact_payload(
                session_id=session_id,
                target_name=target_name,
                risk_score=risk_score,
                ai_report=ai_report,
                connection=connection,
                summary={
                    "finding_count": len(findings or []),
                    "phase_count": len(phase_records or []),
                    "has_supervisor": bool(supervisor),
                },
            ),
            replace_existing=False,
        )
        _persist_execution_artifact(
            user_id=current_user.id,
            session_id=session_id,
            artifact_type='structured_snapshot',
            trace_id=structured_trace_id,
            target_ip=connection.get('ip'),
            target_mac=connection.get('bluetoothMac') or connection.get('canInterface'),
            payload=_build_execution_artifact_payload(
                structured=structured,
            ),
            replace_existing=False,
        )
        for phase_record in phase_records or []:
            _persist_execution_artifact(
                user_id=current_user.id,
                session_id=session_id,
                artifact_type='phase_record',
                trace_id=phase_record.get('trace_id') or structured_trace_id,
                target_ip=connection.get('ip'),
                target_mac=connection.get('bluetoothMac') or connection.get('canInterface'),
                payload=_build_execution_artifact_payload(
                    phase_record=phase_record,
                ),
                replace_existing=False,
            )
        for finding in findings or []:
            _persist_execution_artifact(
                user_id=current_user.id,
                session_id=session_id,
                artifact_type='finding',
                trace_id=finding.get('trace_id') or structured_trace_id,
                poc_filename=finding.get('pocId') or finding.get('name'),
                poc_name=finding.get('name'),
                target_ip=finding.get('target_ip') or connection.get('ip'),
                target_mac=connection.get('bluetoothMac') or connection.get('canInterface'),
                payload=_build_execution_artifact_payload(
                    finding=finding,
                ),
                replace_existing=False,
            )

        db.session.commit()
        logger.info(f"Session {session_id} saved/updated to history for user {current_user.username}")
        return jsonify({"message": "Session saved successfully", "id": history.id}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to save session: {str(e)}")
        return jsonify({"message": f"Error saving session: {str(e)}"}), 500

@app.route('/api/history/<int:history_id>', methods=['DELETE'])
@token_required
def delete_history_item(current_user, history_id):
    """Delete a single history record with RBAC."""
    history = ScanHistory.query.get(history_id)
    if not history:
        return jsonify({"message": "History record not found"}), 404
        
    # RBAC check: Only owner or admin can delete
    if current_user.role != 'admin' and history.user_id != current_user.id:
        return jsonify({"message": "Permission denied"}), 403
        
    session_id = history.session_id
    try:
        # Delete related supervisor snapshots if session_id exists
        if session_id:
            SupervisorMetricSnapshot.query.filter_by(session_id=session_id).delete()
            ExecutionArtifact.query.filter_by(session_id=session_id).delete()
            
        db.session.delete(history)
        db.session.commit()
        logger.info(f"User {current_user.username} deleted history record {history_id} (Session: {session_id})")
        return jsonify({"message": "Record deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to delete history record {history_id}: {str(e)}")
        return jsonify({"message": "Error deleting record"}), 500

@app.route('/api/history/delete-batch', methods=['POST'])
@token_required
def delete_history_batch(current_user):
    """Delete multiple history records with RBAC."""
    data = request.json or {}
    ids = data.get('ids', [])
    if not ids or not isinstance(ids, list):
        return jsonify({"message": "No IDs provided"}), 400
        
    deleted_count = 0
    try:
        for history_id in ids:
            history = ScanHistory.query.get(history_id)
            if not history:
                continue
                
            # RBAC check: Only owner or admin can delete
            if current_user.role != 'admin' and history.user_id != current_user.id:
                continue
            
            session_id = history.session_id
            if session_id:
                SupervisorMetricSnapshot.query.filter_by(session_id=session_id).delete()
                ExecutionArtifact.query.filter_by(session_id=session_id).delete()
                
            db.session.delete(history)
            deleted_count += 1
            
        db.session.commit()
        logger.info(f"User {current_user.username} deleted {deleted_count} history records")
        return jsonify({"message": f"Successfully deleted {deleted_count} records"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Batch delete failed: {str(e)}")
        return jsonify({"message": f"Error during batch deletion: {str(e)}"}), 500

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

    history = [scan.to_dict() for scan in scans]
    return jsonify({"history": history, "source": 'primary'})

@app.route('/api/supervisor-metrics', methods=['GET'])
@token_required
def get_supervisor_metrics(current_user):
    """Get time-series supervisor metrics snapshots for trend analysis."""
    try:
        limit = request.args.get('limit', 20, type=int)
        if current_user.role == 'admin':
            rows = SupervisorMetricSnapshot.query.order_by(SupervisorMetricSnapshot.created_at.desc()).limit(limit).all()
        else:
            rows = SupervisorMetricSnapshot.query.filter_by(user_id=current_user.id).order_by(SupervisorMetricSnapshot.created_at.desc()).limit(limit).all()

        snapshots = [row.to_dict() for row in rows]
        aggregate = {
            "total_sessions": len(snapshots),
            "total_events": sum((snap.get("metrics", {}) or {}).get("total_events", 0) for snap in snapshots),
            "repeat_tool_calls": sum((snap.get("metrics", {}) or {}).get("repeat_tool_calls", 0) for snap in snapshots),
            "no_progress_events": sum((snap.get("metrics", {}) or {}).get("no_progress_events", 0) for snap in snapshots),
            "cascading_error_events": sum((snap.get("metrics", {}) or {}).get("cascading_error_events", 0) for snap in snapshots),
            "planner_fallbacks": sum((snap.get("metrics", {}) or {}).get("planner_fallbacks", 0) for snap in snapshots),
            "deduplicated_steps": sum((snap.get("metrics", {}) or {}).get("deduplicated_steps", 0) for snap in snapshots),
            "pruned_steps": sum((snap.get("metrics", {}) or {}).get("pruned_steps", 0) for snap in snapshots),
            "execution_errors": sum((snap.get("metrics", {}) or {}).get("execution_errors", 0) for snap in snapshots),
            "confirmed_findings": sum((snap.get("metrics", {}) or {}).get("confirmed_findings", 0) for snap in snapshots),
            "skipped_plan_steps": sum((snap.get("metrics", {}) or {}).get("skipped_plan_steps", 0) for snap in snapshots),
        }
        return jsonify({
            "snapshots": snapshots,
            "aggregate": aggregate,
            "source": "supervisor_metric_snapshots",
        })
    except Exception as e:
        logger.error(f"Failed to fetch supervisor metrics: {e}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/session-artifacts/<session_id>', methods=['GET'])
@token_required
def get_session_artifacts(current_user, session_id):
    """Return persisted execution artifacts for a scan session."""
    try:
        query = ExecutionArtifact.query.filter_by(session_id=session_id)
        if current_user.role != 'admin':
            query = query.filter_by(user_id=current_user.id)
        rows = query.order_by(ExecutionArtifact.created_at.asc()).all()
        return jsonify({
            "session_id": session_id,
            "artifacts": [row.to_dict() for row in rows],
            "count": len(rows),
        })
    except Exception as exc:
        logger.error(f"Failed to fetch session artifacts for {session_id}: {exc}")
        return jsonify({"message": str(exc)}), 500


@app.route('/api/evaluation/score', methods=['POST'])
@token_required
def score_evaluation_session(current_user):
    """Score a saved session against benchmark expectations."""
    try:
        data = request.json or {}
        session_id = data.get("session_id")
        benchmark = data.get("benchmark") or {}
        if not session_id:
            return jsonify({"message": "session_id is required"}), 400

        query = ScanHistory.query.filter_by(session_id=session_id)
        if current_user.role != 'admin':
            query = query.filter_by(user_id=current_user.id)
        history = query.first()
        if not history:
            return jsonify({"message": "Session not found"}), 404

        session_payload = history.to_dict()
        score = _score_session_against_benchmark(session_payload, benchmark)
        score["source"] = "scan_history"
        score["artifacts"] = ExecutionArtifact.query.filter_by(session_id=session_id).count()
        return jsonify(score)
    except Exception as exc:
        logger.error(f"Failed to score session evaluation: {exc}")
        return jsonify({"message": str(exc)}), 500


@app.route('/api/evaluation/benchmarks', methods=['GET'])
@token_required
def list_evaluation_benchmarks(current_user):
    """List the default benchmark suite and its metadata."""
    try:
        suite = load_benchmark_suite_data()
        benchmarks = suite.get("benchmarks", []) or []
        return jsonify({
            "suite": {
                "id": suite.get("id"),
                "name": suite.get("name"),
                "description": suite.get("description"),
                "benchmark_count": len(benchmarks),
            },
            "benchmarks": benchmarks,
        })
    except Exception as exc:
        logger.error(f"Failed to list benchmark suite: {exc}")
        return jsonify({"message": str(exc)}), 500


@app.route('/api/evaluation/run-suite', methods=['POST'])
@token_required
def run_evaluation_suite(current_user):
    """Run the regression benchmark suite against a saved session or payload."""
    try:
        data = request.json or {}
        benchmark_ids = set(data.get("benchmark_ids") or [])
        session_payload = data.get("session_payload")
        session_id = data.get("session_id")

        if session_payload and not isinstance(session_payload, dict):
            return jsonify({"message": "session_payload must be an object"}), 400

        if not session_payload:
            if not session_id:
                return jsonify({"message": "session_id or session_payload is required"}), 400
            query = ScanHistory.query.filter_by(session_id=session_id)
            if current_user.role != 'admin':
                query = query.filter_by(user_id=current_user.id)
            history = query.first()
            if not history:
                return jsonify({"message": "Session not found"}), 404
            session_payload = history.to_dict()

        suite = load_benchmark_suite_data()
        benchmarks = suite.get("benchmarks", []) or []
        if benchmark_ids:
            benchmarks = [benchmark for benchmark in benchmarks if benchmark.get("id") in benchmark_ids]
        suite["benchmarks"] = benchmarks

        result = run_benchmark_suite(session_payload, suite)
        result["source"] = "benchmark_suite"
        result["selected_benchmark_ids"] = sorted(benchmark_ids)
        result["session_id"] = session_payload.get("session_id")
        result["artifacts"] = ExecutionArtifact.query.filter_by(session_id=session_payload.get("session_id")).count() if session_payload.get("session_id") else 0
        return jsonify(result)
    except Exception as exc:
        logger.error(f"Failed to run evaluation suite: {exc}")
        return jsonify({"message": str(exc)}), 500

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

# ==========================================
# Patent-1: Topology-Aware Scan Endpoint
# ==========================================

@app.route('/api/topology', methods=['POST'])
@token_required
def topology_scan(current_user):
    """
    拓扑感知网络扫描 — 发现安全网关、枚举 ECU 节点、推荐最优攻击向量
    """
    data = request.json or {}
    target_ip = data.get('target_ip')
    if not target_ip:
        return jsonify({"error": "target_ip is required"}), 400

    try:
        from topology_scanner import TopologyAwareScanner
        scanner = TopologyAwareScanner(target_ip, timeout=4.0)
        topo = scanner.scan()
        logger.info(f"Topology scan by {current_user.username}: {target_ip} -> "
                    f"SEC-GW={topo.has_security_gateway}, vector={topo.recommended_attack_vector}")
        return jsonify(topo.to_dict())
    except ImportError:
        return jsonify({"error": "topology_scanner module not found"}), 500
    except Exception as e:
        logger.error(f"Topology scan error: {e}")
        return jsonify({"error": str(e)}), 500


# ==========================================
# Patent-1: Adaptive Context Endpoint (IVI/Static CAN)
# ==========================================

@app.route('/api/adaptive-context', methods=['POST'])
@token_required
def adaptive_context(current_user):
    """
    自适应上下文探测 — 针对 IVI 测试场景。
    基于已知开放端口，探测：
      1. 服务指纹 → 自动裁剪相关 PoC 集合
      2. IVI 系统负载状态 → 推荐扫描节奏
      3. 认证机制 (SSH/HTTP/UDS) → 推荐最优利用策略
      4. 协议响应反馈历史 → 闭环决策依据
    """
    data = request.json or {}
    target_ip = data.get('target_ip')
    open_ports = data.get('open_ports', [])

    if not target_ip:
        return jsonify({"error": "target_ip is required"}), 400

    try:
        from physical_safety_monitor import get_or_create_engine, clear_engine
        if data.get('reset', False):
            clear_engine(target_ip)
        engine = get_or_create_engine(target_ip)
        summary = engine.initialize(open_ports)
        logger.info(
            f"Adaptive context by {current_user.username}: {target_ip}, "
            f"services={summary.get('detected_services')}, "
            f"load={summary.get('ivi_load', {}).get('status')}"
        )
        return jsonify(summary)
    except Exception as e:
        logger.error(f"Adaptive context error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/test-ai-config', methods=['POST'])
@token_required
def test_ai_config(current_user):
    """
    Test the AI configuration (API key, Base URL, models) by making a lightweight request.
    Useful for ensuring the credentials work before starting a long scan.
    """
    data = request.json or {}
    ai_config = data.get('ai_config') or {}
    
    # Fallback to saved config if not provided in request
    if not isinstance(ai_config, dict) or not any(str(ai_config.get(key) or "").strip() for key in ("api_key", "apiKey", "base_url", "baseUrl")):
        ai_config = _load_user_ai_config(current_user.id)
        
    normalized, error = _validate_ai_config(ai_config)
    if error:
        return jsonify({"success": False, "message": error}), 400
        
    # Use Fast Model for testing if available, else default to qwen-plus
    test_model = normalized.get("fast_model") or normalized.get("strong_model") or "qwen-plus"
    
    logger.info(f"Testing AI config for user {current_user.username} using model {test_model}")
    
    try:
        response = requests.post(
            f"{normalized['base_url'].rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {normalized['api_key']}",
                "Content-Type": "application/json",
            },
            json={
                "model": test_model,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 5
            },
            timeout=10
        )
        
        if response.status_code == 200:
            return jsonify({
                "success": True, 
                "message": f"Successfully connected to {test_model}.",
                "model": test_model
            })
        else:
            try:
                err_data = response.json()
                msg = err_data.get('error', {}).get('message', response.text)
            except:
                msg = response.text
            return jsonify({
                "success": False, 
                "message": f"API returned error ({response.status_code}): {msg}"
            })
            
    except requests.exceptions.RequestException as e:
        return jsonify({
            "success": False, 
            "message": f"Network/Connection failed: {str(e)}"
        })
    except Exception as e:
        logger.error(f"Unexpected error testing AI config: {e}")
        return jsonify({
            "success": False, 
            "message": f"Internal error: {str(e)}"
        })


@app.route('/api/agent-scan', methods=['POST'])
@token_required
def agent_scan(current_user):
    """
    启动 4-Agent 自主协作渗透测试（侦察 → 决策 → 执行 → 评估）
    使用 MCP 工具 + Qwen (千问) Function Calling 驱动
    """
    data = request.json or {}
    target_ip = data.get('target_ip')
    target_name = data.get('target_name', 'Vehicle Target')
    phase = data.get('phase')  # 可指定单独执行某个 phase
    resume_from = data.get('resume_from')
    state = data.get('state') or {}
    context = data.get('context', '')
    ai_config = data.get('ai_config') or {}
    if not isinstance(ai_config, dict) or not any(str(ai_config.get(key) or "").strip() for key in ("api_key", "apiKey", "base_url", "baseUrl")):
        ai_config = _load_user_ai_config(current_user.id)
    # 可选资源参数（用于 Agent 智能过滤 PoC）
    can_interface  = data.get('can_interface', '')
    bluetooth_mac  = data.get('bluetooth_mac', '')
    wifi_interface = data.get('wifi_interface', '')

    if not target_ip:
        return jsonify({"error": "target_ip is required"}), 400

    normalized_ai_config, ai_error = _validate_ai_config(ai_config)
    if ai_error:
        return jsonify({"error": ai_error, "error_code": "MODEL_API_KEY_MISSING"}), 400

    logger.info(f"Agent scan started by {current_user.username}: {target_name} ({target_ip})")

    def _error_payload(message: str, code: str, status: int = 500):
        return jsonify({"error": message, "error_code": code}), status

    try:
        from agent_orchestrator import AgentOrchestrator
        orch = AgentOrchestrator(
            target_ip=target_ip,
            target_name=target_name,
            auth_token=request.headers.get('Authorization'),
            llm_config=normalized_ai_config,
            can_interface=can_interface,
            bluetooth_mac=bluetooth_mac,
            wifi_interface=wifi_interface,
        )

        if resume_from:
            orch.hydrate_state(state)
            report = orch.run_from_phase(resume_from)
            logger.info(f"Agent scan resumed for {target_ip} from {resume_from} in {report['duration_seconds']}s")
            return jsonify(report)

        if phase:
            # 单 Phase 模式（用于步进式调试）
            if state:
                orch.hydrate_state(state)
            res_data = orch.run_phase(phase, context=context)
            return jsonify({
                "phase": phase,
                "target_ip": target_ip,
                "result": res_data["result"],
                "structured_result": res_data.get("structured_result", {}),
                "logs": res_data.get("logs", []),
                "findings": res_data.get("findings", []),
                "phase_records": res_data.get("phase_records", []),
            })
        else:
            # 全量 4-Agent 协作模式
            report = orch.run_full_assessment()
            logger.info(f"Agent scan completed for {target_ip} in {report['duration_seconds']}s")
            return jsonify(report)

    except ImportError as e:
        return _error_payload(f"Agent module not available: {e}", "AGENT_MODULE_UNAVAILABLE")
    except RuntimeError as e:
        message = str(e)
        if "API key" in message or "base_url" in message:
            return _error_payload(message, "MODEL_API_KEY_MISSING")
        if "MCP" in message:
            return _error_payload(message, "MCP_UNAVAILABLE")
        return _error_payload(message, "AGENT_RUNTIME_ERROR")
    except Exception as e:
        logger.error(f"Agent scan error: {e}")
        message = str(e)
        if "API key" in message or "base_url" in message:
            return _error_payload(message, "MODEL_API_KEY_MISSING")
        if "MCP" in message or "AutoSec API" in message:
            return _error_payload(message, "MCP_UNAVAILABLE")
        return _error_payload(message, "AGENT_SCAN_FAILED")


if __name__ == '__main__':
    if len(sys.argv) >= 4 and sys.argv[1] == '--run-sandbox':
        sys.argv = [sys.argv[0], sys.argv[2], sys.argv[3]]
        from sandbox_runner import main as sandbox_main
        raise SystemExit(sandbox_main())

    logger.info(f"AutoSec Execution Engine starting on port {CONFIG.flask_port}...")
    logger.info(f"PoCs directory: {POCS_DIR}")
    for warning in RUNTIME_WARNINGS:
        logger.warning(warning)

    with app.app_context():
        db.create_all()
        logger.info("Database schema checked.")

    # ── 初始化自适应上下文引擎（Patent-1: Adaptive Context for IVI Lab）──
    try:
        from physical_safety_monitor import AdaptiveContextEngine
        logger.info("Adaptive Context Engine loaded (IVI service-fingerprint + load-adaptive mode)")
    except Exception as e:
        logger.warning(f"Adaptive Context Engine load warning: {e}")
    
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
    logger.info("New endpoints: /api/topology, /api/physical-state, /api/agent-scan")

    # Bind to 0.0.0.0 to allow access if frontend is on a different device
    # Disable flask default click logger to favor our custom logger
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host=CONFIG.flask_host, port=CONFIG.flask_port, debug=CONFIG.flask_debug, use_reloader=False)
