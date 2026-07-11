#!/usr/bin/env bash
# 无 CAN 分析仪、直连 CAN 总线：被动抓包 + 1 条 UDS 探测 + 平台 PoC 证据
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVIDENCE="${ROOT}/lab/evidence"
CAN_CSV="${ROOT}/lab/can_test_records.csv"
INTERFACE="${1:-can0}"
DURATION="${2:-15}"
API="${API_BASE:-http://127.0.0.1:5002}"

mkdir -p "${EVIDENCE}"

if [[ ! -f "${CAN_CSV}" ]]; then
  cp "${ROOT}/lab/can_test_records.template.csv" "${CAN_CSV}"
fi

echo "[CAN] 被动嗅探 ${DURATION}s on ${INTERFACE} ..."
if [[ "${INTERFACE}" == PCAN_* ]] || [[ "${INTERFACE}" == pcan* ]]; then
  echo "[CAN] PCAN 接口：跳过 candump/cansend（请依赖平台 canbus/01_CAN_Bus_Sniff.py）" | tee "${EVIDENCE}/can_passive.log"
  FRAME_COUNT=0
  UDS_RESPONSE="skipped for PCAN; use PCAN-View or platform PoC"
elif command -v candump >/dev/null 2>&1; then
  timeout "${DURATION}" candump "${INTERFACE}" -L > "${EVIDENCE}/can_passive.log" 2>&1 || true
  FRAME_COUNT=$(grep -c '^(' "${EVIDENCE}/can_passive.log" 2>/dev/null || echo 0)
  echo "[CAN] 捕获帧数: ${FRAME_COUNT}"
else
  echo "[WARN] 未安装 candump，跳过被动抓包" | tee "${EVIDENCE}/can_passive.log"
  FRAME_COUNT=0
fi

echo "[CAN] UDS DefaultSession 探测 (7E0#0210010000000000) ..."
UDS_LOG="${EVIDENCE}/CAN-002_uds_probe.log"
UDS_RESPONSE="not_sent"
if [[ "${INTERFACE}" == PCAN_* ]] || [[ "${INTERFACE}" == pcan* ]]; then
  UDS_RESPONSE="skipped for PCAN; send UDS via PCAN-View and attach log"
elif command -v cansend >/dev/null 2>&1; then
  if cansend "${INTERFACE}" 7E0#0210010000000000 2>"${UDS_LOG}.err"; then
    UDS_RESPONSE="sent; check candump for 7E8 response within 2s"
    timeout 2 candump "${INTERFACE}" -L 2>/dev/null | head -20 >> "${UDS_LOG}" || true
  else
    UDS_RESPONSE="cansend failed: $(cat "${UDS_LOG}.err" 2>/dev/null || echo unknown)"
  fi
else
  UDS_RESPONSE="cansend not installed"
fi
echo "${UDS_RESPONSE}" > "${UDS_LOG}"

echo "[CAN] 调用平台 CAN Sniff PoC ..."
SNIFF_JSON="${EVIDENCE}/CAN-001_sniff_poc.json"
curl -sf -X POST "${API}/api/v1/run_poc" \
  -H "Authorization: Bearer ${AUTOSEC_TOKEN:?AUTOSEC_TOKEN is required}" \
  -H 'Content-Type: application/json' \
  -d "{\"filename\":\"canbus/01_CAN_Bus_Sniff.py\",\"params\":{\"can_interface\":\"${INTERFACE}\"},\"session_id\":\"CAN-SNIFF-$(date +%Y%m%d_%H%M%S)\"}" \
  > "${SNIFF_JSON}" 2>"${EVIDENCE}/can_sniff_curl.err" || echo '{"error":"api unavailable"}' > "${SNIFF_JSON}"

python3 - <<'PY' "${CAN_CSV}" "${INTERFACE}" "${EVIDENCE}" "${FRAME_COUNT}" "${UDS_RESPONSE}"
import csv
import sys
from datetime import datetime
from pathlib import Path

csv_path, interface, evidence, frame_count, uds_response = sys.argv[1:6]
path = Path(csv_path)
rows = []
if path.is_file():
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
existing_ids = {r.get("case_id") for r in rows}

def append_row(case_id, test_type, can_id, frame_type, payload, send_count, response, abnormal, blocked, evidence_file, notes):
    if case_id in existing_ids:
        return
    rows.append({
        "case_id": case_id,
        "test_type": test_type,
        "interface": interface,
        "can_id": can_id,
        "frame_type": frame_type,
        "payload_hex": payload,
        "send_count": str(send_count),
        "period_ms": "0",
        "input_file": "",
        "gateway_path": "direct_bus",
        "observed_response": response,
        "abnormal": str(abnormal).lower(),
        "blocked_by_safety": str(blocked).lower(),
        "evidence_file": evidence_file,
        "notes": notes,
    })

append_row(
    "CAN-001", "passive_sniff", "N/A", "data", "",
    0, f"{frame_count} frames captured", "false" if int(frame_count or 0) > 0 else "true", "false",
    f"{evidence}/can_passive.log",
    f"direct bus passive; recorded {datetime.now():%Y-%m-%d %H:%M:%S}",
)
append_row(
    "CAN-002", "uds_injection", "0x7E0", "data", "0210010000000000",
    1, uds_response, "false", "false",
    f"{evidence}/CAN-002_uds_probe.log",
    "DefaultSession probe only; authorized bench/vehicle",
)
append_row(
    "CAN-003", "fuzzing", "0x7DF", "data", "02??????????????",
    0, "not executed on real vehicle", "false", "true",
    "",
    "一晚实验：真实车机跳过 fuzzing，仅记录安全拦截",
)
append_row(
    "CAN-004", "dos_remote_frame", "0x200", "remote", "",
    0, "blocked by experiment policy", "false", "true",
    "",
    "无分析仪直连：DoS 类用 blocked_by_safety 证明可控",
)

fieldnames = list(rows[0].keys()) if rows else [
    "case_id", "test_type", "interface", "can_id", "frame_type", "payload_hex",
    "send_count", "period_ms", "input_file", "gateway_path", "observed_response",
    "abnormal", "blocked_by_safety", "evidence_file", "notes",
]
with path.open("w", encoding="utf-8-sig", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
print(f"Updated {path}")
PY

echo "[CAN] 完成。记录: ${CAN_CSV}"
