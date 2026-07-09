#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${ROOT}/lab/experiment_config.local.json"
if [[ ! -f "${CONFIG}" ]]; then
  CONFIG="${ROOT}/lab/experiment_config.full.json"
  echo "[info] 未找到 experiment_config.local.json，使用 full 模板（请先填写 IP/API Key）"
fi
exec python3 "${ROOT}/lab/run_full_experiment.py" --config "${CONFIG}" "$@"
