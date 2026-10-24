#!/usr/bin/env bash
# run.sh — 一個指令啟動 Kali 壓力測試平台
#
# 用法：
#   sudo ./run.sh
#
# 建議用 root 執行：SYN Flood、UDP Flood、EtherCAT/PROFINET/GOOSE 這類 Layer 2/原始
# socket 測項需要 root 或 CAP_NET_RAW 才能發送封包，用 root 跑最簡單、跟大部分
# Kali 上的滲透測試工具習慣一致。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -d ".venv" ]]; then
  echo "找不到虛擬環境，請先執行：sudo ./install.sh"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "!! 目前不是用 root 執行。SYN Flood / UDP Flood / EtherCAT / PROFINET / GOOSE 這類"
  echo "   需要 raw socket 的測項會失敗。建議用：sudo ./run.sh"
  echo ""
fi

source .venv/bin/activate

export STRESS_TOOL_HOST="${STRESS_TOOL_HOST:-127.0.0.1}"
export STRESS_TOOL_PORT="${STRESS_TOOL_PORT:-8000}"

echo "=================================================="
echo " 啟動中...瀏覽器打開： http://${STRESS_TOOL_HOST}:${STRESS_TOOL_PORT}"
echo " 按 Ctrl+C 停止服務"
echo "=================================================="

exec python3 -m uvicorn app.main:app --host "${STRESS_TOOL_HOST}" --port "${STRESS_TOOL_PORT}"
