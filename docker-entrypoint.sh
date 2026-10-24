#!/usr/bin/env bash
# docker-entrypoint.sh — 容器啟動入口
set -euo pipefail

cd /opt/stress-tool
source .venv/bin/activate

# 首次啟動：對全部測項跑一次依賴健康檢查
# 只在資料庫不存在時執行（避免每次重啟都重跑）
if [[ ! -f "data/db.sqlite3" ]]; then
  echo "[entrypoint] 首次啟動，執行測項健康檢查..."
  python3 scripts/run_healthcheck.py || echo "[entrypoint] 健康檢查未完成（不影響啟動）"
fi

echo "=================================================="
echo " ICS Security Stress Testing Platform"
echo " 瀏覽器打開： http://<HOST_IP>:${STRESS_TOOL_PORT}"
echo " 按 Ctrl+C 停止服務"
echo "=================================================="

exec python3 -m uvicorn app.main:app \
  --host "${STRESS_TOOL_HOST:-0.0.0.0}" \
  --port "${STRESS_TOOL_PORT:-8000}"
