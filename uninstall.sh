#!/usr/bin/env bash
# uninstall.sh — 解除安裝本工具在這台機器上建立的東西，並清除全部測試資料
#
# 用法：
#   sudo ./uninstall.sh              互動式，會先列出將被刪除的內容並要求輸入 yes 確認
#   sudo ./uninstall.sh -y           跳過互動確認，直接執行（自動化/腳本化情境使用）
#   sudo ./uninstall.sh --keep-data  只移除 Python 虛擬環境，保留 data/ 底下的資料庫、
#                                    專案紀錄、封包擷取檔、報告、log（如果只是想重灌
#                                    Python 環境、不想連測試紀錄也一起清掉，用這個）
#
# 這支腳本會移除：
#   1. Python 虛擬環境（.venv，install.sh 建立的）
#   2. 全部測試資料（data/ 底下的 db.sqlite3、data/projects/ 每個專案的紀錄、
#      封包擷取檔、報告、log；除非有帶 --keep-data）
#   3. 各目錄底下殘留的 __pycache__ 快取
#
# 這支腳本刻意「不會」動到的東西：
#   - install.sh 用 apt 裝的系統套件／CLI 工具（nmap、hping3、tshark、rustscan、
#     wrk、slowhttptest、netsniff-ng、PDF 報告用的 render 函式庫等）——這些是系統
#     層級的套件，可能被其他程式共用，不是本工具專屬安裝的東西，所以刻意不去動它們，
#     要清掉請自行用 apt remove 處理。
#   - 本工具的原始碼本身（app/ 底下的程式碼、README.md、使用手冊、install.sh／
#     run.sh 本身）——「解除安裝」指的是移除「安裝之後產生的東西」（虛擬環境、
#     資料），不是把整個工具的原始碼刪掉；之後要重新使用，直接重跑
#     sudo ./install.sh 即可，不需要重新下載/解壓縮整包工具。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ $EUID -ne 0 ]]; then
  echo "請用 root 執行（sudo ./uninstall.sh）——install.sh 是用 root 建立虛擬環境／資料目錄的，"
  echo "解除安裝時通常也需要 root 權限才能完整刪除。"
  exit 1
fi

ASSUME_YES=0
KEEP_DATA=0
for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    --keep-data) KEEP_DATA=1 ;;
    -h|--help)
      echo "用法：sudo ./uninstall.sh [-y|--yes] [--keep-data]"
      echo "  -y, --yes     跳過互動確認，直接執行"
      echo "  --keep-data   只移除 Python 虛擬環境，保留 data/ 底下的測試資料"
      exit 0
      ;;
    *)
      echo "未知參數：$arg（可用：-y/--yes、--keep-data）"
      exit 1
      ;;
  esac
done

# 資料目錄路徑跟 app/config.py 一致，支援 STRESS_TOOL_DATA_DIR 環境變數覆寫
# （例如啟動時有自訂資料目錄位置，解除安裝時也要清同一個地方）。
DATA_DIR="${STRESS_TOOL_DATA_DIR:-$SCRIPT_DIR/data}"

echo "=================================================="
echo " 即將移除以下內容："
echo "   - Python 虛擬環境：$SCRIPT_DIR/.venv"
if [[ "$KEEP_DATA" -eq 0 ]]; then
  echo "   - 全部測試資料（資料庫、專案紀錄、封包擷取檔、報告、log）：$DATA_DIR"
else
  echo "   - （已指定 --keep-data，$DATA_DIR 底下的資料庫與專案紀錄將保留不動）"
fi
echo "   - 各目錄底下殘留的 __pycache__ 快取"
echo ""
echo " 不會動到的東西："
echo "   - install.sh 用 apt 裝的系統套件／CLI 工具（nmap、hping3、tshark、rustscan、"
echo "     wrk、slowhttptest、netsniff-ng、PDF 報告用的 render 函式庫等）——這些可能"
echo "     被其他程式共用，這支腳本刻意不去處理，要清掉請自行用 apt remove。"
echo "   - 本工具的原始碼本身（app/、README.md、使用手冊、install.sh／run.sh）——"
echo "     之後要重新使用，直接重跑 sudo ./install.sh 即可。"
echo "=================================================="

if [[ "$ASSUME_YES" -ne 1 ]]; then
  read -r -p "確定要繼續嗎？此動作無法復原，輸入 yes 才會執行：" CONFIRM
  if [[ "$CONFIRM" != "yes" ]]; then
    echo "已取消，沒有刪除任何東西。"
    exit 0
  fi
fi

# 盡力偵測本工具是否還在執行中（uvicorn app.main:app），有的話先嘗試停止，
# 避免刪除 .venv／資料庫的過程中它還在寫入。這只是 best-effort 的便利偵測，
# 不保證抓到所有情況（例如用不同啟動方式跑的話），偵測不到也不影響後續刪除。
RUNNING_PIDS="$(pgrep -f "uvicorn app.main:app" 2>/dev/null || true)"
if [[ -n "$RUNNING_PIDS" ]]; then
  echo "==> 偵測到工具目前可能正在執行中（PID: $RUNNING_PIDS），嘗試停止..."
  kill $RUNNING_PIDS 2>/dev/null || true
  sleep 1
fi

echo "==> [1/3] 移除 Python 虛擬環境"
rm -rf "$SCRIPT_DIR/.venv"

if [[ "$KEEP_DATA" -eq 0 ]]; then
  echo "==> [2/3] 清除全部測試資料（資料庫／專案紀錄／封包擷取檔／報告／log）"
  rm -rf "$DATA_DIR"
else
  echo "==> [2/3] 已指定 --keep-data，略過清除測試資料"
fi

echo "==> [3/3] 清除 __pycache__ 快取"
find "$SCRIPT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

echo ""
echo "=================================================="
echo " 解除安裝完成。"
echo " 系統套件（nmap/hping3/tshark/...）未被移除；如果要一併清掉，請自行用"
echo " apt remove 處理，本工具不會自動幫你做這件事。"
echo " 之後要重新安裝並使用，直接執行：sudo ./install.sh"
echo "=================================================="
