#!/usr/bin/env bash
# install.sh — 一個指令裝好 Kali 壓力測試平台所需的一切
#
# 用法：
#   sudo ./install.sh
#
# 這支腳本會裝：
#   1. apt 套件：python3 / nmap(含nping) / hping3 / wrk / slowhttptest / tshark 等 CLI 工具
#   2. Python 虛擬環境 (.venv) 並安裝 requirements.txt 裡的所有 Python 套件
#
# 因為壓力測項需要開 raw socket（SYN flood 等），平台本身建議直接用 root 執行
# （這也是 Kali 上大部分滲透測試工具的慣例），所以這支腳本也要求用 root 執行。

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "請用 root 執行（sudo ./install.sh），因為要裝系統套件、且平台本身也需要 root 權限做 raw socket 操作。"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# apt 在裝套件時，如果偵測到有服務連結到剛更新的舊版函式庫，預設會跳出
# needrestart 的互動式勾選畫面問「要重啟哪些服務」，會卡住一個指令跑到底的流程。
# 這裡強制關閉互動、讓它自動重啟該重啟的服務，不用手動選。
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

echo "==> [1/5] 更新 apt 套件索引"
apt-get update -y

echo "==> [2/5] 安裝系統套件（CLI 壓力測試工具 + Python 環境 + PDF 報告所需的系統函式庫）"
# 核心 CLI 工具（rustscan 是可選的快速 Port Scan 引擎，Kali 近期版本的官方倉庫有收錄；
# 裝不到也沒關係，Port Scan 頁面選別的掃描類型即可，不影響其他功能）
CORE_PKGS=(python3 python3-venv python3-pip nmap hping3 tshark rustscan)
# HTTP 測項用
HTTP_PKGS=(wrk slowhttptest)
# 網路層（L2）進階測項用。netsniff-ng 套件內含 mausezahn，
# 用於 STP/PVST+ BPDU 洪水測項（netlayer/bpdu_stp_flood.py）。這是 Kali/Debian
# 官方套件庫收錄的套件（非第三方來源），安裝風險低；即使這裡安裝失敗，也只會讓
# 這一個測項的健康檢查判定異常並自動停用，不影響其他測項的安裝/執行
# （見下方「[4/5] 健康檢查」與 app/plugin_healthcheck.py 的設計說明）。
L2_ADV_PKGS=(netsniff-ng)
# weasyprint（PDF 報告）需要的系統層 render 函式庫
PDF_PKGS=(libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info fonts-noto-cjk)

ALL_PKGS=("${CORE_PKGS[@]}" "${HTTP_PKGS[@]}" "${L2_ADV_PKGS[@]}" "${PDF_PKGS[@]}")

for pkg in "${ALL_PKGS[@]}"; do
  if apt-get install -y "$pkg"; then
    echo "    - $pkg 安裝完成"
  else
    echo "    !! $pkg 安裝失敗或找不到套件，略過（不影響其他功能，缺什麼之後再手動裝）"
  fi
done

echo "==> [3/5] 建立 Python 虛擬環境並安裝套件"
if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install --upgrade pip
# 逐一嘗試安裝，理由跟上面 apt 套件迴圈一樣：requirements.txt 裡任何單一套件在
# 特殊環境（少見的 CPU 架構、缺系統動態函式庫等）安裝失敗，不該讓整個安裝流程
# 中斷、連其他 90 個不相依於該套件的測項都裝不起來。先整批嘗試（最常見、最快的
# 路徑），失敗時才退回逐行安裝找出真正有問題的套件並繼續安裝其餘套件。
if ! pip install -r requirements.txt; then
  echo "    !! 整批安裝 requirements.txt 時發生錯誤，改為逐一安裝以避免單一套件卡住整個流程"
  while IFS= read -r line; do
    line="$(echo "$line" | sed 's/#.*$//' | xargs)"
    [[ -z "$line" ]] && continue
    if pip install "$line"; then
      echo "    - $line 安裝完成"
    else
      echo "    !! $line 安裝失敗，略過（對應測項的健康檢查會偵測到並自動停用，不影響其他測項）"
    fi
  done < requirements.txt
fi

echo "==> [4/5] 建立資料目錄"
mkdir -p data/projects

# 讓 tshark/dumpcap 在非 root 情境下也能抓封包（平台預設用 root 跑就不需要，但保留這段以防萬一）
if command -v dumpcap >/dev/null 2>&1; then
  setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)" || true
fi

echo "==> [5/5] 測項健康檢查（確認每個測項所需的套件/執行檔是否齊全，異常者將自動停用）"
# 安裝完成後自動對全部測項跑一次依賴健康檢查並寫入資料庫，
# 讓使用者一開啟網頁「測項管理」頁就能看到目前哪些測項可用。健康檢查本身只探測
# 依賴是否存在（import 套件／查 PATH 執行檔），不會對任何目標發送測試流量，
# 詳見 app/plugin_healthcheck.py 開頭說明。這一步失敗不會中止安裝（健康檢查是
# 錦上添花的輔助資訊，不是安裝是否成功的必要條件），僅提示使用者之後可自行手動執行。
if ! python3 scripts/run_healthcheck.py; then
  echo "    !! 自動健康檢查未能完成（不影響安裝結果），可稍後手動執行："
  echo "         .venv/bin/python3 scripts/run_healthcheck.py"
fi

echo ""
echo "=================================================="
echo " 安裝完成！接下來執行： sudo ./run.sh"
echo " 服務預設只 bind 127.0.0.1:8000，在 Kali VM 本機瀏覽器打開："
echo "     http://127.0.0.1:8000"
echo " 開啟後建議先到「測項管理」頁確認上方健康檢查結果，任何被標記異常/停用的"
echo " 測項都可以看到詳細原因與建議的修復方式。"
echo "=================================================="
