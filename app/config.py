"""
app/config.py — 平台設定

對應設計文件第 3 節：單一操作者、預設只 bind localhost。
所有可調參數集中在這裡，之後要改成讀環境變數/設定檔也只需要動這個檔案。
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("STRESS_TOOL_DATA_DIR", BASE_DIR / "data"))
PROJECTS_DIR = DATA_DIR / "projects"
DB_PATH = DATA_DIR / "db.sqlite3"

# 設計文件第 3 節：預設只 bind localhost，避免不小心把壓力測試工具曝露到網路上。
# 如果真的需要從別台機器連，請用 SSH port forward 或 VPN，而不是改這裡對外開放。
HOST = os.environ.get("STRESS_TOOL_HOST", "127.0.0.1")
PORT = int(os.environ.get("STRESS_TOOL_PORT", "8000"))

# 設計文件第 5.5 節：測試時長硬上限 30 分鐘，這裡是後端驗證層真正擋住的地方
# （前端只是方便輸入，不能只靠前端限制）。
MAX_DURATION_SEC = 1800
DEFAULT_DURATION_SEC = 300

DATA_DIR.mkdir(parents=True, exist_ok=True)
PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
