#!/usr/bin/env python3
"""
scripts/run_healthcheck.py

用途：安裝完成後（install.sh 最後一步會自動呼叫本腳本）對全部測項跑一次
「依賴健康檢查」（見 app/plugin_healthcheck.py 的完整說明），並把結果寫進資料庫
（TestItemConfig 表），讓「測項管理」頁一開啟就看得到目前哪些測項可用、哪些
因為缺少 Python 套件/CLI 執行檔而被偵測為異常並預設停用。

也可以在安裝完成後隨時手動重跑（例如之後又補裝了某個原本缺少的依賴）：
    .venv/bin/python3 scripts/run_healthcheck.py
或直接在網頁「測項管理」頁點「重新檢查全部測項」按鈕（呼叫同一套邏輯，
見 app/routers/test_items.py 的 POST /api/test-items/healthcheck/run）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db import SessionLocal, init_db  # noqa: E402
from app import plugin_healthcheck  # noqa: E402


def main() -> int:
    init_db()
    db = SessionLocal()
    try:
        result = plugin_healthcheck.run_all_healthchecks(db)
    finally:
        db.close()

    print("")
    print("==================== 測項健康檢查結果 ====================")
    print(f" 共 {result['total']} 個測項，{result['ok']} 個通過，{result['failed']} 個偵測到異常")
    if result["failed_items"]:
        print(" 以下測項因偵測到異常，已預設停用（不影響其他測項安裝/執行）：")
        for item in result["failed_items"]:
            print(f"   - {item['module']}")
            print(f"     {item['detail']}")
        print("")
        print(" 可於啟動平台後，在網頁「測項管理」頁查看詳細原因、視需要補裝缺少的")
        print(" 套件/執行檔後點「重新檢查」，或重新執行本腳本：")
        print("     .venv/bin/python3 scripts/run_healthcheck.py")
    else:
        print(" 全部測項皆通過健康檢查，可直接使用。")
    print("============================================================")
    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
