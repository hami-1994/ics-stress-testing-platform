"""
app/plugin_healthcheck.py — 測項健康檢查（對應設計文件第 20 節）

目的：安裝好之後要先有機制確認目前所有測項是不是可以執行，測項若
偵測到異常，使用者可以在測項管理畫面知道，並預設不使用。這裡回答的問題是
「這個測項的執行環境依賴（Python 套件／CLI 執行檔）目前是否齊全」，**不是**
「對某個目標打下去會不會成功」——後者永遠要等操作者選定已授權目標才有意義，
在安裝完成、尚未有任何目標的階段去對外送測試流量本身就違反平台安全規則第 4 點
（不可對未授權對象送出流量）。因此這裡採用的是「依賴探測」而非「即時開火測試」：

    1. 該測項模組本身能否被匯入（import）、get_param_schema() 能否正常執行。
    2. 該測項原始碼中實際會用到的第三方 Python 套件（例如 scapy／pymodbus／
       asyncua／pycomm3／python-snap7...）能否被匯入。
    3. 該測項若透過 run_subprocess() 呼叫外部 CLI 工具（例如 hping3／wrk／
       slowhttptest／slowloris／mausezahn...），該執行檔是否存在於 PATH 上。

第 2、3 點所需的「這個測項到底依賴哪些套件/執行檔」**不是**由每個 plugin 手動
額外宣告一份 metadata（91 個既有測項都要回頭手動填寫、容易漏填/寫錯、日後新增
測項也容易忘記更新，維護成本高且容易與程式碼本身脫節）——而是直接靜態掃描
plugin 原始碼裡實際出現的 `import X` / `from X import` 陳述式，以及
`cmd = [...]` 陣列的第一個字串字面值（各測項慣例的 CLI 指令第一個元素就是
執行檔名稱，可見 http/http_get_flood.py 的 `cmd = ["wrk", ...]`、
netlayer/bpdu_stp_flood.py 的 `cmd = ["mausezahn", iface, ...]` 等）。這樣
「依賴宣告」永遠跟原始碼本身同步，不會因為忘記維護一份額外清單而失準；代價是
對於用變數/f-string 組出執行檔名稱的寫法（目前程式碼中沒有這種寫法）會抓不到，
這點在下面 _extract_dependencies() 的docstring 一併誠實註明。
"""
from __future__ import annotations

import importlib
import re
import sys
from datetime import datetime
from pathlib import Path

from . import models, registry

# import 名稱 -> 建議 pip 安裝名稱（僅用於顯示給使用者看的提示訊息，import 探測
# 本身一律用「import 名稱」而非 pip 名稱，兩者常常不同，例如 python-snap7 這個
# pip 套件實際 import 進來的名字是 `snap7`）。對照不到的就直接顯示 import 名稱本身。
_IMPORT_TO_PIP_HINT = {
    "snap7": "python-snap7",
    "dns": "dnspython",
    "paho": "paho-mqtt",
    "yaml": "PyYAML",
    "OpenSSL": "pyOpenSSL",
}

# 這些 import 名稱雖然「不是」Python 標準函式庫，但屬於本專案自己的套件命名空間
# 或明顯的誤判來源，不應被當成「第三方依賴」納入健康檢查。
_IGNORE_IMPORT_NAMES = {"app"}

# CLI 執行檔名稱在原始碼裡有時只是傳給 shlex.quote 顯示用、不代表真的呼叫該執行檔，
# 這裡先用最單純的規則（cmd = [ 陣列第一個字串）即可涵蓋目前所有 subprocess 類測項。
_CMD_BIN_RE = re.compile(r"cmd\s*=\s*\[\s*f?\"([^\"]+)\"|cmd\s*=\s*\[\s*f?'([^']+)'")
_IMPORT_RE = re.compile(r"^\s*(?:import|from)\s+([a-zA-Z_][\w]*)", re.MULTILINE)

try:
    _STDLIB_NAMES = set(sys.stdlib_module_names)  # Python 3.10+
except AttributeError:  # pragma: no cover - 舊版 Python 相容
    _STDLIB_NAMES = {
        "os", "sys", "time", "threading", "queue", "socket", "subprocess", "signal",
        "shlex", "re", "json", "datetime", "pathlib", "typing", "functools", "random",
        "struct", "math", "itertools", "collections", "logging",
    }


def _extract_dependencies(source: str) -> tuple[set[str], set[str]]:
    """從 plugin 原始碼文字靜態掃描出 (第三方 Python 套件名稱集合, CLI 執行檔名稱集合)。
    刻意不做真正的 AST 執行/動態 import 分析，單純文字比對即可涵蓋本專案目前
    「try/except ImportError 包住 import」與「cmd = [...] 陣列」這兩種一致的既有寫法。
    """
    py_mods: set[str] = set()
    for m in _IMPORT_RE.finditer(source):
        name = m.group(1)
        if name in _STDLIB_NAMES or name in _IGNORE_IMPORT_NAMES:
            continue
        py_mods.add(name)

    bins: set[str] = set()
    for m in _CMD_BIN_RE.finditer(source):
        b = m.group(1) or m.group(2)
        if b:
            bins.add(b)
    return py_mods, bins


def _check_one(module_path: str) -> dict:
    """回傳 {"ok": bool, "detail": str, "py_modules": [...], "binaries": [...]}"""
    import shutil

    problems: list[str] = []
    py_mods: set[str] = set()
    bins: set[str] = set()

    # 1) 模組本身能不能匯入、get_param_schema() 能不能正常跑
    try:
        mod = importlib.import_module(module_path)
    except Exception as e:  # noqa: BLE001
        return {
            "ok": False, "detail": f"測項模組匯入失敗：{e}",
            "py_modules": [], "binaries": [],
        }
    try:
        mod.get_param_schema()
    except Exception as e:  # noqa: BLE001
        problems.append(f"get_param_schema() 執行失敗：{e}")

    # 2) 靜態掃描該模組原始碼，找出實際用到的第三方套件/CLI 執行檔
    try:
        src_path = Path(mod.__file__)
        source = src_path.read_text(encoding="utf-8")
        py_mods, bins = _extract_dependencies(source)
    except Exception as e:  # noqa: BLE001
        problems.append(f"原始碼掃描失敗（不影響測項本身，僅無法驗證依賴）：{e}")

    # 3) 逐一驗證第三方 Python 套件是否可匯入（真的 import，而非只查 find_spec，
    #    因為像 python-snap7 這類套件可能「find_spec 找得到檔案」但實際載入時因
    #    系統缺少對應的動態函式庫（libsnap7 等）而在 import 階段就丟例外，
    #    唯有真的 import 一次才能可靠地探測出這種情況）。
    for pkg in sorted(py_mods):
        try:
            importlib.import_module(pkg)
        except Exception as e:  # noqa: BLE001
            hint = _IMPORT_TO_PIP_HINT.get(pkg, pkg)
            problems.append(f"缺少 Python 套件 {pkg}（建議：pip install {hint}）：{e.__class__.__name__}: {e}")

    # 4) 逐一驗證 CLI 執行檔是否存在於 PATH
    for b in sorted(bins):
        if shutil.which(b) is None:
            problems.append(f"找不到執行檔 {b}（請確認已透過 install.sh 安裝對應套件並存在於 PATH）")

    ok = not problems
    return {
        "ok": ok,
        "detail": "；".join(problems) if problems else "",
        "py_modules": sorted(py_mods),
        "binaries": sorted(bins),
    }


def run_all_healthchecks(db) -> dict:
    """對 registry.TEST_ITEMS 全部跑一次健康檢查，寫回/建立 TestItemConfig。

    行為（對應使用者需求「安裝好應該要先有機制確認...如果偵測到異常...預設不使用」）：
      - 全新測項（DB 裡還沒有對應 TestItemConfig 紀錄）：健康檢查沒過 -> 新建紀錄時
        enabled 直接設為 False（預設不使用）；健康檢查通過 -> enabled=True。
      - 已存在的測項（使用者可能已手動調整過 enabled）：只更新 health_status/
        health_detail/checked_at，**不**自動覆寫使用者已手動設定過的 enabled 值，
        避免使用者明知風險、手動重新啟用某測項後，下次重跑健康檢查又被靜默改回停用。
        使用者若想依最新健康檢查結果重新決定是否啟用，請在測項管理頁自行切換。
    """
    now = datetime.utcnow()
    results = []
    for entry in registry.TEST_ITEMS:
        module_path = entry["module"]
        check = _check_one(module_path)
        cfg = db.query(models.TestItemConfig).filter_by(module=module_path).one_or_none()
        is_new = cfg is None
        if cfg is None:
            cfg = models.TestItemConfig(module=module_path)
            db.add(cfg)
        cfg.health_status = "ok" if check["ok"] else "error"
        cfg.health_detail = check["detail"]
        cfg.checked_at = now
        if is_new:
            cfg.enabled = check["ok"]
        results.append({
            "module": module_path,
            "ok": check["ok"],
            "detail": check["detail"],
            "enabled": cfg.enabled,
            "is_new": is_new,
        })
    db.commit()

    ok_count = sum(1 for r in results if r["ok"])
    failed = [r for r in results if not r["ok"]]
    return {
        "total": len(results),
        "ok": ok_count,
        "failed": len(failed),
        "failed_items": failed,
        "checked_at": now.isoformat(),
    }
