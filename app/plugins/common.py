"""
plugins/common.py
壓力測試平台 - 測項 Plugin 共用工具

所有 plugin 模組必須遵守下列合約（對應設計文件 5.5 節）：

    NAME = "顯示名稱"
    CATEGORY = "所屬通訊協定分類（一般 / HTTP/Web / Modbus TCP / ...）"
    PROTOCOL = "TCP / UDP / HTTP / L2"
    DEFAULT_PORT = 502   # 可選，UI 建立測項時的預設埠

    def get_param_schema() -> dict: ...
    def run(target: str, port: int, protocol: str, duration: int,
            params: dict, stop_event: threading.Event,
            log_fn: Callable[[str], None]) -> dict: ...

安全限制（由框架層強制，plugin 開發者也應主動遵守，不可繞過）：
  1. duration 一律經過 clamp_duration() 限制在 1~1800 秒（30 分鐘）之間，
     這是設計文件 5.5 節「測試時長不超過 30 分鐘」的落地。
  2. 所有子行程（CLI 工具）一律透過 run_subprocess() 啟動，確保：
       - 可被 stop_event 中斷（對應 5.6 節「停止」）
       - 逾時會自動 terminate/kill（避免卡死佇列）
       - stdout/stderr 即時透過 log_fn 回拋給 WebSocket（對應 log_line 事件）
  3. 所有「flood 類」測項一律要有 rate/併發數等速率參數，且預設值為「可控速率」，
     不提供「無限全速、無上限」的模式（原始命令中的 --flood、--rand-source、
     while true、asyncio.sleep(3600) 等寫法在本平台一律不採用，理由見各 plugin 內註解）。
  4. 這裡的 target/port 一律是由 Orchestrator 從「已完成授權確認的 Target + 使用者勾選的 Port」
     傳入，plugin 本身不做授權檢查（授權檢查在建立 Target 時已完成，見設計文件 5.1、8 節）。
"""
from __future__ import annotations

import os
import queue
import shlex
import signal
import socket
import subprocess
import threading
import time
from typing import Callable, List

MAX_DURATION_SEC = 1800  # 平台硬上限：30 分鐘，與設計文件 5.5 一致
LogFn = Callable[[str], None]


def clamp_duration(duration: int) -> int:
    """任何 plugin 收到的 duration 都要先過這一關，就算前端/API 傳錯也不會被繞過。"""
    try:
        d = int(duration)
    except (TypeError, ValueError):
        d = 300
    return max(1, min(d, MAX_DURATION_SEC))


_LOG_MIN_INTERVAL_SEC = 0.2   # 高 pps 工具（nping/hping3）逐行輸出可能每秒數千行，節流彙整輸出
_LOG_MAX_LINES_PER_FLUSH = 20  # 每次彙整最多顯示幾行，超過的視為省略（不影響實際攻擊流量/統計）
_SIGTERM_GRACE_SEC = 2.5       # 先禮貌 SIGTERM 等待秒數，時間到還沒死就直接 SIGKILL 整個 process group
_SIGKILL_WAIT_SEC = 2.0


def run_subprocess(cmd: List[str], duration: int, stop_event, log_fn: LogFn) -> dict:
    """啟動外部 CLI 工具（hping3/nping/wrk/slowhttptest...），逐行把輸出轉給 log_fn，
    並在下列任一情況發生時優雅終止：
      - 子行程自然結束
      - 已達 duration 秒
      - stop_event 被 Orchestrator 觸發（使用者按了停止/跳過/緊急停止）
    先送 SIGTERM，等待 grace period 未結束再 SIGKILL；訊號送給整個 process group
    （子行程用 start_new_session=True 啟動），避免 nping/hping3 等工具在某些版本下
    衍生出獨立於主行程之外、不會隨 SIGTERM 一起結束的殘留行程。

    實作重點：
      1. 這裡不用 proc.stdout.readline() 直接堵在控制迴圈裡——如果子行程把 stdout
         全緩衝，readline() 可能卡住很久才回來，導致 stop_event/duration 檢查被延遲
         觸發。改成：另開一個 reader thread 專門 blocking 讀 stdout，丟進
         queue.Queue；主控制迴圈用 queue.get(timeout=0.3) 短輪詢，跟子行程輸出的
         時機完全脫鉤。
      2. 高 pps 的 flood 工具（例如 nping/hping3 每秒送出成千上萬個封包，預設會逐包
         印一行 SENT/RCVD）如果「每一行」都立刻寫檔(含 flush)+透過 WebSocket 廣播，
         這個 I/O 開銷本身會拖慢控制迴圈的節奏、也會讓攻擊端主機/瀏覽器端疲於奔命
         處理巨量訊息，導致「跳過/停止功能要跑很久才生效」。改成把輸出彙整成緩衝區，
         最多每 0.2 秒才實際呼叫一次 log_fn（超量的行數只顯示最後 N 行，其餘計數後
         在結尾用一行提示「已省略 X 行」），且這個節流只影響「畫面看到的 log」，
         完全不影響背景實際送出的攻擊封包速率/數量。
    """
    duration = clamp_duration(duration)
    log_fn(f"[cmd] {' '.join(shlex.quote(c) for c in cmd)}")
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
            start_new_session=True,  # 獨立 process group，收尾時可以連同它衍生的子行程一起處理掉
        )
    except FileNotFoundError as e:
        log_fn(f"[!] 找不到執行檔：{e}")
        return {"elapsed_sec": 0, "returncode": None, "error": str(e)}

    line_queue: "queue.Queue[str | None]" = queue.Queue()

    def _reader():
        try:
            if proc.stdout:
                for line in proc.stdout:
                    line_queue.put(line)
        except Exception:  # noqa: BLE001  reader thread 本身出錯不該讓控制迴圈卡住
            pass
        finally:
            line_queue.put(None)  # sentinel：告知控制迴圈 stdout 已關閉/子行程結束輸出

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    start = time.time()
    stdout_closed = False
    line_count = 0
    dropped_count = 0
    pending_lines: List[str] = []
    last_log_ts = 0.0

    def _flush_pending(force: bool = False):
        nonlocal pending_lines, last_log_ts, dropped_count
        if not pending_lines:
            return
        now = time.time()
        if not force and (now - last_log_ts) < _LOG_MIN_INTERVAL_SEC:
            return
        if len(pending_lines) > _LOG_MAX_LINES_PER_FLUSH:
            dropped_count += len(pending_lines) - _LOG_MAX_LINES_PER_FLUSH
            shown = pending_lines[-_LOG_MAX_LINES_PER_FLUSH:]
        else:
            shown = pending_lines
        log_fn("\n".join(shown))
        pending_lines = []
        last_log_ts = now

    while True:
        try:
            line = line_queue.get(timeout=0.3)
            if line is None:
                stdout_closed = True
            elif line:
                line_count += 1
                pending_lines.append(line.rstrip())
        except queue.Empty:
            pass

        _flush_pending(force=stdout_closed or line_queue.empty())

        if proc.poll() is not None and (stdout_closed or line_queue.empty()):
            break
        if stop_event is not None and stop_event.is_set():
            log_fn("[!] stop_event 觸發，終止子行程")
            break
        if time.time() - start >= duration:
            log_fn("[!] 已達測試時長，終止子行程")
            break

    _flush_pending(force=True)

    if proc.poll() is None:
        _terminate_process_group(proc)

    if dropped_count:
        log_fn(f"[i] 輸出量過大，已省略 {dropped_count} 行（僅節流畫面顯示，不影響實際攻擊流量與統計）")

    reader_thread.join(timeout=2)

    elapsed = time.time() - start
    return {"elapsed_sec": round(elapsed, 1), "returncode": proc.poll(), "output_lines": line_count}


def _terminate_process_group(proc: subprocess.Popen) -> None:
    """先對整個 process group 送 SIGTERM，grace period 內沒結束就直接 SIGKILL。
    用 process group（而非只對單一 pid）是因為部分 CLI 工具在某些版本/參數組合下
    會衍生出獨立的子行程，只 terminate 主行程不保證全部跟著結束。"""
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001
            pass
    try:
        proc.wait(timeout=_SIGTERM_GRACE_SEC)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
    try:
        proc.wait(timeout=_SIGKILL_WAIT_SEC)
    except subprocess.TimeoutExpired:
        pass


class RateLimiter:
    """固定速率限制器，給原生 Python 迴圈型測項（scapy/socket）使用，
    避免『無限全速』發送——所有 flood 類測項都必須經過這裡控速。"""

    def __init__(self, rate_per_sec: float):
        self.interval = 1.0 / rate_per_sec if rate_per_sec and rate_per_sec > 0 else 0.0
        self._next = time.time()

    def wait(self):
        if self.interval <= 0:
            return
        now = time.time()
        if self._next > now:
            time.sleep(self._next - now)
        self._next = max(self._next, now) + self.interval


def tcp_precheck(target: str, port: int, timeout: float = 2.0) -> bool:
    """測試開始前的健康檢查：先確認目標埠可連線，連不上就不必浪費整個 duration。"""
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except OSError:
        return False


# ============================================================================
# 「高並發加速版」引擎（設計文件擴充，見 registry.py
# ENGINE_MODE_* 與 orchestrator.py 呼叫處），可在測項管理頁針對個別測項切換偏好。
#
# 背景：盤點後發現，本專案 95 個測項裡，屬於「流量型」(TEST_TYPE == "traffic") 且採用
# 單一 Python 迴圈（RateLimiter + scapy sendp()／socket.sendto() 等）驅動的測項，
# 其「schema 宣告的可調速率上限」與「單一執行緒實際能真正送達的速率」之間存在落差——
# 這是 CPython 的已知限制：單一執行緒受 GIL 序列化 + 逐包物件建構/系統呼叫開銷影響，
# 即使 RateLimiter 設定要求每秒送出數十萬個封包，單一迴圈實際能達到的送出速率通常
# 遠低於此（尤其 scapy 的 sendp() 每次呼叫都有不小的物件建構開銷）。
#
# 這裡新增的「高並發加速版」引擎，做法是把同一個測項的 run() 函式同時開 N 條
# **執行緒**（刻意選擇 threading 而非 multiprocessing——後者需要 log_fn/stop_event
# 等閉包物件可被 pickle 跨行程傳遞，本專案這兩者都綁定在 Orchestrator 內部狀態/
# WebSocket 廣播機制上，不是簡單可 pickle 的物件，貿然改用多行程風險遠高於效益；
# 而 Python 的 GIL 在進行 socket 系統呼叫〔sendto／send／connect 等〕期間會被釋放，
# 多執行緒對這類「大部分時間在等待作業系統完成呼叫」而非「花在 Python 運算」的
# I/O-bound 迴圈，仍然能有意義地提升實際吞吐量），平行執行同一個 run()。
#
# **重要安全設計（刻意維持，不可繞過）**：每條執行緒各自負責「原始設定速率 ÷ N」，
# 加總後的目標速率等於使用者原始設定值，**不會**變成 N 倍——因為所有速率型欄位
# 的 min/max 上限都已經過安全把關，高並發引擎的目的是「更接近打滿已核准的
# 上限」，而不是「繞過上限、把總負載再往上乘」。這個不變量（invariant）是本引擎
# 設計上最核心的安全前提，日後如果要修改這段邏輯，務必維持「加總目標速率 = 原始
# 設定值」這個性質。
# ============================================================================

CONCURRENT_ENGINE_WORKERS = 10  # 高並發加速版引擎預設同時開幾條執行緒（可由測項管理頁 per-測項調整）

# 與各測項壓力參數上限調整沿用同一組欄位
# 白名單：這些是各測項 schema 裡「代表速率/併發量」的欄位名稱。高並發引擎只會把
# 這些欄位的值切分給多條執行緒，其餘欄位（iface/dst_mac/path 等）每條執行緒維持
# 相同原始值，讓多條執行緒各自對相同目標做相同動作、只是分攤總速率。
RATE_FIELD_WHITELIST = frozenset({
    "rate_pps", "rate_per_sec", "connect_rate", "connect_rate_per_sec",
    "concurrent_connections", "concurrent_sessions", "concurrent_channels",
    "concurrent_clients", "concurrent_workers", "threads", "connections",
    "sockets", "packet_count", "pipeline_depth",
})


def run_concurrent_workers(
    run_fn, target: str, port, protocol: str, duration: int, params: dict,
    stop_event, log_fn: LogFn, workers: int = CONCURRENT_ENGINE_WORKERS,
    param_schema: dict | None = None,
) -> dict:
    """通用「高並發加速版」引擎 wrapper——不修改任何既有測項 plugin 的程式碼，單純
    在 Orchestrator 呼叫 `mod.run(...)` 的地方，改成呼叫這裡把同一個 `run_fn`
    （就是該測項模組的 `run`）平行開 `workers` 條執行緒各跑一份，並把回傳的統計
    數字加總。適用於任何符合本專案 plugin 合約（見本檔案最上方 docstring）的
    `run_fn`，不限定特定協定/測項，這也是為什麼可以「全部測項一次到位」——不需要
    為每個測項另外寫一份「加速版」程式碼，這個 wrapper 本身就是通用的加速機制。

    安全設計：見上方模組層級註解。簡言之，速率型欄位（RATE_FIELD_WHITELIST）的
    「加總後總值」永遠等於呼叫端傳入的原始 `params` 值（或該欄位的 schema 預設值），
    不會因為切成多條執行緒就把總負載乘 N 倍。

    若 `params`／`param_schema` 裡完全找不到任何白名單欄位（理論上不會發生於既有
    的「流量型」單迴圈測項，但保留這個防呆是為了避免日後新增的測項不小心踩到這個
    假設時，意外把總負載乘成 N 倍）：這種情況下直接退化為單一執行緒呼叫（等同
    `workers=1`），並在 log 註明原因，不強行套用平行化。

    回傳值：把每條執行緒 `run_fn(...)` 的回傳字典逐一加總——數值欄位（int/float，
    排除鍵名為 `elapsed_sec` 的欄位）加總，`elapsed_sec` 取最大值（代表整體測項
    實際耗時），其餘型別欄位取第一個非空值，並額外附加 `engine_mode`／
    `engine_workers` 兩個欄位方便報告/log 呈現使用的是哪種引擎。
    """
    workers = max(1, int(workers or 1))
    params = dict(params or {})
    schema = param_schema or {}

    rate_fields_present = [k for k in schema if k in RATE_FIELD_WHITELIST] or \
                           [k for k in params if k in RATE_FIELD_WHITELIST]

    if workers == 1 or not rate_fields_present:
        if workers > 1 and not rate_fields_present:
            log_fn(f"[i] 高並發加速版引擎：此測項的參數中找不到可切分的速率型欄位，"
                   f"為避免總負載意外變成 {workers} 倍，改用單一執行緒執行（等同標準版）")
        return run_fn(target, port, protocol, duration, params, stop_event, log_fn)

    sub_params_list = []
    for i in range(workers):
        sub = dict(params)
        for key in rate_fields_present:
            base = sub.get(key)
            if base is None:
                base = (schema.get(key) or {}).get("default")
            if not isinstance(base, (int, float)) or isinstance(base, bool):
                continue
            is_int = isinstance(base, int)
            share = (base // workers) if is_int else (base / workers)
            remainder = (base - share * workers) if is_int else 0
            value = share + (1 if is_int and i < remainder else 0)
            if value <= 0 and base > 0:
                value = 1  # 切分後不足 1 的執行緒仍保留最低限度動作，不會完全不送
            sub[key] = value
        sub_params_list.append(sub)

    log_fn(f"[+] 高並發加速版引擎啟動：{workers} 條執行緒平行執行，"
           f"速率型參數（{', '.join(rate_fields_present)}）已平均切分，加總仍等於原始設定值")

    results: list[dict | None] = [None] * workers

    def _worker(i: int, sub_params: dict):
        def _sub_log(line: str, _i=i):
            log_fn(f"[並發#{_i + 1}/{workers}] {line}")
        try:
            results[i] = run_fn(target, port, protocol, duration, sub_params, stop_event, _sub_log)
        except Exception as e:  # noqa: BLE001  單一執行緒出錯不該讓其餘執行緒/整個測項掛掉
            results[i] = {"error": str(e)}
            log_fn(f"[!] 並發#{i + 1}/{workers} 執行緒發生例外：{e}")

    threads = [threading.Thread(target=_worker, args=(i, sub_params_list[i]), daemon=True) for i in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        # 理論上每條執行緒都會在 duration 秒左右自行收尾（跟單一執行緒版本走同一套
        # duration/stop_event 收尾邏輯），這裡的 timeout 只是防呆上限，避免極端情況
        # 下單一執行緒卡死拖累整個 join 迴圈。
        t.join(timeout=duration + 30)

    aggregated: dict = {}
    for r in results:
        if not isinstance(r, dict):
            continue
        for k, v in r.items():
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                aggregated.setdefault(k, v)
            elif k == "elapsed_sec":
                aggregated[k] = max(aggregated.get(k, 0), v)
            else:
                aggregated[k] = aggregated.get(k, 0) + v

    aggregated["engine_mode"] = "concurrent"
    aggregated["engine_workers"] = workers
    log_fn(f"[+] 高並發加速版引擎完成，{workers} 條執行緒統計已加總")
    return aggregated
