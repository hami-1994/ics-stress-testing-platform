"""
app/capture.py — 封包擷取（設計文件 5.7 節，pcap／摘要雙模式）
用 tshark 執行，交給獨立子行程，測項結束時一併停止。

實作重點：
  - 檔案大小上限使用 `-a filesize:N`（autostop 條件，達到大小上限就停止寫入/結束擷取），
    而不是 `-b filesize:N`（ring buffer 環狀輪替）：tshark/dumpcap 在使用 `-b` 時，並不會
    直接寫入 `-w` 指定的檔名，而是把序號＋時間戳記插入到副檔名前面（例如 `run_4.pcap`
    實際會變成 `run_4_00001_20260815064412.pcap`），導致程式追蹤的檔案路徑對不上、
    誤判為擷取失敗。改用 autostop 條件可確保檔名維持指定的原樣。
  - 停止擷取優先送 SIGINT（Ctrl-C）：這是 tshark 官方文件列出的互動環境下「停止擷取」
    最標準的做法，會觸發它自己的收尾流程（把緩衝區資料 flush、正確關閉 pcap 檔案、
    寫入正確的封包統計）；未在時限內結束才依序降級為 SIGTERM、SIGKILL（各階段等待
    時間：SIGINT 6 秒 → SIGTERM 4 秒 → SIGKILL），避免在較慢的機器或使用 "any" 這種
    偽介面時，收尾動作還沒跑完就被強制 SIGKILL、遺失緩衝區裡還沒寫出的封包資料
    （SIGKILL 是無法攔截、無法收尾的強制訊號，是最可能讓輸出檔案變成 0 bytes 的原因）。
  - 加上 `-n`（不做網路名稱反解析）：如果環境沒有可用的 DNS（工控/隔離測試網路常見），
    tshark 預設的反解析行為可能拖慢啟動/關閉速度，讓收尾流程更容易被逾時打斷。
  - stderr 導到專屬的 log 檔而非 DEVNULL：`stop()` 如果發現檔案大小是 0，會把 tshark
    自己回報的錯誤內容一併帶出來（例如權限不足、介面不存在、BPF 篩選條件語法錯誤），
    不會只看到一個沒有解釋的「0 B」。
  - 「兩者都要」（both）模式下，pcap 跟 summary 各自獨立啟動一個 tshark 行程、各自有
    自己的 CaptureFile 紀錄，其中一種失敗不會連帶讓另一種也拿不到結果。

已知限制：若擷取結果仍是 0 bytes，可查看跟 pcap 檔案同一個資料夾底下的
`run_{id}_pcap_stderr.log`（或 `run_{id}_summary_stderr.log`），內容是 tshark
自己回報的錯誤訊息，可用於進一步排查（例如「權限不足」代表整個工具需要用 sudo 啟動）。
"""
import shutil
import signal
import subprocess
from pathlib import Path

_PCAP_SIZE_CAP_KB = 500000
_STOP_SIGINT_WAIT_SEC = 6.0   # 先送 SIGINT（tshark 標準的「停止擷取」訊號），等它自己收尾
_STOP_SIGTERM_WAIT_SEC = 4.0  # SIGINT 沒反應才送 SIGTERM，再等一次
_STOP_SIGKILL_WAIT_SEC = 2.0  # 最後手段：SIGKILL（會遺失還沒 flush 的資料，僅在前兩者都沒反應時使用）


def _tshark_available() -> bool:
    return shutil.which("tshark") is not None


def _graceful_stop(proc: subprocess.Popen) -> None:
    """依序嘗試 SIGINT → SIGTERM → SIGKILL，每個階段給予足夠時間讓 tshark 自己完成
    「停止擷取、把緩衝資料寫出、正確關閉檔案」的收尾流程，避免直接 SIGKILL 導致檔案
    內容淨空（這是先前版本 pcap 檔案大小為 0 的可能成因之一）。"""
    for sig, wait_sec in ((signal.SIGINT, _STOP_SIGINT_WAIT_SEC), (signal.SIGTERM, _STOP_SIGTERM_WAIT_SEC)):
        try:
            proc.send_signal(sig)
        except (ProcessLookupError, OSError):
            return
        try:
            proc.wait(timeout=wait_sec)
            return
        except subprocess.TimeoutExpired:
            continue
    try:
        proc.kill()
        proc.wait(timeout=_STOP_SIGKILL_WAIT_SEC)
    except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
        pass


class _SingleCapture:
    """單一 tshark 子行程（pcap 或 summary 其中一種模式）。"""

    def __init__(self, proc, file_path, stderr_path, mode):
        self.proc = proc
        self.file_path = file_path
        self.stderr_path = stderr_path
        self.mode = mode

    def stop(self) -> dict:
        if not self.proc:
            err = ""
            if self.stderr_path and self.stderr_path.exists():
                try:
                    err = self.stderr_path.read_text(errors="ignore").strip()[-800:]
                except OSError:
                    pass
            return {"mode": self.mode, "file": None, "size_bytes": 0,
                    "error": err or "tshark 未啟動（找不到執行檔，或啟動失敗）"}

        if self.proc.poll() is None:
            _graceful_stop(self.proc)

        actual_path = self.file_path
        if actual_path and not actual_path.exists():
            candidates = sorted(actual_path.parent.glob(f"{actual_path.stem}*{actual_path.suffix}"))
            if candidates:
                actual_path = candidates[-1]

        size = actual_path.stat().st_size if actual_path and actual_path.exists() else 0
        result = {"mode": self.mode, "file": str(actual_path) if actual_path else None, "size_bytes": size}

        if size == 0:
            err_text = ""
            if self.stderr_path and self.stderr_path.exists():
                try:
                    err_text = self.stderr_path.read_text(errors="ignore").strip()[-800:]
                except OSError:
                    pass
            result["error"] = err_text or (
                "封包擷取檔案大小為 0，但 tshark 沒有留下明確錯誤訊息，常見原因：權限不足"
                "（建議整個工具改用 sudo 啟動）、指定的網路介面不存在、或 BPF 篩選條件在整個"
                "測試期間都沒有比對到任何封包。"
            )
        return result


class CaptureHandle:
    """對外的封包擷取控制代碼。capture_mode == "both" 時內部會是兩個各自獨立的 tshark
    行程（pcap + summary），其中一個失敗不會連帶讓另一個也拿不到結果。"""

    def __init__(self, captures: list):
        self._captures = captures

    def stop(self) -> list:
        """回傳一個 list，每個元素是 {"mode", "file", "size_bytes", "error"(可選)}——
        "both" 模式會回傳兩筆（pcap + summary），其餘模式回傳一筆，"none" 回傳空 list。"""
        return [c.stop() for c in self._captures]


def _start_one(mode: str, bpf: str, out_dir: Path, run_id: int, iface: str) -> _SingleCapture:
    stderr_path = out_dir / f"run_{run_id}_{mode}_stderr.log"

    if mode == "pcap":
        file_path = out_dir / f"run_{run_id}.pcap"
        cmd = [
            "tshark", "-i", iface, "-n", "-f", bpf, "-w", str(file_path),
            "-a", f"filesize:{_PCAP_SIZE_CAP_KB}",
        ]
    else:  # summary
        file_path = out_dir / f"run_{run_id}_summary.txt"
        cmd = ["tshark", "-i", iface, "-n", "-f", bpf, "-q", "-z", "io,stat,5"]

    if not _tshark_available():
        try:
            stderr_path.write_text("找不到 tshark 執行檔，請確認 install.sh 已安裝 wireshark-common/tshark。\n")
        except OSError:
            pass
        return _SingleCapture(None, None, stderr_path, mode)

    stdout_f = open(file_path, "w") if mode == "summary" else subprocess.DEVNULL
    stderr_f = open(stderr_path, "w")
    try:
        proc = subprocess.Popen(cmd, stdout=stdout_f, stderr=stderr_f)
    except (FileNotFoundError, OSError) as e:
        stderr_f.write(f"啟動 tshark 失敗：{e}\n")
        proc = None
    finally:
        if stdout_f is not subprocess.DEVNULL:
            stdout_f.close()
        stderr_f.close()

    if proc is None:
        return _SingleCapture(None, None, stderr_path, mode)
    return _SingleCapture(proc, file_path, stderr_path, mode)


def start_capture(mode: str, target: str, port, out_dir: Path, run_id: int, iface: str = "any") -> CaptureHandle:
    if mode == "none":
        return CaptureHandle([])
    out_dir.mkdir(parents=True, exist_ok=True)
    bpf = f"host {target}"
    if port:
        bpf += f" and port {port}"

    sub_modes = ["pcap", "summary"] if mode == "both" else [mode]
    captures = [_start_one(m, bpf, out_dir, run_id, iface) for m in sub_modes]
    return CaptureHandle(captures)
