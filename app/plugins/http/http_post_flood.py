"""
測項：HTTP POST 大量負載請求衝擊
分類：HTTP/Web
說明：與既有的 http/http_get_flood.py（純 GET，無 request body，靠併發連線量/
請求速率造成負擔）不同，POST 請求會附帶可調大小的 request body，測試的是伺服器端
「接收並解析請求本文（body parsing/上傳處理）」這條額外的程式碼路徑——許多 Web
應用/API Gateway 對 GET 與 POST 走的是不同的中介層邏輯（例如 body 大小限制檢查、
Content-Type 解析、暫存寫檔等），純 GET flood 測不到這個面向。

實作：改用 Python 標準函式庫 http.client（不透過 wrk，因為 wrk 要送出自訂 POST
body 需要額外撰寫 Lua 腳本管理，維護成本較高；此處用標準函式庫 + RateLimiter 節流
迴圈即可達到等效測試目的，也與本專案其餘「原生 Python 迴圈型」測項的風格一致，見
modbus/fc03_high_freq_read.py、cip/list_identity_flood.py 等），每次迭代都新建立
連線並送出一個 POST 請求（body 為可調大小的固定內容），模擬大量不同來源、各自
上傳一份請求本文的情境，讀取狀態碼後即關閉連線。
需求：無額外套件（純標準函式庫 http.client）。
"""
import http.client
import time

from ..common import RateLimiter, clamp_duration

NAME = "HTTP POST 大量負載請求衝擊"
CATEGORY = "HTTP/Web"
PROTOCOL = "HTTP"
DEFAULT_PORT = 80
TEST_TYPE = "traffic"  # 流量型：高頻率帶 body 的 POST 請求洪水，靠請求速率+本文解析負擔造成壓力


def get_param_schema() -> dict:
    return {
        "rate_per_sec": {"type": "int", "default": 50000, "min": 1, "max": 50000, "desc": "每秒送出 POST 請求數"},
        "path": {"type": "string", "default": "/", "desc": "請求路徑"},
        "body_size_bytes": {"type": "int", "default": 1024, "min": 1, "max": 1048576, "desc": "POST body 大小（bytes，上限 1MB）"},
        "content_type": {"type": "string", "default": "application/x-www-form-urlencoded", "desc": "Content-Type 標頭"},
        "connect_timeout": {"type": "float", "default": 3.0, "min": 0.5, "max": 10.0, "desc": "單一請求連線逾時秒數"},
        "use_https": {"type": "bool", "default": False},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    rate = int(params.get("rate_per_sec", 100))
    path = params.get("path", "/")
    body_size = int(params.get("body_size_bytes", 1024))
    content_type = params.get("content_type", "application/x-www-form-urlencoded")
    timeout = float(params.get("connect_timeout", 3.0))
    use_https = bool(params.get("use_https", False))

    body = b"x" * body_size
    headers = {
        "Content-Type": content_type,
        "Content-Length": str(len(body)),
        "Connection": "close",
    }

    limiter = RateLimiter(rate)
    ok, fail = 0, 0
    start = time.time()

    log_fn(f"[+] HTTP POST 負載風暴 -> {'https' if use_https else 'http'}://{target}:{port}{path} "
           f"@ {rate}/s, body={body_size} bytes, {duration}s")

    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        conn = None
        try:
            if use_https:
                import ssl
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(target, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(target, port, timeout=timeout)
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            resp.read(0)  # 不需要完整讀回內容，僅確認回應已到
            ok += 1
        except Exception:  # noqa: BLE001  連線拒絕/逾時/伺服器錯誤都算失敗，繼續下一輪
            fail += 1
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass

    elapsed = time.time() - start
    log_fn(f"[+] 完成，成功 {ok} 次，失敗 {fail} 次")
    return {"ok": ok, "fail": fail, "elapsed_sec": round(elapsed, 1)}
