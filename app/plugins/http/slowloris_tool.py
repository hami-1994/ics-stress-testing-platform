"""
測項：Slowloris 慢速連線資源耗盡測試（gkbrk/slowloris 原生工具）
分類：HTTP/Web（預設埠 80）

與同分類下既有的 http/slow_header.py 的差異（重要，避免混淆）：
    slow_header.py 使用的是 `slowhttptest` 這一套獨立工具（可切換 Slow Headers /
    Slow Body / Range 等多種模式），本測項則是直接包裝業界知名度最高、最常被提及
    的 Slowloris *原生實作* —— gkbrk/slowloris（PyPI 套件名稱同樣是 `slowloris`，
    專案首頁 https://github.com/gkbrk/slowloris）。兩者背後利用的攻擊技術類似
    （開大量連線、緩慢送出不完整的 HTTP header，讓伺服器的執行緒/連線池被占滿而
    無法服務正常請求），但實作、參數與底層行為細節不同，稽核報告若要精準指出
    「使用了 gkbrk/slowloris 這套工具」，必須用這個測項而非 slow_header.py。

需求套件：pip install slowloris（純 Python 標準函式庫實作，無其他相依套件；
    另外套件本身支援 `-x/--useproxy` SOCKS5 代理參數，本平台不使用/不開放此參數，
    一律直接對已授權目標發出連線，不透過任何代理跳板）。

安裝於本開發環境驗證：`pip install slowloris` 成功安裝 slowloris 0.2.6，並在
    PATH 中提供 `slowloris` 執行檔，`slowloris --help` 實際輸出確認下列參數存在
    （為避免臆測，僅使用下列已核實存在的參數，未使用任何未驗證旗標）：
        slowloris [-h] [-p PORT] [-s SOCKETS] [-v] [-ua] [-x]
                  [--proxy-host PROXY_HOST] [--proxy-port PROXY_PORT] [--https]
                  [--sleeptime SLEEPTIME]
                  [host]

工具行為上的重要限制：gkbrk/slowloris 這套工具本身**沒有**任何
    「跑多久之後自動結束」的旗標——它只會不斷迴圈保持/更新連線直到被中斷。因此
    本測項完全依賴本平台 `run_subprocess()` 既有的「已達 duration 秒即送
    SIGTERM→SIGKILL 給整個 process group」機制來強制收尾，這點與其他大多數
    subprocess 類測項（自己有 -l/--time 之類的參數可以指定秒數）不同，特別在此
    註明，避免日後有人誤以為漏放了時長參數。

安全設計：
    1. duration 一律經過 clamp_duration() 限制在 1~1800 秒。
    2. sockets（併發連線數）與 sleeptime（keep-alive 間隔）皆為可調且有上限的
       參數，不提供「無限併發」選項；預設值取自工具作者建議的常見數值。
    3. 透過 run_subprocess() 啟動，可被 stop_event 中斷、逾時自動終止、
       stdout 即時回拋給前端 log。
    4. 不做任何 IP/MAC 偽造，不繞過代理（本測項不開放 -x/--useproxy 參數），
       純粹對已完成授權確認的 target:port 發出連線。
"""
from ..common import clamp_duration, run_subprocess

NAME = "Slowloris 慢速連線資源耗盡（gkbrk/slowloris 原生工具）"
CATEGORY = "HTTP/Web"
PROTOCOL = "HTTP"
DEFAULT_PORT = 80
TEST_TYPE = "resource"  # 占用伺服器端連線槽/執行緒資源，非以流量/頻寬取勝


def get_param_schema() -> dict:
    return {
        "sockets": {
            "type": "int", "default": 100000, "min": 1, "max": 100000,
            "desc": "同時開啟並維持的慢速連線數（對應 slowloris -s/--sockets）",
        },
        "sleeptime": {
            "type": "int", "default": 15, "min": 1, "max": 60,
            "desc": "每次補送 keep-alive 標頭片段的間隔秒數（對應 --sleeptime；"
                    "數值越小越積極維持連線但對攻擊端本身的負擔也越高）",
        },
        "https": {
            "type": "bool", "default": False,
            "desc": "目標埠是否為 HTTPS（對應 --https；勾選時建議將埠改為 443 或目標實際的 HTTPS 埠）",
        },
        "randomize_user_agent": {
            "type": "bool", "default": True,
            "desc": "每次請求隨機化 User-Agent（對應 -ua/--randuseragents，降低被單一特徵規則辨識/擋下的機率）",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    sockets = int(params.get("sockets", 150))
    sockets = max(1, min(sockets, 1000))
    sleeptime = int(params.get("sleeptime", 15))
    sleeptime = max(1, min(sleeptime, 60))
    use_https = bool(params.get("https", False))
    randomize_ua = bool(params.get("randomize_user_agent", True))
    tcp_port = int(port) if port else DEFAULT_PORT

    cmd = [
        "slowloris", target,
        "-p", str(tcp_port),
        "-s", str(sockets),
        "--sleeptime", str(sleeptime),
    ]
    if use_https:
        cmd.append("--https")
    if randomize_ua:
        cmd.append("-ua")

    log_fn(
        f"[+] 啟動 gkbrk/slowloris：{sockets} 條併發慢速連線，keep-alive 間隔 {sleeptime} 秒 "
        f"-> {target}:{tcp_port}（工具本身無內建時長限制，將於 {duration} 秒後由平台強制終止）"
    )
    result = run_subprocess(cmd, duration, stop_event, log_fn)
    result["sockets"] = sockets
    result["sleeptime"] = sleeptime
    return result
