"""
app/health.py — 監控取樣的異常判斷（對應使用者需求：監控器用顏色/圖示標示異常狀態，
報告要看得出來「服務中斷/網路中斷/link down」）。

集中在這裡判斷，理由：
  - WebSocket 即時推播（前端要即時上色）跟報告產生（事後統計異常次數）要用同一套邏輯，
    不要各寫一份、標準不一致。
  - Orchestrator 在寫 monitor CSV / 推播 monitor_sample 事件之前，先呼叫這裡的
    evaluate_sample()，把回傳的 level/reason 一起塞進 metrics，後面 CSV 統計、報告
    Summary 都直接讀這個欄位就好。

level 只有三種：
  - "ok"       正常
  - "warn"     偏高/需留意，但還不到「中斷」等級
  - "critical" 明確異常：服務無回應、連線失敗、Ping 逾時丟包、介面 link down 等

部分監控器（iface 的錯誤/丟棄封包數）需要看「這次比上次多了多少」才有意義，
所以這裡用一個以 key（通常是 f"{run_id}:{monitor_type}[:iface]"）為主的小型狀態表
記錄上一筆數值——因為平台是單一佇列依序執行（不會同時跑兩個測項），這個全域狀態表
不會有跨測項互相污染的問題。
"""
from __future__ import annotations

_last_values: dict[str, dict] = {}

OK, WARN, CRITICAL, NA = "ok", "warn", "critical", "na"


def _result(level: str, reason: str = "") -> dict:
    return {"level": level, "reason": reason}


def evaluate_sample(monitor_type: str, metrics: dict, key: str | None = None) -> dict:
    """回傳 {"level": "ok"|"warn"|"critical", "reason": "人類看得懂的中文說明"}。
    key 用來區分「同一種監控器、不同測項/介面」的狀態追蹤，通常由呼叫端組
    f"{test_run_id}:{monitor_type}:{iface 或其他子鍵}"。
    """
    if not isinstance(metrics, dict):
        return _result(OK)

    if monitor_type in ("service", "udp") and metrics.get("error") == "缺少 target/port":
        # 這種監控器需要一個具體的 Port 才能運作，但這次測項本身沒有對應 Port
        # （最常見於 Layer 2 通訊協定測項，例如 EtherCAT/PROFINET DCP/ARP 相關測項）。
        # 這不是「監控失敗」，是「這個監控器本來就不適用於這次測項」，不該顯示成紅色異常
        # 誤導使用者——Orchestrator 在建立監控器時其實已經直接短路掉這種組合、不會真的
        # 呼叫到這裡，這裡留著純粹是防呆（例如未來有新的呼叫路徑忘記做同樣的短路判斷）。
        return _result(NA, "此測項無對應 Port（Layer 2 通訊協定或未選擇 Port），此監控器不適用於本次測試")

    if metrics.get("error") and monitor_type not in ("udp",):
        # udp 監控器的 error 欄位只在 up=False（ICMP unreachable）或連線層錯誤時才有意義，
        # 底下 udp 分支會單獨處理；其他監控器只要 sample() 回錯誤，一律視為 critical。
        return _result(CRITICAL, f"監控器讀取失敗：{metrics.get('error')}")

    if monitor_type == "ping":
        if metrics.get("loss"):
            return _result(CRITICAL, "Ping 逾時/丟包，疑似網路中斷或目標無回應")
        rtt = metrics.get("rtt_ms")
        if rtt is not None and rtt > 800:
            return _result(WARN, f"Ping 延遲異常偏高（{rtt} ms）")
        return _result(OK)

    if monitor_type == "service":
        # 升級版服務監控器回傳三級狀態 status=UP/DEGRADED/DOWN 與 protocol/detail；
        # 向下相容舊版（只有 up=True/False）。
        svc_status = metrics.get("status")  # UP / DEGRADED / DOWN（新版才有）
        protocol = metrics.get("protocol", "tcp")
        detail = metrics.get("detail", "")
        proto_label = f"[{protocol}] " if protocol else ""

        if svc_status == "DOWN" or metrics.get("up") is False:
            reason = f"{proto_label}服務協定探測失敗（{detail}）" if detail else "服務連線失敗，疑似服務中斷或該 Port 已關閉"
            return _result(CRITICAL, reason)
        if svc_status == "DEGRADED":
            reason = f"{proto_label}服務部分功能受損（{detail}）" if detail else "服務部分功能受損"
            return _result(WARN, reason)
        latency = metrics.get("latency_ms")
        if latency is not None and latency > 1500:
            return _result(WARN, f"{proto_label}服務回應延遲異常偏高（{latency} ms）")
        return _result(OK)

    if monitor_type == "udp":
        if metrics.get("up") is False:
            return _result(CRITICAL, "收到 ICMP Port Unreachable 或連線層錯誤，疑似服務中斷")
        latency = metrics.get("latency_ms")
        if latency is not None and latency > 1500:
            return _result(WARN, f"UDP 回應延遲異常偏高（{latency} ms）")
        return _result(OK)  # up is True 或 None（UDP 無回應為常態）都視為 ok

    if monitor_type == "arp":
        if metrics.get("up") is False:
            return _result(CRITICAL, "ARP 無回應，裝置可能已離線／斷網／網路卡故障（link down 等級異常）")
        return _result(OK)  # up is True 或 None（不同網段量不到，屬正常限制）都視為 ok

    if monitor_type == "tcp":
        total = metrics.get("total", 0)
        close_wait = metrics.get("close_wait", 0)
        if total > 0 and close_wait / total > 0.5:
            return _result(WARN, f"CLOSE_WAIT 連線比例偏高（{close_wait}/{total}），應用層可能未正常關閉連線")
        return _result(OK)

    if monitor_type == "self_resource":
        cpu = metrics.get("cpu_percent")
        mem = metrics.get("mem_percent")
        if cpu is not None and cpu > 95:
            return _result(CRITICAL, f"發起測試的主機自身 CPU 使用率過高（{cpu}%），測試結果可能受攻擊端效能瓶頸影響")
        if mem is not None and mem > 95:
            return _result(CRITICAL, f"發起測試的主機自身記憶體使用率過高（{mem}%）")
        if (cpu is not None and cpu > 85) or (mem is not None and mem > 85):
            return _result(WARN, "發起測試的主機自身資源使用率偏高，建議留意攻擊端本身效能")
        return _result(OK)

    if monitor_type == "iface":
        # 這個監控器量的是「發起測試的 Kali 主機自己的網卡」。carrier
        # （實體鏈路載波偵測）是唯一不受「攻擊端自己送出大量流量」影響的乾淨訊號——
        # 如果這張網卡跟受測標的直接對接，對方斷線通常會反映成這裡的 carrier 掉為 0，
        # 所以這個訊號視為 critical（判定用）。至於 bps/pps/errin/errout/dropin/dropout
        # 這些流量計數器，在測試期間本來就會因為攻擊端自己送出大量封包而劇烈波動，
        # 不是乾淨的「標的斷線」訊號，只降為 warn（診斷用參考，不觸發中斷判定），
        # 避免攻擊流量太大時，Kali 自己網卡開始出現誤差/丟包，卻被誤判成「標的連線中斷」。
        carrier = metrics.get("carrier")
        if carrier == 0:
            return _result(CRITICAL, "實體鏈路中斷（Link Down）：Kali 網卡偵測不到鏈路訊號。若這張網卡與"
                                       "受測標的直接對接（直連網路線／同一台交換器的鄰接埠），這通常代表標的"
                                       "的網路介面或實體鏈路已經斷線；若是接在共用交換器/多台裝置的網段，"
                                       "則只能代表該網段目前無載波訊號，請搭配 service/ping 等監控器交叉確認。")

        iface = metrics.get("iface", "")
        state_key = key or f"iface:{iface}"
        prev = _last_values.get(state_key)
        cur = {
            "errin": metrics.get("errin", 0), "errout": metrics.get("errout", 0),
            "dropin": metrics.get("dropin", 0), "dropout": metrics.get("dropout", 0),
        }
        _last_values[state_key] = cur

        bps_sent = metrics.get("bps_sent")
        bps_recv = metrics.get("bps_recv")
        no_traffic = bps_sent == 0 and bps_recv == 0

        if prev is not None:
            derr = (cur["errin"] - prev["errin"]) + (cur["errout"] - prev["errout"])
            ddrop = (cur["dropin"] - prev["dropin"]) + (cur["dropout"] - prev["dropout"])
            if derr > 0:
                return _result(WARN, f"網路介面（Kali 自己的網卡）出現新的收發錯誤（+{derr}），"
                                       f"可能是攻擊流量本身造成，也可能是 link 不穩定，僅供診斷參考")
            if ddrop > 20:
                return _result(WARN, f"網路介面（Kali 自己的網卡）短時間內丟棄大量封包（+{ddrop}），"
                                       f"可能是攻擊流量已接近 Kali 自己網卡的處理上限，僅供診斷參考")
        if no_traffic:
            # 單一取樣沒有流量不一定異常（例如兩次取樣間剛好沒封包），交由呼叫端用連續多筆判斷是否為 link down。
            return _result(WARN, "此取樣區間內介面完全沒有收發流量，若持續出現請留意是否 link down")
        return _result(OK)

    return _result(OK)


def reset_state():
    """每次新測項開始前呼叫，避免上一個測項殘留的 iface 錯誤基準值影響這次判斷。"""
    _last_values.clear()
