"""ARP 監控（鏈路層存活）。

跟 ping/service/udp 監控的差異：這幾種都是 IP 層以上的探測，如果目標的防火牆擋 ICMP、
服務當機、或應用層卡死，都會讓它們判定「down」；但只要目標的網路卡與作業系統的 ARP stack
還活著，通常還是會回 ARP reply。所以 ARP 監控回應更接近「這台裝置在網路上到底還在不在」，
比較能捕捉到使用者說的「網路中斷／link down」這類更底層的異常，跟 TCP/ICMP 逾時是不同等級
的問題（後者可能只是服務掛了，前者是整台裝置/網路介面掛了）。

限制（誠實列出）：ARP 只在同一個 Layer 2 網段（同一個子網/VLAN）才有效——如果目標在別的
網段、中間要經過路由器，這個監控器本來就量不到東西，會一直顯示 up=None（無法判斷），
這是 ARP 協定本身的限制，不是 bug。需要 root 或 CAP_NET_RAW 權限才能送出 ARP request。
"""
import time

TYPE = "arp"
NAME = "ARP 監控（鏈路層存活）"


def sample(config: dict) -> dict:
    target = config.get("target", "")
    if not target:
        return {"error": "缺少 target"}
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        return {"error": "未安裝 scapy，請先執行 pip install scapy"}

    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
        t0 = time.time()
        ans, _ = srp(pkt, timeout=1.5, verbose=False, retry=0)
        if ans:
            latency_ms = round((time.time() - t0) * 1000, 1)
            mac = ans[0][1].hwsrc
            return {"up": True, "latency_ms": latency_ms, "mac": mac}
        # 沒收到 ARP reply：可能真的離線，也可能目標不在同一個 L2 網段（此監控器本來就量不到）。
        return {"up": False, "latency_ms": None}
    except PermissionError as e:
        return {"error": f"需要 root/CAP_NET_RAW 權限才能送 ARP request：{e}"}
    except OSError as e:
        return {"error": str(e)}
