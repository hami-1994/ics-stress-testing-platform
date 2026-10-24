"""UDP 服務監控：對目標 UDP port 送出探測封包，觀察其存活訊號。

UDP 本身是無連線協定，「沒收到回應」不代表服務掛了——很多 UDP 服務對非預期格式的
封包本來就不會回覆。這裡採用比較保守、不會亂噴誤判的判斷方式：

  - 用「已 connect() 的 UDP socket」送出一個探測封包。Linux 上，對 connected UDP
    socket 而言，如果對方回了 ICMP Port Unreachable（代表該 port 根本沒有服務在聽），
    這個錯誤會在下一次 send/recv 時浮現成 ConnectionRefusedError——這是少數對 UDP
    「服務是否還在」的明確訊號，視為 up=False。
  - 若真的收到任何回應（不管內容格式），視為存活，up=True，並記錄延遲。
  - 若單純逾時、什麼都沒收到也沒有錯誤，這是 UDP 的常態（服務可能刻意不回應未知封包），
    標記 up=None（無法判斷／中性），不當成異常，避免大量誤報淹沒真正的問題。
"""
import socket
import time

TYPE = "udp"
NAME = "UDP 服務監控"


def sample(config: dict) -> dict:
    target = config.get("target", "")
    port = config.get("port")
    if not target or not port:
        return {"error": "缺少 target/port"}

    t0 = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.5)
    try:
        sock.connect((target, int(port)))
        sock.send(b"\x00")
        try:
            sock.recv(512)
            latency_ms = round((time.time() - t0) * 1000, 1)
            return {"up": True, "latency_ms": latency_ms}
        except socket.timeout:
            return {"up": None, "latency_ms": None}
        except ConnectionRefusedError:
            return {"up": False, "latency_ms": None, "error": "ICMP Port Unreachable"}
    except OSError as e:
        return {"up": False, "latency_ms": None, "error": str(e)}
    finally:
        try:
            sock.close()
        except OSError:
            pass
