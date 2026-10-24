"""
app/monitors — 監控器（設計文件 5.4 節）

每個監控器模組提供：
    TYPE = "ping" 等識別字串
    NAME = 顯示名稱
    def sample(config: dict) -> dict:  單次取樣，回傳一組 metrics（供寫入 CSV / WebSocket）

實際的「每隔 N 秒跑一次、寫檔、推播」迴圈邏輯統一在 base.py 的 MonitorRunner，
監控器模組本身只需要負責「怎麼取一次樣」，不用管執行緒/停止/寫檔這些。
"""
from . import arp_monitor, iface_monitor, ping_monitor, self_resource_monitor, service_monitor, tcp_monitor, udp_monitor

REGISTRY = {
    ping_monitor.TYPE: ping_monitor,
    iface_monitor.TYPE: iface_monitor,
    tcp_monitor.TYPE: tcp_monitor,
    udp_monitor.TYPE: udp_monitor,
    arp_monitor.TYPE: arp_monitor,
    self_resource_monitor.TYPE: self_resource_monitor,
    service_monitor.TYPE: service_monitor,
}
