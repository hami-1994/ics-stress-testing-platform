"""
app/scan.py — Port Scan 模組（設計文件 5.2 節），用 nmap 執行、解析 XML 結果。
"""
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from . import models
from .db import SessionLocal

_SCAN_FLAGS = {
    "tcp_syn": ["-sS"],
    "tcp_connect": ["-sT"],
    "udp": ["-sU"],
    "tcp_udp": ["-sS", "-sU"],  # TCP SYN + UDP 一起掃（預設選項），nmap 原生支援同一次掃描下兩種協定
}

# 這是內部授權測試工具（測自己團隊的產品），不需要隱匿性考量，所以速度優先：
# -T5（最積極的 timing template）+ --min-rate 強制最低發送速率，避免 nmap 自動降速。
# UDP 掃描本身受限於協定設計（很多裝置對非預期封包會做 ICMP rate limit），這兩個參數
# 沒辦法讓 UDP 掃描跟 TCP 一樣快，這是協定本身的限制，不是設定問題。
_NMAP_SPEED_FLAGS = ["-T5", "--min-rate", "1000"]


def _build_cmd(scan_type: str, port_range: str, target_host: str, xml_path: Path) -> list[str]:
    if scan_type == "rustscan":
        # rustscan 先用自己的高併發 port discovery 找出開放的 port（比 nmap 原生掃描快很多），
        # 再透過 `--` 把剩下的參數丟給 nmap 做 service/version 偵測＋輸出 XML
        # （沿用同一個 XML 解析邏輯，前端/資料庫端完全不用區分是哪個掃描引擎跑出來的）。
        return [
            "rustscan", "-a", target_host, "-r", port_range, "--ulimit", "5000",
            "--", "-sV", "-oX", str(xml_path),
        ]
    flags = _SCAN_FLAGS.get(scan_type, ["-sS"])
    return ["nmap", *flags, *_NMAP_SPEED_FLAGS, "-p", port_range, "-sV", "-oX", str(xml_path), target_host]


def run_scan_background(scan_id: int, project_dir: Path):
    """在背景執行緒跑 nmap，完成後把結果寫回 DB。用自己的 DB session（跨執行緒不能共用）。"""
    db = SessionLocal()
    try:
        scan = db.get(models.ScanResult, scan_id)
        if not scan:
            return
        project = scan.project
        target = project.target

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()

        scans_dir = project_dir / "scans"
        scans_dir.mkdir(parents=True, exist_ok=True)
        xml_path = scans_dir / f"scan_{scan_id}.xml"

        cmd = _build_cmd(scan.scan_type, scan.port_range, target.ip_or_host, xml_path)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            if proc.returncode != 0 and not xml_path.exists():
                scan.status = "failed"
                scan.error = proc.stderr[-2000:]
            else:
                _parse_and_store(db, project.id, xml_path)
                scan.status = "completed"
        except subprocess.TimeoutExpired:
            scan.status = "failed"
            scan.error = "掃描逾時（超過 1 小時）"
        except FileNotFoundError:
            tool = "rustscan" if scan.scan_type == "rustscan" else "nmap"
            scan.status = "failed"
            scan.error = f"找不到 {tool}，請確認已安裝（見 install.sh），或改選其他掃描類型"

        scan.raw_xml_path = str(xml_path)
        scan.finished_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()


def _parse_and_store(db, project_id: int, xml_path: Path):
    if not xml_path.exists():
        return
    tree = ET.parse(xml_path)
    root = tree.getroot()
    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            portid = int(port_el.get("portid"))
            protocol = port_el.get("protocol", "tcp")
            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"
            if state not in ("open", "open|filtered"):
                continue
            service_el = port_el.find("service")
            service_name = service_el.get("name", "") if service_el is not None else ""
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            banner = " ".join(filter(None, [product, version]))

            existing = (
                db.query(models.PortEntry)
                .filter_by(project_id=project_id, port=portid, protocol=protocol)
                .first()
            )
            if existing:
                existing.service_name = service_name
                existing.banner = banner
                existing.state = state
            else:
                db.add(models.PortEntry(
                    project_id=project_id, port=portid, protocol=protocol,
                    service_name=service_name, banner=banner, state=state,
                    selected=True, source="scan",
                ))
    db.commit()
