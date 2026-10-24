# ICS Security Stress Testing Platform

開源、單人操作的 ICS/OT/IoT 資安壓力測試平台。以 FastAPI + SQLite 建構，提供 Web 介面進行 Port Scanning、協定層級監控、分類測試項目庫（35 個協定類別共 95 項測試）、測試佇列排程、封包擷取，以及 HTML/PDF 報告產出——設計用於產出稽核等級的測試記錄，適合送交驗證機構及管理階層審閱。

**For English documentation, see [README.md](README.md)**

## 警告 — 使用前務必閱讀

本工具會向指定目標傳送大量／高頻率的網路封包，**可能導致服務中斷、效能下降，甚至設備故障**。請**僅在**明確授權、範圍界定的測試環境中使用，強烈建議使用隔離的測試網段——切勿對正式環境使用。

- 所有測試項目僅針對操作者指定的單一目標；不進行來源 IP/MAC 偽冒，不進行反射/放大攻擊。
- 每個測試項目皆有可設定的持續時間上限（預設最長 30 分鐘）及可調整的速率參數；可隨時停止或緊急中止。
- 攻擊主機本身的 CPU/記憶體受到監控；過載時自動中止測試，保護 Kali 主機本身。
- 操作者對測試範圍及授權負完全責任。

## 快速開始 — Docker（建議）

### 前置需求

- 安裝有 Docker 及 Docker Compose 的 Linux 主機（建議使用 Kali Linux VM）
- Root 權限或 Docker 群組成員資格
- Docker 主機到目標設備的網路連通性

### 啟動

```bash
git clone https://github.com/YOUR_USERNAME/ics-stress-testing-platform.git
cd ics-stress-testing-platform
docker compose up -d
```

以瀏覽器開啟 **http://\<Kali-VM-IP\>:8000**

> **如何查詢 Kali VM IP：** 在終端機執行 `ip addr show` 或 `hostname -I`。
> 第一個非 loopback 位址（通常在 `eth0` 或 `ens33`）就是你需要的。

### 網路架構

```
┌──────────────────────┐     ┌────────────────┐     ┌──────────────┐
│ Docker Container     │     │ Kali VM Host   │     │ Target       │
│ (stress-tool)        │────▶│ Network Stack  │────▶│ Device (DUT) │
│ network_mode: host   │     │ Physical NIC   │     │              │
└──────────────────────┘     └────────────────┘     └──────────────┘
```

Container 使用 `network_mode: host`，使得：
- Layer 2 測試（EtherCAT、PROFINET、GOOSE）可直接存取主機的實體網卡
- Raw socket 操作（SYN Flood 等）不受 Docker bridge NAT 干擾
- 攻擊流量正確通過主機網路堆疊路由至目標

### Docker 常用指令

```bash
docker compose up -d          # 背景啟動
docker compose logs -f        # 串流即時 log
docker compose down           # 停止並移除 container
docker compose up -d --build  # 程式碼修改後重新建構
```

### 資料持久化

測試資料儲存在主機的 `./data/` 目錄（掛載為 Docker volume）。Container 重建或重啟不會遺失專案、報告或 CSV 記錄。

## 快速開始 — 直接安裝

```bash
sudo ./install.sh    # 安裝系統套件 + Python venv + 健康檢查
sudo ./run.sh        # 啟動平台（預設綁定 127.0.0.1:8000）
```

在同一台機器的瀏覽器開啟 **http://127.0.0.1:8000**。若需遠端存取，請使用 SSH port forwarding 或 VPN，而非綁定 `0.0.0.0`。

> 需要 Kali Linux（或相容的 Debian 衍生發行版），2+ vCPU / 4GB+ RAM，root 權限。

## 功能特色

- **Port Scanning** — 整合 nmap 及 rustscan，支援背景執行
- **協定層級服務監控** — 以真實協定交握探測（CIP RegisterSession、Modbus FC03、EtherNet/IP ListIdentity 等）取代單純的 TCP 連線檢查，提供三級狀態：UP / DEGRADED / DOWN
- **35 個協定類別共 95 項測試** — 涵蓋 Modbus、EtherNet/IP (CIP)、OPC UA、S7、EtherCAT、PROFINET、DNP3、IEC 104、BACnet、MQTT、GOOSE、MMS、HTTP 等
- **雙重執行引擎** — 每個測試項目可選擇 Standard（單執行緒）或 High-Concurrency（多執行緒，可設定 1–32 workers）
- **雙軸判定** — 過程穩定性（測試中）+ 恢復能力（測試後），獨立評估
- **封包擷取** — 整合 tshark，支援 pcap/summary 雙模式
- **HTML & PDF 報告** — 稽核等級，含執行摘要、監控交叉矩陣及個別測試項目細節
- **Plugin 健康檢查** — 安裝時進行靜態依賴掃描；缺少依賴的測試項目自動停用
- **自我保護** — 攻擊主機 CPU/記憶體過載時自動中止

## 測試項目庫（95 項，35 類別）

| 類別 | 數量 |
|---|---|
| Generic（協定無關） | 4 |
| HTTP/Web | 5 |
| Modbus TCP | 12 |
| EtherNet/IP (CIP) | 5 |
| OPC UA | 5 |
| Siemens S7 | 4 |
| EtherCAT | 4 |
| PROFINET | 4 |
| DNP3 | 4 |
| IEC 60870-5-104 | 4 |
| BACnet | 5 |
| MQTT | 2 |
| SNMP | 3 |
| IEC 61850 (GOOSE) | 1 |
| IEC 61850 (MMS) | 1 |
| FTP | 2 |
| SSH | 2 |
| RDP | 2 |
| RPC | 2 |
| Network Layer (ARP/ICMP/IGMP/LLDP/STP) | 5 |
| CoAP (IoT) | 1 |
| UPnP/SSDP (IoT) | 1 |
| mDNS (IoT Service Discovery) | 1 |
| RTSP/ONVIF (IP Camera) | 1 |
| Telnet | 1 |
| TFTP (Firmware Update) | 1 |
| LoRaWAN Gateway Bridge | 1 |
| ICS Gateway | 3 |
| FINS (Omron PLC) | 2 |
| KNX/IP (Building Automation) | 2 |
| DNS | 1 |
| NTP | 1 |
| Redis | 1 |
| SMB/CIFS | 1 |
| VNC | 1 |

## 專案結構

```
ics-stress-testing-platform/
  Dockerfile / docker-compose.yml    # Docker 部署
  docker-entrypoint.sh
  install.sh / run.sh / uninstall.sh # 直接安裝部署
  requirements.txt
  app/
    main.py                    # FastAPI 進入點
    config.py                  # 設定（綁定位址、資料目錄、時間上限）
    db.py / models.py / schemas.py   # SQLite ORM + API 資料結構
    audit.py                   # 稽核日誌（唯附加）
    scan.py                    # Port Scan（nmap / rustscan）
    capture.py                 # 封包擷取（tshark，pcap/summary 雙模式）
    orchestrator.py            # 測試佇列狀態機
    reports.py                 # HTML/PDF 報告產生
    events.py                  # WebSocket 即時事件廣播
    registry.py                # 測試項目註冊表（依協定分類）
    plugin_healthcheck.py      # 各 plugin 靜態依賴掃描
    health.py                  # 監控異常評估（ok/warn/critical/na）
    monitors/                  # 監控器（ping/iface/TCP/UDP/self-resource/service/ARP）
    plugins/                   # 測試項目 plugins（95 項，35 個協定類別）
    routers/                   # REST API 端點
    templates/                 # index.html（前端）、report_template.html
    static/                    # app.js、style.css
  scripts/
    run_healthcheck.py         # 安裝後健康檢查執行器
  data/                        # 執行時資料：db.sqlite3 + projects/
```

## 擴充

- **新增測試項目：** 依照 `app/plugins/common.py` 中的介面（定義 `NAME`/`CATEGORY`/`PROTOCOL`/`TEST_TYPE`/`get_param_schema()`/`run()`），然後在 `app/registry.py` 的 `TEST_ITEMS` 中新增項目。
- **新增監控器：** 參考 `app/monitors/` 中的現有檔案（定義 `TYPE`/`NAME`/`sample(config)`），然後在 `app/monitors/__init__.py` 的 `REGISTRY` 中新增。

## 已知限制

- 部分協定封包建構（DNP3、IEC 104、BACnet、GOOSE/MMS、CoAP、FINS、KNX/IP 等）是依據公開規格手動實作，尚未針對實體設備進行端對端驗證。正式使用前請以 Wireshark 驗證。
- Niagara Fox/CODESYS、PROFIBUS-DP gateway、SMB/CIFS 測試因專有協定複雜性，刻意停留在 TCP 連線層級的資源耗盡。
- PDF 報告依賴 `weasyprint`；若系統缺少函式庫（cairo/pango），將退回僅產出 HTML 報告。
- 單一 FastAPI 程序、單一佇列執行緒——不支援多專案平行測試執行（設計如此，以保持監控資料乾淨）。
- WebSocket 僅推送；頁面重新整理需靠 REST polling 恢復當前狀態。
- Plugin 健康檢查為靜態依賴掃描，非即時協定驗證。

## 授權條款

本專案採用 MIT License 授權——詳見 [LICENSE](LICENSE)。

## 貢獻

歡迎貢獻！請參閱 [CONTRIBUTING.md](CONTRIBUTING.md) 瞭解指引。

## 免責聲明

本工具**僅供經授權的資安測試使用**。作者不對任何濫用行為負責。在測試任何非您所有的系統之前，請務必取得適當授權。
