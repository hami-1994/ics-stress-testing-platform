# ICS Security Stress Testing Platform

An open-source, single-operator ICS/OT/IoT security stress testing platform. Built with FastAPI + SQLite, it provides a web-based interface for Port Scanning, protocol-aware monitoring, a categorized test library (95 test items across 35 protocol categories), test queue orchestration, packet capture, and HTML/PDF report generation — designed to produce audit-grade test records suitable for certification bodies and management review.

**繁體中文說明請見 [README_zh-TW.md](README_zh-TW.md)**

## Warning — Read Before Use

This tool sends high-volume / high-frequency network packets to designated targets, which **may cause service disruption, performance degradation, or device failure**. Use it **only** within explicitly authorized, scope-defined test environments, and strongly prefer isolated test network segments — never point it at production systems.

- All test items target only the operator-specified single target; no source IP/MAC spoofing, no reflection/amplification attacks.
- Every test item has a configurable duration cap (default max 30 min) and adjustable rate parameters; tests can be stopped or emergency-stopped at any time.
- The attacking host's own CPU/memory is monitored; overload triggers automatic test abort to protect the Kali host itself.
- The operator bears full responsibility for test scope and authorization.

## Quick Start — Docker (Recommended)

### Prerequisites

- A Linux host with Docker and Docker Compose (Kali Linux VM recommended)
- Root privileges or Docker group membership
- Network connectivity from the Docker host to the target device

### Run

```bash
git clone https://github.com/YOUR_USERNAME/ics-stress-testing-platform.git
cd ics-stress-testing-platform
docker compose up -d
```

Open your browser at **http://\<Kali-VM-IP\>:8000**

> **How to find your Kali VM IP:** Run `ip addr show` or `hostname -I` in a terminal.
> The first non-loopback address (typically on `eth0` or `ens33`) is what you need.

### Network Architecture

```
┌──────────────────────┐     ┌────────────────┐     ┌──────────────┐
│ Docker Container     │     │ Kali VM Host   │     │ Target       │
│ (stress-tool)        │────▶│ Network Stack  │────▶│ Device (DUT) │
│ network_mode: host   │     │ Physical NIC   │     │              │
└──────────────────────┘     └────────────────┘     └──────────────┘
```

The container runs with `network_mode: host` so that:
- Layer 2 tests (EtherCAT, PROFINET, GOOSE) can directly access the host's physical NIC
- Raw socket operations (SYN Flood, etc.) are not interfered by Docker bridge NAT
- Attack traffic routes correctly through the host network stack to the target

### Docker Commands

```bash
docker compose up -d          # Start in background
docker compose logs -f        # Stream live logs
docker compose down           # Stop and remove container
docker compose up -d --build  # Rebuild after code changes
```

### Data Persistence

Test data is stored in `./data/` on the host (mounted as a Docker volume). Container rebuilds or restarts will not lose your projects, reports, or CSV logs.

## Quick Start — Bare Metal

```bash
sudo ./install.sh    # Install system packages + Python venv + healthcheck
sudo ./run.sh        # Start the platform (binds 127.0.0.1:8000 by default)
```

Open **http://127.0.0.1:8000** in the browser on the same machine. For remote access, use SSH port forwarding or a VPN rather than binding to `0.0.0.0`.

> Requires Kali Linux (or compatible Debian-based distro), 2+ vCPU / 4GB+ RAM, root privileges.

## Features

- **Port Scanning** — nmap and rustscan integration with background execution
- **Protocol-Aware Service Monitoring** — real protocol handshake probing (CIP RegisterSession, Modbus FC03, EtherNet/IP ListIdentity, etc.) instead of just TCP connect, with three-level status: UP / DEGRADED / DOWN
- **95 Test Items across 35 Protocol Categories** — covering Modbus, EtherNet/IP (CIP), OPC UA, S7, EtherCAT, PROFINET, DNP3, IEC 104, BACnet, MQTT, GOOSE, MMS, HTTP, and more
- **Dual Execution Engines** — Standard (single-thread) or High-Concurrency (multi-thread, configurable 1–32 workers) per test item
- **Two-Axis Pass/Fail Verdict** — Process Stability (during test) + Recovery Ability (after test), independently assessed
- **Packet Capture** — tshark integration with pcap/summary dual modes
- **HTML & PDF Reports** — audit-grade, with executive summary, monitoring cross-reference matrix, and per-test-item detail
- **Plugin Healthcheck** — static dependency scan on install; missing dependencies auto-disable affected test items
- **Self-Protection** — auto-abort on attacking host CPU/memory overload

## Test Item Library (95 items, 35 categories)

| Category | Count |
|---|---|
| Generic (protocol-agnostic) | 4 |
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

## Project Structure

```
ics-stress-testing-platform/
  Dockerfile / docker-compose.yml    # Docker deployment
  docker-entrypoint.sh
  install.sh / run.sh / uninstall.sh # Bare-metal deployment
  requirements.txt
  app/
    main.py                    # FastAPI entry point
    config.py                  # Settings (bind address, data dir, duration cap)
    db.py / models.py / schemas.py   # SQLite ORM + API data structures
    audit.py                   # Audit log (append-only)
    scan.py                    # Port Scan (nmap / rustscan)
    capture.py                 # Packet capture (tshark, pcap/summary dual mode)
    orchestrator.py            # Test queue state machine
    reports.py                 # HTML/PDF report generation
    events.py                  # WebSocket real-time event broadcast
    registry.py                # Test item registry (protocol-categorized)
    plugin_healthcheck.py      # Static dependency scan for each plugin
    health.py                  # Monitor anomaly assessment (ok/warn/critical/na)
    monitors/                  # Monitors (ping/iface/TCP/UDP/self-resource/service/ARP)
    plugins/                   # Test item plugins (95 items, 35 protocol categories)
    routers/                   # REST API endpoints
    templates/                 # index.html (frontend), report_template.html
    static/                    # app.js, style.css
  scripts/
    run_healthcheck.py         # Post-install healthcheck runner
  data/                        # Runtime data: db.sqlite3 + projects/
```

## Extending

- **New test items:** Follow the contract in `app/plugins/common.py` (define `NAME`/`CATEGORY`/`PROTOCOL`/`TEST_TYPE`/`get_param_schema()`/`run()`), then add an entry to `TEST_ITEMS` in `app/registry.py`.
- **New monitors:** Follow any existing file in `app/monitors/` (define `TYPE`/`NAME`/`sample(config)`), then add to `REGISTRY` in `app/monitors/__init__.py`.

## Known Limitations

- Some protocol-specific packet construction (DNP3, IEC 104, BACnet, GOOSE/MMS, CoAP, FINS, KNX/IP, etc.) is hand-implemented from public specifications and has not been end-to-end validated against real devices. Verify with Wireshark before production use.
- Niagara Fox/CODESYS, PROFIBUS-DP gateway, SMB/CIFS tests intentionally stay at TCP connection-level resource exhaustion due to proprietary protocol complexity.
- PDF reports depend on `weasyprint`; if system libraries (cairo/pango) are missing, it falls back to HTML-only reports.
- Single FastAPI process, single queue thread — no parallel multi-project test execution (by design, to keep monitoring data clean).
- WebSocket is push-only; page refresh requires REST polling to restore current state.
- Plugin healthcheck is a static dependency scan, not a live protocol validation.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Disclaimer

This tool is provided for **authorized security testing only**. The authors assume no liability for misuse. Always obtain proper authorization before testing any system you do not own.
