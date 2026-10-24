FROM kalilinux/kali-rolling:latest

# ── 防止互動式安裝卡住 ──
ENV DEBIAN_FRONTEND=noninteractive
ENV NEEDRESTART_MODE=a

# ── 系統套件 ──
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip python3-dev \
    nmap hping3 tshark \
    wrk slowhttptest \
    netsniff-ng \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev \
    shared-mime-info fonts-noto-cjk \
    iproute2 iputils-ping net-tools procps curl \
    gcc build-essential \
    && rm -rf /var/lib/apt/lists/*

# rustscan 在部分架構可能不可用，單獨安裝避免阻塞
RUN apt-get update -y && apt-get install -y rustscan || true \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/stress-tool

# ── 先複製 requirements.txt 以利 Docker 層快取 ──
COPY requirements.txt .
RUN python3 -m venv .venv \
    && .venv/bin/pip install --upgrade pip \
    && .venv/bin/pip install -r requirements.txt \
    || { echo "整批安裝失敗，改為逐行安裝"; \
         while IFS= read -r line; do \
           line="$(echo "$line" | sed 's/#.*$//' | xargs)"; \
           [ -z "$line" ] && continue; \
           .venv/bin/pip install "$line" || echo "!! $line 安裝失敗，略過"; \
         done < requirements.txt; }

# ── 複製應用程式碼 ──
COPY . .

# ── 建立資料目錄 ──
RUN mkdir -p data/projects

# ── 讓 tshark 可以在容器內抓封包 ──
RUN if command -v dumpcap >/dev/null 2>&1; then \
      setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)" || true; \
    fi

# ── 環境變數：bind 0.0.0.0 讓容器外可連 ──
ENV STRESS_TOOL_HOST=0.0.0.0
ENV STRESS_TOOL_PORT=8000

EXPOSE 8000

# ── 啟動健康檢查 + 服務 ──
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
