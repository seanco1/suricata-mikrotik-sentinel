# Suricata MikroTik & Telegram Sentinel 🛡️⚡

A high-performance **Suricata IDS/IPS Automated Defense System** that bridges Suricata intrusion detection with MikroTik RouterOS firewalls and interactive Telegram Bot alerts.

It parses real-time Suricata `eve.json` alert streams, automatically injects threat IPs into MikroTik firewall address-lists (IPS mode), provides instant Telegram inline actions (Block/Unblock/Suppress), and features a rich, responsive Web UI Dashboard for real-time monitoring and rule tuning.

---

## ✨ System Architecture & Features

### 🛡️ 1. Active Threat Prevention (IPS Engine)
- **Automatic IP Blocking**: Instantly adds attacking source IPs to MikroTik RouterOS IP Firewall Address-List (`BLOCK_TIMEOUT = 1 hour`).
- **Cool-Down Protection**: Implements per-signature and per-IP cooldown timers (5 minutes) to prevent event flooding.
- **Dynamic Whitelisting**: Automatically queries MikroTik interface WAN IPs, IPv6 prefixes, and subnet ranges to avoid accidental blocking of local interfaces or public gateway IPs.

### 📱 2. Interactive Telegram Bot Integration
- **Real-Time Threat Notifications**: Sends formatted threat alerts to your Telegram chat containing signature name, target IP, category, and severity.
- **Inline Action Buttons**:
  - 🛑 **Block IP**: Manually block an IP on MikroTik.
  - 🔓 **Unblock IP**: Remove an IP from MikroTik address-list.
  - 🔕 **Suppress Signature**: Silence noisy rule alerts directly from Telegram.
  - ⚪ **Whitelist Target/IP**: Exclude safe IPs from future automated blocks.
- **Webhook Callback Processing**: Processes Telegram button clicks in real time via secure HTTP webhook.

### 💻 3. Modern Web UI Security Command Center (`Port 8888`)
- **Live Threat Stream**: View incoming high-severity and low-severity Suricata alert events in real time.
- **Interactive Whitelist Management**: Add, remove, and view custom target/IP whitelists.
- **Rule Suppression Tuning**: Add or edit rule suppression thresholds (`threshold.config`) directly from the web interface.
- **MikroTik Active Blocks List**: View currently blocked IPs on the router with remaining timeout counters and manual unblock triggers.

### 🔄 4. TZSP Traffic Decapsulation (`tzsp_decap.py`)
- Receives MikroTik Packet Streaming (TZSP UDP 37008) traffic.
- Decapsulates raw Ethernet frames and injects them into a virtual bridge (`br-ids`) for Suricata interface sniffing without requiring physical TAP hardware.

---

## 🛠️ Complete Installation & Setup Guide

### 📋 Prerequisites

1. **Suricata IDS/IPS** installed on Linux (`/etc/suricata/suricata.yaml` configured with `eve-log` JSON enabled).
2. **MikroTik RouterOS** device with API enabled (`/ip service enable api`).
3. **Telegram Bot Token & Chat ID** (via Telegram [@BotFather](https://t.me/BotFather)).
4. **Python 3.8+** with `pip`.

---

### Step 1: Clone Repository & Install Python Dependencies

```bash
git clone https://github.com/seanco1/suricata-mikrotik-sentinel.git
cd suricata-mikrotik-sentinel
pip install -r requirements.txt
```

---

### Step 2: Environment Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Edit `.env` with your network and credential settings:

```ini
TELEGRAM_BOT_TOKEN="your_bot_token_here"
TELEGRAM_CHAT_ID="your_telegram_chat_id"
SURICATA_WEBHOOK_SECRET="your_random_webhook_secret"
NUC_BRIDGE_WEBHOOK_SECRET="your_random_bridge_secret"

MIKROTIK_HOST="172.18.141.1"
MIKROTIK_USER="admin"
MIKROTIK_PASS="your_secure_router_password"
BLOCK_TIMEOUT="01:00:00"

EVE_LOG_PATH="/var/log/suricata/eve.json"
THRESHOLD_CONF_PATH="/etc/suricata/threshold.config"
WHITELIST_CONF_PATH="/etc/suricata/whitelist.config"
WEB_PORT=8888
DASHBOARD_URL="https://suricata.yourdomain.com/"
```

---

### Step 3: MikroTik RouterOS Setup

#### 1. Enable RouterOS API
Log in to your MikroTik router (WinBox or SSH) and ensure the API service is enabled:

```routeros
/ip service set api disabled=no port=8728
```

#### 2. Create Firewall Drop Rule
Add a firewall rule to drop traffic originating from the `Suricata-Blocked` address-list:

```routeros
/ip firewall filter add chain=forward src-address-list=Suricata-Blocked action=drop comment="Suricata IDS Automated Block"
```

---

### Step 4: Virtual IDS Interface Setup (TZSP Sniffing)

Create systemd service `/etc/systemd/system/virtual-ids-interface.service` to create the virtual `br-ids` bridge:

```ini
[Unit]
Description=Create Virtual IDS Bridge Interface for Suricata
Before=suricata.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'ip link add name br-ids type bridge 2>/dev/null || true; ip link set dev br-ids up; ip link add name dummy-ids type dummy 2>/dev/null || true; ip link set dev dummy-ids master br-ids; ip link set dev dummy-ids up'
ExecStop=/bin/sh -c 'ip link delete dev dummy-ids 2>/dev/null || true; ip link delete dev br-ids 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
```

Enable and start the bridge service:

```bash
systemctl daemon-reload
systemctl enable --now virtual-ids-interface.service
```

---

### Step 5: Systemd Service Installation

Create `/etc/systemd/system/suricata-mikrotik.service`:

```ini
[Unit]
Description=Suricata to MikroTik & Telegram Integration Service
After=suricata.service
Wants=suricata.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/suricata-mikrotik-sentinel
ExecStart=/usr/bin/python3 daemon.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the daemon:

```bash
systemctl daemon-reload
systemctl enable --now suricata-mikrotik.service
```

---

## 📡 API & Webhook Endpoints

- `GET /`: Modern Web UI Security Dashboard.
- `GET /api/threats`: Fetch recent threats and raw alert event ring-buffer.
- `GET /api/blocked`: List active blocked IPs on MikroTik.
- `POST /api/unblock`: Unblock IP from MikroTik address-list.
- `POST /api/whitelist`: Add/Remove IP or Target signature from whitelist.
- `POST /api/suppress`: Add signature suppression rule to `threshold.config`.
- `POST /telegram/webhook`: Webhook handler for Telegram inline button click actions.

---

## 📄 License

[MIT](LICENSE) - Free to use and modify!
