import json
import time
import os
import requests
import re
import html
import routeros_api
import ipaddress
import socket
from threading import Thread
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

# Config
EVE_LOG_PATH = os.environ.get("EVE_LOG_PATH", "/var/log/suricata/eve.json")
THRESHOLD_CONF_PATH = os.environ.get("THRESHOLD_CONF_PATH", "/etc/suricata/threshold.config")
WHITELIST_CONF_PATH = os.environ.get("WHITELIST_CONF_PATH", "/etc/suricata/whitelist.config")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "YOUR_TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "YOUR_TELEGRAM_CHAT_ID")
SURICATA_WEBHOOK_SECRET = os.environ.get("SURICATA_WEBHOOK_SECRET", "YOUR_SURICATA_WEBHOOK_SECRET")
NUC_BRIDGE_WEBHOOK_SECRET = os.environ.get("NUC_BRIDGE_WEBHOOK_SECRET", "YOUR_NUC_BRIDGE_WEBHOOK_SECRET")
MIKROTIK_HOST = os.environ.get("MIKROTIK_HOST", "172.18.141.1")
MIKROTIK_USER = os.environ.get("MIKROTIK_USER", "admin")
MIKROTIK_PASS = os.environ.get("MIKROTIK_PASS", "password")
BLOCK_TIMEOUT = os.environ.get("BLOCK_TIMEOUT", "01:00:00")  # 1 hour timeout on MikroTik
WEB_PORT = int(os.environ.get("WEB_PORT", 8888))
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "http://localhost:8888/")

# Alert history tracking: signature_id -> count
ALERT_HISTORY = {}
ALERT_CACHE = {}
RECENT_THREATS = []
RAW_EVENTS = []  # Ring buffer storing last 500 alert events (including low severity)
LAST_TARGET_PER_SIG = {}  # signature_id -> target_ip
COOLDOWN_SECONDS = 300  # 5 minutes per signature/IP

# Persistent RouterOS API connection
ROUTEROS_POOL = None

def get_routeros_connection():
    global ROUTEROS_POOL
    if ROUTEROS_POOL is None:
        try:
            ROUTEROS_POOL = routeros_api.RouterOsApiPool(
                MIKROTIK_HOST,
                username=MIKROTIK_USER,
                password=MIKROTIK_PASS,
                plaintext_login=True
            )
        except Exception as e:
            print(f"Error initializing persistent RouterOS API connection: {e}", flush=True)
            ROUTEROS_POOL = None
    return ROUTEROS_POOL

# Dynamic Public IP & IPv6 Prefix Whitelist Cache
PUBLIC_IPS = set()
IPV6_PREFIXES = []
IPV4_WAN_ADDRESS = ""
CUSTOM_WHITELIST_TARGETS = set()
CUSTOM_WHITELIST_IPS = set()
LAST_IP_CHECK = 0
CHECK_INTERVAL = 30  # Refresh IPv6 prefixes & check sniffer status every 30 seconds

def ensure_mikrotik_sniffer_running():
    """Check if RouterOS packet sniffer is running; automatically start it if stopped (e.g. post-reboot)."""
    pool = get_routeros_connection()
    if pool:
        try:
            api = pool.get_api()
            sniffer_res = api.get_resource('/tool/sniffer')
            status_list = sniffer_res.get()
            if status_list:
                status = status_list[0]
                if status.get('running') == 'false':
                    print("[SNIFFER] MikroTik packet sniffer is stopped. Auto-starting sniffer...", flush=True)
                    sniffer_res.call('start')
                    print("[SNIFFER] Successfully started MikroTik packet sniffer!", flush=True)
        except Exception as e:
            print(f"Error checking/starting MikroTik packet sniffer: {e}", flush=True)

def normalize_ip(ip_str):
    """Normalize IPv4 or IPv6 string for exact comparison."""
    if not ip_str:
        return ""
    clean = str(ip_str).strip().split('/')[0]
    try:
        return str(ipaddress.ip_address(clean))
    except Exception:
        return clean

def resolve_target_to_ips(target_str):
    """Resolve an IP or FQDN (domain) into a list of normalized IPv4 and IPv6 addresses."""
    resolved_ips = []
    target_str = target_str.strip()
    
    try:
        ip_obj = ipaddress.ip_address(target_str)
        return [str(ip_obj)]
    except ValueError:
        pass
        
    try:
        addr_info = socket.getaddrinfo(target_str, None)
        for item in addr_info:
            ip = normalize_ip(item[4][0])
            if ip and ip not in resolved_ips:
                resolved_ips.append(ip)
    except Exception as e:
        print(f"Error resolving FQDN {target_str}: {e}", flush=True)
        
    return resolved_ips

def load_custom_whitelist():
    """Load user whitelisted IPs and FQDN domains directly from disk on every check."""
    global CUSTOM_WHITELIST_TARGETS, CUSTOM_WHITELIST_IPS
    targets = set()
    ips = set()
    if os.path.exists(WHITELIST_CONF_PATH):
        with open(WHITELIST_CONF_PATH, "r") as f:
            for line in f:
                entry = line.strip()
                if entry and not entry.startswith("#"):
                    targets.add(entry)
                    resolved = resolve_target_to_ips(entry)
                    for ip in resolved:
                        ips.add(normalize_ip(ip))
    CUSTOM_WHITELIST_TARGETS = targets
    CUSTOM_WHITELIST_IPS = ips
    return targets, ips

def refresh_mikrotik_prefixes():
    """Query persistent MikroTik API directly for public IPv4 WAN IP (/ip/cloud) & dynamic IPv6 Prefix Delegation (/ipv6/pool)."""
    global PUBLIC_IPS, IPV6_PREFIXES, IPV4_WAN_ADDRESS, LAST_IP_CHECK
    now = time.time()
    if now - LAST_IP_CHECK < CHECK_INTERVAL:
        return
        
    new_ips = set()
    new_prefixes = []
    
    load_custom_whitelist()
    
    pool = get_routeros_connection()
    if pool:
        try:
            api = pool.get_api()
            
            try:
                cloud_data = api.get_resource('/ip/cloud').get()
                if cloud_data:
                    pub_v4 = cloud_data[0].get('public-address')
                    if pub_v4:
                        new_ips.add(normalize_ip(pub_v4))
                        IPV4_WAN_ADDRESS = pub_v4
            except Exception as e:
                print(f"Failed to fetch /ip/cloud public address: {e}", flush=True)
                
            pools = api.get_resource('/ipv6/pool').get()
            for p in pools:
                prefix_str = p.get('prefix') or p.get('actual-prefix')
                if prefix_str:
                    clean_prefix = prefix_str.split(',')[0].strip()
                    try:
                        net = ipaddress.ip_network(clean_prefix, strict=False)
                        new_prefixes.append(net)
                    except Exception:
                        pass
                        
            addrs = api.get_resource('/ipv6/address').get()
            for a in addrs:
                addr_str = a.get('address')
                if addr_str:
                    clean_addr = normalize_ip(addr_str)
                    new_ips.add(clean_addr)
        except Exception as e:
            print(f"Failed to query persistent MikroTik API (will reconnect): {e}", flush=True)
            ROUTEROS_POOL = None

    ensure_mikrotik_sniffer_running()
            
    PUBLIC_IPS = new_ips
    IPV6_PREFIXES = new_prefixes
    LAST_IP_CHECK = now

def resolve_lan_ip_from_mikrotik(src_port, dest_port):
    """Lookup active MikroTik NAT connection table using reply-dst-port or src-port to resolve original pre-NAT LAN IPv4."""
    pool = get_routeros_connection()
    if not pool:
        return None
    ports_to_check = [p for p in [src_port, dest_port] if p]
    try:
        api = pool.get_api()
        conns_resource = api.get_resource('/ip/firewall/connection')
        for port in ports_to_check:
            try:
                conns = conns_resource.get(reply_dst_port=str(port))
                for c in conns:
                    orig_src = c.get('src-address', '').split(':')[0]
                    if orig_src and (orig_src.startswith("192.168.") or orig_src.startswith("10.") or orig_src.startswith("172.16.") or orig_src.startswith("172.17.") or orig_src.startswith("172.18.") or orig_src.startswith("172.19.")):
                        return orig_src
                        
                conns2 = conns_resource.get(src_port=str(port))
                for c in conns2:
                    orig_src = c.get('src-address', '').split(':')[0]
                    if orig_src and (orig_src.startswith("192.168.") or orig_src.startswith("10.") or orig_src.startswith("172.16.") or orig_src.startswith("172.17.") or orig_src.startswith("172.18.") or orig_src.startswith("172.19.")):
                        return orig_src
            except Exception:
                pass
    except Exception:
        pass
    return None

def is_custom_whitelisted(ip_str):
    """Check if target IP is present in custom whitelist file on disk."""
    if not ip_str:
        return False
    norm = normalize_ip(ip_str)
    _, custom_ips = load_custom_whitelist()
    return norm in custom_ips

def is_internal_or_whitelisted(ip_str):
    if not ip_str:
        return True
        
    norm = normalize_ip(ip_str)
    
    if is_custom_whitelisted(norm):
        return True
        
    try:
        ip_obj = ipaddress.ip_address(norm)
        # Explicitly exclude CGNAT (100.64.0.0/10) so cellular provider IPs are treated as external WAN threats
        if ip_obj in ipaddress.ip_network("100.64.0.0/10"):
            return False
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
            return True
    except ValueError:
        return True

    if norm.startswith("192.168.") or norm.startswith("10.") or norm.startswith("172.16.") or norm.startswith("172.17.") or norm.startswith("172.18.") or norm.startswith("172.19.") or norm.startswith("172.31."):
        return True

    if norm in PUBLIC_IPS:
        return True

    if ip_obj.version == 6 and IPV6_PREFIXES:
        for prefix_net in IPV6_PREFIXES:
            if ip_obj in prefix_net:
                return True

    return False

def get_signature_name_by_sid(sig_id):
    """Look up human-readable threat signature name by SID from rule files or recent memory."""
    try:
        sid_str = str(sig_id).strip()
        for threat in RECENT_THREATS:
            if str(threat.get("sig_id")) == sid_str and threat.get("signature"):
                return threat.get("signature")
                
        rule_paths = ["/var/lib/suricata/rules/suricata.rules", "/etc/suricata/rules/custom.rules"]
        for path in rule_paths:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if f"sid:{sid_str};" in line or f"sid:{sid_str} ;" in line:
                            match = re.search(r'msg:\"([^\"]+)\";', line)
                            if match:
                                return match.group(1)
    except Exception:
        pass
    return f"Signature SID {sig_id}"

def suppress_signature_in_suricata(sig_id, sig_name=None):
    """Dynamically append suppression rule to threshold.config with threat name comment, unblock target IP on MikroTik, and reload Suricata."""
    try:
        sig_id_int = int(sig_id)
        if not sig_name or sig_name == f"Signature SID {sig_id}":
            sig_name = get_signature_name_by_sid(sig_id_int)
            
        suppress_line = f"suppress gen_id 1, sig_id {sig_id_int}  # user: {sig_name}\n"
        existing = ""
        if os.path.exists(THRESHOLD_CONF_PATH):
            with open(THRESHOLD_CONF_PATH, "r") as f:
                existing = f.read()
                
        if f"sig_id {sig_id_int}" not in existing:
            with open(THRESHOLD_CONF_PATH, "a") as f:
                f.write(suppress_line)
            print(f"[SUPPRESS] Added signature {sig_id_int} ({sig_name}) to {THRESHOLD_CONF_PATH}", flush=True)
            
            if sig_id_int in LAST_TARGET_PER_SIG:
                target_ip = LAST_TARGET_PER_SIG[sig_id_int]
                is_v6 = ":" in target_ip
                unblock_on_mikrotik(target_ip, is_v6)
                
            os.system("suricatasc -c reload-rules || systemctl reload suricata.service")
            return True, sig_name
        else:
            return False, sig_name
    except Exception as e:
        print(f"Error suppressing signature {sig_id}: {e}", flush=True)
    return False, f"Signature SID {sig_id}"

def unsuppress_signature_in_suricata(sig_id):
    """Remove a suppression line from threshold.config and reload Suricata."""
    try:
        if os.path.exists(THRESHOLD_CONF_PATH):
            with open(THRESHOLD_CONF_PATH, "r") as f:
                lines = f.readlines()
            new_lines = [l for l in lines if f"sig_id {sig_id}" not in l]
            with open(THRESHOLD_CONF_PATH, "w") as f:
                f.writelines(new_lines)
            print(f"[UNSUPPRESS] Removed signature {sig_id} from {THRESHOLD_CONF_PATH}", flush=True)
            os.system("suricatasc -c reload-rules || systemctl reload suricata.service")
            return True
    except Exception as e:
        print(f"Error unsuppressing signature {sig_id}: {e}", flush=True)
    return False

def send_telegram_text(msg):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": msg,
        "parse_mode": "HTML"
    }
    try:
        res = requests.post(url, json=payload, timeout=5)
        print(f"[TELEGRAM_TEXT] status: {res.status_code} body: {res.text}", flush=True)
    except Exception as e:
        print(f"[TELEGRAM_TEXT] Failed to send text message: {e}", flush=True)

def send_telegram_alert(msg, sig_id, show_suppress_button=False):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": msg,
        "parse_mode": "HTML"
    }
    
    if show_suppress_button:
        payload["reply_markup"] = {
            "inline_keyboard": [
                [
                    {
                        "text": f"🔕 Suppress Rule SID {sig_id}",
                        "callback_data": f"suppress:{sig_id}"
                    }
                ]
            ]
        }
        
    try:
        res = requests.post(url, json=payload, timeout=5)
        print(f"[TELEGRAM] Sent alert (Button={show_suppress_button}) status: {res.status_code}", flush=True)
    except Exception as e:
        print(f"[TELEGRAM] Failed to send Telegram alert: {e}", flush=True)

def process_telegram_update(update):
    """Process a single push update from Telegram Webhook (button callbacks, /status, /blocks, /dashboard, /help)."""
    try:
        callback = update.get("callback_query")
        if callback:
            cb_id = callback.get("id")
            cb_data = callback.get("data", "")
            from_user = callback.get("from", {}).get("first_name", "Admin")
            
            if cb_data.startswith("suppress:"):
                sig_to_suppress = int(cb_data.split(":")[1])
                sig_name_preview = get_signature_name_by_sid(sig_to_suppress)
                safe_sig_name = html.escape(sig_name_preview)
                safe_from_user = html.escape(from_user)
                
                # 1. Answer callback toast INSTANTLY (<0.1s)
                ans_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/answerCallbackQuery"
                requests.post(ans_url, json={"callback_query_id": cb_id, "text": f"✅ Suppressed: {sig_name_preview[:100]}"}, timeout=3)
                
                # 2. Send Telegram Chat Confirmation Text INSTANTLY (<0.2s)
                log_msg = f"✅ <b>Rule Suppressed & Unblocked</b>\n\nUser <b>{safe_from_user}</b> permanently suppressed threat:\n<code>user: {safe_sig_name}</code> (SID <code>{sig_to_suppress}</code>) and unblocked target IP on MikroTik."
                send_telegram_text(log_msg)
                
                # 3. Perform file write, MikroTik unblock & Suricata reload in background worker
                Thread(target=suppress_signature_in_suricata, args=(sig_to_suppress, sig_name_preview), daemon=True).start()
                
        message = update.get("message")
        if message:
            text = message.get("text", "").strip()
            if text.startswith("/status"):
                pool = get_routeros_connection()
                mikrotik_ok = "🟢 Connected" if pool else "🔴 Disconnected"
                wan_v4 = IPV4_WAN_ADDRESS or "N/A"
                v6_pref = str(IPV6_PREFIXES[0]) if IPV6_PREFIXES else "N/A"
                status_msg = (
                    f"🛡️ <b>Suricata Sentinel Status</b>\n\n"
                    f"• <b>Suricata Engine:</b> 🟢 Active\n"
                    f"• <b>MikroTik API:</b> {mikrotik_ok}\n"
                    f"• <b>Public IPv4:</b> <code>{wan_v4}</code>\n"
                    f"• <b>IPv6 Subnet:</b> <code>{v6_pref}</code>\n"
                    f"• <b>Logged Threats:</b> {len(RECENT_THREATS)}"
                )
                send_telegram_text(status_msg)
            elif text.startswith("/blocks"):
                refresh_mikrotik_prefixes()
                b_list = []
                pool = get_routeros_connection()
                if pool:
                    try:
                        api = pool.get_api()
                        v4 = api.get_resource('/ip/firewall/address-list').get(list='Suricata-Blocked')
                        v6 = api.get_resource('/ipv6/firewall/address-list').get(list='Suricata-Blocked')
                        for i in v4 + v6:
                            b_list.append(f"• <code>{i.get('address')}</code>")
                    except Exception:
                        pass
                if b_list:
                    blocks_msg = f"🚫 <b>Active MikroTik Blocks ({len(b_list)}):</b>\n\n" + "\n".join(b_list)
                else:
                    blocks_msg = "✅ No IPs are currently blocked on MikroTik firewall."
                send_telegram_text(blocks_msg)
            elif text.startswith("/dashboard"):
                dash_msg = f"🖥️ <b>Web Command Center Dashboard</b>\n\nAccess Link: {DASHBOARD_URL}"
                send_telegram_text(dash_msg)
            elif text.startswith("/help") or text.startswith("/start"):
                help_msg = (
                    f"🤖 <b>Suricata Bot Commands</b>\n\n"
                    f"Freeform text messages are disabled.\n"
                    f"Use inline buttons or slash commands:\n\n"
                    f"/status - Check live Suricata daemon & MikroTik status\n"
                    f"/blocks - List active MikroTik blocked IP addresses\n"
                    f"/dashboard - Get link to local Web Command Center\n"
                    f"/help - Show this help menu"
                )
                send_telegram_text(help_msg)
            elif text.startswith("/"):
                send_telegram_text("⚠️ Unknown command. Type /help to see available bot commands.")
    except Exception as e:
        print(f"Error processing Telegram webhook update: {e}", flush=True)

def setup_telegram_webhook():
    """Register Webhook URL with Telegram Bot API."""
    webhook_url = f"{DASHBOARD_URL.rstrip('/')}/telegram-webhook"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/setWebhook?url={webhook_url}&secret_token={SURICATA_WEBHOOK_SECRET}"
    try:
        r = requests.get(url, timeout=5)
        print(f"[TELEGRAM_WEBHOOK] Registered webhook {webhook_url} status: {r.status_code} body: {r.text}", flush=True)
    except Exception as e:
        print(f"[TELEGRAM_WEBHOOK] Failed to set webhook: {e}", flush=True)

def block_on_mikrotik(ip, reason):
    global ROUTEROS_POOL
    if is_internal_or_whitelisted(ip):
        print(f"[WHITELIST] Ignored block for internal/whitelisted target: {ip}", flush=True)
        return False
        
    is_ipv6 = ":" in ip
    resource_path = '/ipv6/firewall/address-list' if is_ipv6 else '/ip/firewall/address-list'
    
    pool = get_routeros_connection()
    if not pool:
        print(f"Cannot block {ip}: RouterOS connection unavailable", flush=True)
        return False
        
    try:
        api = pool.get_api()
        address_list = api.get_resource(resource_path)
        
        existing = address_list.get(list='Suricata-Blocked', address=ip)
        if existing:
            print(f"[EXISTS] {ip} is already in 'Suricata-Blocked' ({resource_path})", flush=True)
        else:
            address_list.add(
                list='Suricata-Blocked',
                address=ip,
                timeout=BLOCK_TIMEOUT,
                comment=f"{reason[:60]}"
            )
            print(f"[BLOCKED] Successfully added {ip} to MikroTik 'Suricata-Blocked' list at {resource_path} (Timeout: {BLOCK_TIMEOUT})", flush=True)
        return True
    except Exception as e:
        print(f"Error blocking {ip} on MikroTik (reconnecting): {e}", flush=True)
        ROUTEROS_POOL = None
        return False

def unblock_on_mikrotik(ip, is_v6=False):
    global ROUTEROS_POOL
    pool = get_routeros_connection()
    if not pool:
        return False
    resource_path = '/ipv6/firewall/address-list' if is_v6 else '/ip/firewall/address-list'
    try:
        api = pool.get_api()
        res = api.get_resource(resource_path)
        items = res.get(list='Suricata-Blocked', address=ip)
        for item in items:
            res.remove(id=item['id'])
        print(f"[UNBLOCKED] Removed {ip} from MikroTik 'Suricata-Blocked' ({resource_path})", flush=True)
        return True
    except Exception as e:
        print(f"Error unblocking {ip} on MikroTik: {e}", flush=True)
        ROUTEROS_POOL = None
        return False

def follow_eve_log():
    if not os.path.exists(EVE_LOG_PATH):
        print(f"Waiting for {EVE_LOG_PATH}...", flush=True)
        while not os.path.exists(EVE_LOG_PATH):
            time.sleep(2)
            
    print(f"Tailing {EVE_LOG_PATH} for alerts...", flush=True)
    
    with open(EVE_LOG_PATH, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                event = json.loads(line.strip())
                if event.get("event_type") == "alert":
                    alert = event.get("alert", {})
                    src_ip = event.get("src_ip")
                    dest_ip = event.get("dest_ip")
                    src_port = event.get("src_port")
                    dest_port = event.get("dest_port")
                    signature = alert.get("signature", "Unknown Alert")
                    severity = alert.get("severity", 3)
                    sig_id = alert.get("signature_id")
                    category = alert.get("category", "")
                    flow = event.get("flow", {})
                    timestamp = event.get("timestamp", "").split('.')[0].replace('T', ' ')
                    
                    # Ignore Telegram API bot polling noise
                    if sig_id == 2033966 or "Telegram API" in signature:
                        continue

                    # Deduplicate identical consecutive alert events within RAW_EVENTS ring buffer (15-second window)
                    dedup_key = f"{sig_id}_{src_ip}_{dest_ip}"
                    now_ts = time.time()
                    is_duplicate = False
                    if RAW_EVENTS:
                        for existing_evt in RAW_EVENTS[:20]:
                            if existing_evt.get("dedup_key") == dedup_key and (now_ts - existing_evt.get("last_seen_ts", 0)) < 15:
                                existing_evt["count"] = existing_evt.get("count", 1) + 1
                                existing_evt["timestamp"] = timestamp
                                existing_evt["last_seen_ts"] = now_ts
                                is_duplicate = True
                                break

                    if not is_duplicate:
                        RAW_EVENTS.insert(0, {
                            "timestamp": timestamp,
                            "last_seen_ts": now_ts,
                            "dedup_key": dedup_key,
                            "severity": severity,
                            "signature": signature,
                            "sig_id": sig_id,
                            "category": category,
                            "src_ip": src_ip,
                            "dest_ip": dest_ip,
                            "src_port": src_port,
                            "dest_port": dest_port,
                            "proto": event.get("proto", ""),
                            "count": 1
                        })
                        if len(RAW_EVENTS) > 500:
                            RAW_EVENTS.pop()

                    # Filter stream decode noise out from high-priority Telegram alerts & MikroTik blocking
                    if signature.startswith("SURICATA STREAM") or signature.startswith("SURICATA UDP") or category == "Generic Protocol Command Decode":
                        continue

                    if severity > 2:
                        continue
                        
                    cache_key = f"{sig_id}_{src_ip}_{dest_ip}"
                    now = time.time()
                    if cache_key in ALERT_CACHE and (now - ALERT_CACHE[cache_key]) < COOLDOWN_SECONDS:
                        continue
                        
                    ALERT_CACHE[cache_key] = now
                    
                    ALERT_HISTORY[sig_id] = ALERT_HISTORY.get(sig_id, 0) + 1
                    repeat_count = ALERT_HISTORY[sig_id]
                    show_suppress_button = repeat_count >= 2
                    
                    flow_src_ip = flow.get("src_ip")
                    flow_dest_ip = flow.get("dest_ip")
                    
                    if flow_src_ip and is_internal_or_whitelisted(flow_src_ip) and not is_internal_or_whitelisted(flow_dest_ip):
                        lan_device_ip = flow_src_ip
                        target_ip = flow_dest_ip
                    elif flow_dest_ip and is_internal_or_whitelisted(flow_dest_ip) and not is_internal_or_whitelisted(flow_src_ip):
                        lan_device_ip = flow_dest_ip
                        target_ip = flow_src_ip
                    elif is_internal_or_whitelisted(src_ip) and not is_internal_or_whitelisted(dest_ip):
                        lan_device_ip = src_ip
                        target_ip = dest_ip
                    elif is_internal_or_whitelisted(dest_ip) and not is_internal_or_whitelisted(src_ip):
                        lan_device_ip = dest_ip
                        target_ip = src_ip
                    else:
                        lan_device_ip = dest_ip
                        target_ip = src_ip

                    # Read custom whitelist directly from disk to ensure immediate un-whitelisting
                    if is_custom_whitelisted(target_ip) or is_custom_whitelisted(src_ip) or is_custom_whitelisted(dest_ip):
                        print(f"[WHITELIST] Suppressed alert for whitelisted IP (src={src_ip}, dest={dest_ip}, target={target_ip})", flush=True)
                        continue

                    is_target_v6 = ":" in str(target_ip)
                    is_lan_v6 = ":" in str(lan_device_ip)
                    
                    if not is_lan_v6 and not is_target_v6:
                        if (lan_device_ip == IPV4_WAN_ADDRESS or not is_internal_or_whitelisted(lan_device_ip)):
                            resolved_lan = resolve_lan_ip_from_mikrotik(src_port, dest_port)
                            if resolved_lan:
                                lan_device_ip = resolved_lan
                            else:
                                lan_device_ip = f"{IPV4_WAN_ADDRESS} (NAT)"

                    if target_ip and sig_id:
                        LAST_TARGET_PER_SIG[sig_id] = target_ip

                    RECENT_THREATS.insert(0, {
                        "timestamp": timestamp,
                        "severity": severity,
                        "signature": signature,
                        "lan_ip": lan_device_ip,
                        "target_ip": target_ip,
                        "expire_time": now + COOLDOWN_SECONDS
                    })
                    if len(RECENT_THREATS) > 50:
                        RECENT_THREATS.pop()

                    severity_label = "🔴 HIGH (Malware / Exploit)" if severity == 1 else "🟡 MEDIUM (Attack / Intrusion)"
                    repeat_badge = f" <i>(Occurrence #{repeat_count})</i>" if repeat_count > 1 else ""
                    
                    is_will_block = bool(target_ip and not is_internal_or_whitelisted(target_ip))
                    target_label = f"🎯 <b>Blocked Target:</b> <code>{target_ip}</code>" if is_will_block else f"🎯 <b>Target:</b> <code>{target_ip}</code> <i>(Whitelisted - No Block)</i>"
                    action_label = "⏱️ <b>MikroTik Block Duration:</b> 1 Hour" if is_will_block else "🛡️ <b>Action:</b> Internal Host (Firewall Block Bypassed)"

                    safe_sig = signature.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    msg = (
                        f"🚨 <b>Suricata Threat Alert</b>{repeat_badge}\n\n"
                        f"📌 <b>Threat:</b> {safe_sig}\n"
                        f"🖥️ <b>LAN Device:</b> <code>{lan_device_ip}</code>\n"
                        f"{target_label}\n"
                        f"⚠️ <b>Severity:</b> {severity_label}\n"
                        f"{action_label}"
                    )
                    print(msg, flush=True)
                    send_telegram_alert(msg, sig_id, show_suppress_button=show_suppress_button)
                    
                    if is_will_block:
                        block_on_mikrotik(target_ip, f"Suricata: {signature}")
            except Exception as err:
                pass

# --- Flask Web Dashboard Routes ---
app = Flask(__name__, template_folder="/opt/suricata-mikrotik/templates", static_folder="/opt/suricata-mikrotik/static")
CORS(app)

@app.route("/telegram-webhook", methods=["POST"])
def telegram_webhook_route():
    incoming_secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if incoming_secret != SURICATA_WEBHOOK_SECRET:
        print(f"[SECURITY] Rejected unauthorized request to /telegram-webhook (Invalid Token)", flush=True)
        return jsonify({"error": "Unauthorized secret token"}), 403
        
    update = request.json or {}
    if update:
        Thread(target=process_telegram_update, args=(update,), daemon=True).start()
    return jsonify({"status": "ok"}), 200

@app.route("/nuc-bridge-webhook", methods=["POST"])
def nuc_bridge_webhook_route():
    incoming_secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if incoming_secret != NUC_BRIDGE_WEBHOOK_SECRET:
        print(f"[SECURITY] Rejected unauthorized request to /nuc-bridge-webhook (Invalid Token)", flush=True)
        return jsonify({"error": "Unauthorized secret token"}), 403
        
    try:
        headers = {k: v for k, v in request.headers if k.lower() != 'host'}
        r = requests.post("http://127.0.0.1:8889/nuc-bridge-webhook", data=request.get_data(), headers=headers, timeout=10)
        return (r.content, r.status_code, r.headers.items())
    except Exception as e:
        return jsonify({"error": f"NUC Bridge Webhook Proxy Error: {e}"}), 500

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status")
def api_status():
    refresh_mikrotik_prefixes()
    blocked_ips = []
    pool = get_routeros_connection()
    if pool:
        try:
            api = pool.get_api()
            v4 = api.get_resource('/ip/firewall/address-list').get(list='Suricata-Blocked')
            v6 = api.get_resource('/ipv6/firewall/address-list').get(list='Suricata-Blocked')
            for i in v4:
                blocked_ips.append({"address": i.get('address'), "comment": i.get('comment', ''), "is_v6": False})
            for i in v6:
                blocked_ips.append({"address": i.get('address'), "comment": i.get('comment', ''), "is_v6": True})
        except Exception:
            pass
            
    suppressed_rules = []
    if os.path.exists(THRESHOLD_CONF_PATH):
        with open(THRESHOLD_CONF_PATH, "r") as f:
            for line in f:
                if line.strip().startswith("suppress") and "sig_id" in line:
                    parts = line.strip().split("sig_id")
                    if len(parts) > 1:
                        sid_str = parts[1].strip().split()[0]
                        comment = line.split("#")[1].strip() if "#" in line else ""
                        if not comment or comment == "User Suppressed Rule":
                            comment = get_signature_name_by_sid(sid_str)
                        suppressed_rules.append({"sid": sid_str, "description": comment})

    ipv6_pool_str = str(IPV6_PREFIXES[0]) if IPV6_PREFIXES else "None"
    
    now = time.time()
    active_threats = [t for t in RECENT_THREATS if t.get("expire_time", 0) > now]
    
    targets, _ = load_custom_whitelist()

    suricata_active = os.system("systemctl is-active --quiet suricata.service") == 0

    return jsonify({
        "total_threats": len(RECENT_THREATS),
        "blocked_ips": blocked_ips,
        "whitelist_entries": sorted(list(targets)),
        "suppressed_rules": suppressed_rules,
        "recent_threats": active_threats[:15],
        "ipv4_wan": IPV4_WAN_ADDRESS or "None",
        "ipv6_prefix": ipv6_pool_str,
        "hostname": socket.gethostname(),
        "suricata_active": suricata_active
    })

@app.route("/api/suricata/start", methods=["POST"])
def api_suricata_start():
    """Start Suricata packet engine service without stopping the Web UI."""
    try:
        ret = os.system("systemctl start suricata.service")
        return jsonify({"success": ret == 0, "message": "Suricata service started" if ret == 0 else "Failed to start Suricata service"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/suricata/stop", methods=["POST"])
def api_suricata_stop():
    """Stop Suricata packet engine service without stopping the Web UI."""
    try:
        ret = os.system("systemctl stop suricata.service")
        return jsonify({"success": ret == 0, "message": "Suricata service stopped" if ret == 0 else "Failed to stop Suricata service"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/events")
def api_events():
    """Return raw alert events (including low severity) with selectable limit and search query."""
    try:
        limit = int(request.args.get("limit", 25))
    except ValueError:
        limit = 25
    limit = max(10, min(limit, 100))
    
    q = request.args.get("q", "").strip().lower()
    
    if q:
        filtered = []
        for e in RAW_EVENTS:
            searchable_str = f"{e.get('timestamp')} {e.get('signature')} {e.get('category')} {e.get('src_ip')} {e.get('dest_ip')} {e.get('sig_id')} {e.get('proto')}".lower()
            if q in searchable_str:
                filtered.append(e)
        return jsonify({"events": filtered[:limit], "total_in_memory": len(RAW_EVENTS)})
    
    return jsonify({"events": RAW_EVENTS[:limit], "total_in_memory": len(RAW_EVENTS)})

@app.route("/api/whitelist/add", methods=["POST"])
def api_whitelist_add():
    """Add an IP or FQDN domain to /etc/suricata/whitelist.config without touching MikroTik."""
    data = request.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"success": False, "message": "Target cannot be empty"}), 400
        
    resolved_ips = resolve_target_to_ips(target)
    if not resolved_ips:
        return jsonify({"success": False, "message": f"Could not resolve '{target}' to any valid IP address"}), 400
        
    try:
        existing = set()
        if os.path.exists(WHITELIST_CONF_PATH):
            with open(WHITELIST_CONF_PATH, "r") as f:
                for l in f:
                    if l.strip() and not l.startswith("#"):
                        existing.add(l.strip())
        if target not in existing:
            with open(WHITELIST_CONF_PATH, "a") as f:
                f.write(f"{target}\n")
                
        load_custom_whitelist()
        return jsonify({"success": True, "message": f"Added '{target}' to Suricata Whitelist."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error saving whitelist: {e}"}), 500

@app.route("/api/whitelist/remove", methods=["POST"])
def api_whitelist_remove():
    """Remove an IP or FQDN domain from /etc/suricata/whitelist.config."""
    data = request.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"success": False, "message": "Target cannot be empty"}), 400
        
    try:
        if os.path.exists(WHITELIST_CONF_PATH):
            with open(WHITELIST_CONF_PATH, "r") as f:
                lines = f.readlines()
            new_lines = [l for l in lines if l.strip() != target]
            with open(WHITELIST_CONF_PATH, "w") as f:
                f.writelines(new_lines)
        load_custom_whitelist()
        return jsonify({"success": True, "message": f"Removed '{target}' from Whitelist."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error removing whitelist: {e}"}), 500

@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.json or {}
    ip = data.get("ip")
    is_v6 = data.get("is_v6", False)
    if ip:
        success = unblock_on_mikrotik(ip, is_v6)
        return jsonify({"success": success})
    return jsonify({"success": False}), 400

@app.route("/api/unsuppress", methods=["POST"])
def api_unsuppress():
    data = request.json or {}
    sid = data.get("sid")
    if sid:
        success = unsuppress_signature_in_suricata(sid)
        return jsonify({"success": success})
    return jsonify({"success": False}), 400

def run_web_server():
    print(f"Starting Flask Security Dashboard on port {WEB_PORT}...", flush=True)
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False, use_reloader=False)

def background_maintenance_loop():
    """Periodic 30-second background worker: continuously verifies RouterOS packet sniffer status & WAN IPv6/IPv4 prefixes."""
    while True:
        try:
            refresh_mikrotik_prefixes()
        except Exception as e:
            print(f"Error in background maintenance loop: {e}", flush=True)
        time.sleep(30)

if __name__ == "__main__":
    print("Starting Suricata -> MikroTik & Telegram Integration Daemon...", flush=True)
    setup_telegram_webhook()
    t2 = Thread(target=run_web_server, daemon=True)
    t2.start()
    t3 = Thread(target=background_maintenance_loop, daemon=True)
    t3.start()
    follow_eve_log()

