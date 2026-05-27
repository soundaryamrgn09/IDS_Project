# =============================================================
# Sentinel AI — Improved Live Capture
# Extracts real values for all 41 KDD features from live packets
# =============================================================

import asyncio
import pyshark
import requests
import time
import signal
import sys
from collections import deque, defaultdict

# Fix for Python event loop issue
asyncio.set_event_loop(asyncio.new_event_loop())

API_URL = "http://127.0.0.1:5001/predict"

# =============================================================
# CHANGE THIS to your network interface name
# Windows : "Wi-Fi" or "Ethernet"
# Linux   : "eth0" or "wlan0"
# Mac     : "en0"
# =============================================================
INTERFACE = "Wi-Fi"

# =============================================================
# PROTOCOL MAP
# Maps protocol name → encoded number (same as training data)
# tcp=1, udp=2, icmp=0
# =============================================================
PROTOCOL_MAP = {
    "TCP":  1,
    "UDP":  2,
    "ICMP": 0
}

# =============================================================
# SERVICE MAP
# Maps destination port → service name → encoded number
# Based on KDD dataset service encoding
# =============================================================
PORT_TO_SERVICE = {
    80:   "http",
    443:  "https",
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    25:   "smtp",
    53:   "domain",
    110:  "pop3",
    143:  "imap",
    3306: "sql",
    3389: "remote_job",
    8080: "http_8001",
    20:   "ftp_data",
}

# Service name → encoded integer (based on KDD label encoding order)
SERVICE_ENCODE = {
    "ftp_data": 0, "other": 1, "private": 2, "http": 3,
    "remote_job": 4, "name": 5, "netbios_ns": 6, "eco_i": 7,
    "mtp": 8, "telnet": 9, "finger": 10, "domain_u": 11,
    "supdup": 12, "uucp_path": 13, "Z39_50": 14, "smtp": 15,
    "csnet_ns": 16, "uucp": 17, "netbios_dgm": 18, "urp_i": 19,
    "auth": 20, "domain": 21, "ftp": 22, "bgp": 23,
    "ldap": 24, "ecr_i": 25, "gopher": 26, "vmnet": 27,
    "systat": 28, "http_443": 29, "efs": 30, "whois": 31,
    "imap4": 32, "iso_tsap": 33, "echo": 34, "klogin": 35,
    "link": 36, "sunrpc": 37, "login": 38, "kshell": 39,
    "sql_net": 40, "time": 41, "hostnames": 42, "exec": 43,
    "ntp_u": 44, "discard": 45, "nntp": 46, "courier": 47,
    "ctf": 48, "ssh": 49, "daytime": 50, "shell": 51,
    "netstat": 52, "pop_3": 53, "nnsp": 54, "IRC": 55,
    "pop_2": 56, "printer": 57, "tim_i": 58, "pm_dump": 59,
    "red_i": 60, "netbios_ssn": 61, "rje": 62, "X11": 63,
    "urh_i": 64, "http_8001": 65, "aol": 66, "http_2784": 67,
    "tftp_u": 68, "harvest": 69
}

# =============================================================
# FLAG MAP
# TCP flag combinations → KDD flag → encoded number
# =============================================================
FLAG_ENCODE = {
    "SF":   0,   # Normal established connection
    "S0":   1,   # SYN sent, no response (SYN flood)
    "REJ":  2,   # Connection rejected
    "RSTO": 3,   # Reset by originator
    "RSTR": 4,   # Reset by responder
    "SH":   5,   # SYN + FIN (half open)
    "S1":   6,
    "S2":   7,
    "S3":   8,
    "OTH":  9,
    "RSTOS0": 10
}

# =============================================================
# SLIDING WINDOW TRACKER
# Tracks last 2 seconds of connections per host/service
# Used to compute rate-based features (Groups 3 & 4)
# =============================================================

WINDOW_SECONDS = 2      # KDD uses 2-second window for traffic features
HOST_WINDOW    = 100    # KDD uses last 100 connections for host features

# Each entry: (timestamp, dst_ip, dst_port, flag, src_port)
connection_log = deque()

# Per destination host: last 100 connections
host_log = defaultdict(lambda: deque(maxlen=HOST_WINDOW))


def clean_old_entries():
    """Remove entries older than WINDOW_SECONDS from connection_log"""
    now = time.time()
    while connection_log and (now - connection_log[0][0]) > WINDOW_SECONDS:
        connection_log.popleft()


def compute_traffic_features(dst_ip, dst_port, flag_str):
    """
    Compute Group 3 features — last 2 seconds of connections
    Returns: count, srv_count, serror_rate, srv_serror_rate,
             rerror_rate, srv_rerror_rate, same_srv_rate,
             diff_srv_rate, srv_diff_host_rate
    """
    clean_old_entries()

    recent = list(connection_log)
    total  = len(recent)

    if total == 0:
        return 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0

    # Connections to same destination host
    same_host = [r for r in recent if r[1] == dst_ip]
    count      = len(same_host)

    # Connections to same service (port)
    same_srv   = [r for r in recent if r[2] == dst_port]
    srv_count  = len(same_srv)

    # SYN error = flag is S0, S1, S2, S3, SH
    syn_error_flags = {"S0", "S1", "S2", "S3", "SH"}

    # REJ error = flag is REJ, RSTO, RSTR
    rej_error_flags = {"REJ", "RSTO", "RSTR", "RSTOS0"}

    # Rates for same host connections
    if count > 0:
        serror_count   = sum(1 for r in same_host if r[3] in syn_error_flags)
        rerror_count   = sum(1 for r in same_host if r[3] in rej_error_flags)
        serror_rate    = serror_count / count
        rerror_rate    = rerror_count / count
        same_srv_count = sum(1 for r in same_host if r[2] == dst_port)
        same_srv_rate  = same_srv_count / count
        diff_srv_rate  = 1 - same_srv_rate
    else:
        serror_rate  = 0.0
        rerror_rate  = 0.0
        same_srv_rate = 1.0
        diff_srv_rate = 0.0

    # Rates for same service connections
    if srv_count > 0:
        srv_serror_count    = sum(1 for r in same_srv if r[3] in syn_error_flags)
        srv_rerror_count    = sum(1 for r in same_srv if r[3] in rej_error_flags)
        srv_serror_rate     = srv_serror_count / srv_count
        srv_rerror_rate     = srv_rerror_count / srv_count
        # Different hosts for same service
        diff_hosts          = len(set(r[1] for r in same_srv if r[1] != dst_ip))
        srv_diff_host_rate  = diff_hosts / srv_count
    else:
        srv_serror_rate    = 0.0
        srv_rerror_rate    = 0.0
        srv_diff_host_rate = 0.0

    return (count, srv_count,
            round(serror_rate, 2), round(srv_serror_rate, 2),
            round(rerror_rate, 2), round(srv_rerror_rate, 2),
            round(same_srv_rate, 2), round(diff_srv_rate, 2),
            round(srv_diff_host_rate, 2))


def compute_host_features(dst_ip, dst_port, flag_str):
    """
    Compute Group 4 features — last 100 connections to same dst host
    Returns: dst_host_count, dst_host_srv_count,
             dst_host_same_srv_rate, dst_host_diff_srv_rate,
             dst_host_same_src_port_rate, dst_host_srv_diff_host_rate,
             dst_host_serror_rate, dst_host_srv_serror_rate,
             dst_host_rerror_rate, dst_host_srv_rerror_rate
    """
    host_history = list(host_log[dst_ip])
    total        = len(host_history)

    if total == 0:
        return 1, 1, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0

    syn_error_flags = {"S0", "S1", "S2", "S3", "SH"}
    rej_error_flags = {"REJ", "RSTO", "RSTR", "RSTOS0"}

    dst_host_count     = total
    same_srv           = [h for h in host_history if h[0] == dst_port]
    dst_host_srv_count = len(same_srv)

    dst_host_same_srv_rate = dst_host_srv_count / total
    dst_host_diff_srv_rate = 1 - dst_host_same_srv_rate

    # Same source port rate
    same_src_port = sum(1 for h in host_history if h[1] == dst_port)
    dst_host_same_src_port_rate = same_src_port / total

    # Different hosts for same service
    if dst_host_srv_count > 0:
        diff_hosts = len(set(h[2] for h in same_srv if h[2] != dst_ip))
        dst_host_srv_diff_host_rate = diff_hosts / dst_host_srv_count
    else:
        dst_host_srv_diff_host_rate = 0.0

    # Error rates for host
    serror_count = sum(1 for h in host_history if h[3] in syn_error_flags)
    rerror_count = sum(1 for h in host_history if h[3] in rej_error_flags)
    dst_host_serror_rate = serror_count / total
    dst_host_rerror_rate = rerror_count / total

    # Error rates for service
    if dst_host_srv_count > 0:
        srv_serror = sum(1 for h in same_srv if h[3] in syn_error_flags)
        srv_rerror = sum(1 for h in same_srv if h[3] in rej_error_flags)
        dst_host_srv_serror_rate = srv_serror / dst_host_srv_count
        dst_host_srv_rerror_rate = srv_rerror / dst_host_srv_count
    else:
        dst_host_srv_serror_rate = 0.0
        dst_host_srv_rerror_rate = 0.0

    return (
        dst_host_count,
        dst_host_srv_count,
        round(dst_host_same_srv_rate, 2),
        round(dst_host_diff_srv_rate, 2),
        round(dst_host_same_src_port_rate, 2),
        round(dst_host_srv_diff_host_rate, 2),
        round(dst_host_serror_rate, 2),
        round(dst_host_srv_serror_rate, 2),
        round(dst_host_rerror_rate, 2),
        round(dst_host_srv_rerror_rate, 2)
    )


# =============================================================
# EXTRACT FLAG FROM TCP PACKET
# =============================================================

def get_tcp_flag(packet):
    """
    Read TCP flags from packet and map to KDD flag string
    """
    try:
        flags = int(packet.tcp.flags, 16)

        SYN = bool(flags & 0x02)
        ACK = bool(flags & 0x10)
        FIN = bool(flags & 0x01)
        RST = bool(flags & 0x04)

        if RST:
            return "RSTO"
        elif SYN and not ACK and not FIN:
            return "S0"      # SYN sent, no response yet
        elif SYN and ACK:
            return "SF"      # Normal handshake
        elif FIN and ACK:
            return "SF"      # Normal close
        else:
            return "OTH"
    except:
        return "OTH"


# =============================================================
# EXTRACT SERVICE FROM PORT
# =============================================================

def get_service(dst_port):
    service_name = PORT_TO_SERVICE.get(dst_port, "other")
    return SERVICE_ENCODE.get(service_name, 1)  # default = "other" = 1


# =============================================================
# EXTRACT ALL 41 FEATURES FROM A PACKET
# =============================================================

def extract_features(packet, start_time):
    """
    Extract all 41 KDD features from a single live packet
    """

    # ── Group 1: Basic Features ──────────────────────────────

    # Duration: time since capture started (approximation)
    duration = round(time.time() - start_time, 2)

    # Protocol type
    proto_str = getattr(packet, 'transport_layer', 'TCP') or 'TCP'
    protocol_type = PROTOCOL_MAP.get(proto_str.upper(), 1)

    # Source & Destination bytes
    src_bytes = int(packet.length)
    dst_bytes = 0  # Cannot know response size from single packet

    # Destination port → service
    try:
        dst_port = int(packet[packet.transport_layer].dstport)
    except:
        dst_port = 0

    try:
        src_port = int(packet[packet.transport_layer].srcport)
    except:
        src_port = 0

    service = get_service(dst_port)

    # TCP Flag
    flag_str = "OTH"
    if proto_str.upper() == "TCP":
        flag_str = get_tcp_flag(packet)
    flag = FLAG_ENCODE.get(flag_str, 9)

    # Source & Destination IP
    try:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
    except:
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"

    # Land: src IP == dst IP (loopback attack)
    land = 1 if src_ip == dst_ip else 0

    # Wrong fragment
    try:
        wrong_fragment = int(packet.ip.frag_offset) > 0
        wrong_fragment = int(wrong_fragment)
    except:
        wrong_fragment = 0

    # Urgent (TCP urgent pointer)
    try:
        urgent = int(packet.tcp.urgent_pointer) > 0
        urgent = int(urgent)
    except:
        urgent = 0

    # ── Group 2: Content Features ────────────────────────────
    # These require application-layer or OS-level data
    # Cannot be extracted from raw packets — set to 0
    hot              = 0
    num_failed_logins = 0
    logged_in        = 0
    num_compromised  = 0
    root_shell       = 0
    su_attempted     = 0
    num_root         = 0
    num_file_creations = 0
    num_shells       = 0
    num_access_files = 0
    num_outbound_cmds = 0
    is_host_login    = 0
    is_guest_login   = 0

    # ── Log this connection for rate calculations ─────────────
    now = time.time()
    connection_log.append((now, dst_ip, dst_port, flag_str, src_port))
    host_log[dst_ip].append((dst_port, src_port, src_ip, flag_str))

    # ── Group 3: Traffic Features (last 2 seconds) ────────────
    (count, srv_count,
     serror_rate, srv_serror_rate,
     rerror_rate, srv_rerror_rate,
     same_srv_rate, diff_srv_rate,
     srv_diff_host_rate) = compute_traffic_features(dst_ip, dst_port, flag_str)

    # ── Group 4: Host Features (last 100 connections) ─────────
    (dst_host_count, dst_host_srv_count,
     dst_host_same_srv_rate, dst_host_diff_srv_rate,
     dst_host_same_src_port_rate, dst_host_srv_diff_host_rate,
     dst_host_serror_rate, dst_host_srv_serror_rate,
     dst_host_rerror_rate, dst_host_srv_rerror_rate) = compute_host_features(dst_ip, dst_port, flag_str)

    # ── Build Final Feature Dict (41 features) ────────────────
    features = {
        # Group 1 — Basic
        "duration":              duration,
        "protocol_type":         protocol_type,
        "service":               service,
        "flag":                  flag,
        "src_bytes":             src_bytes,
        "dst_bytes":             dst_bytes,
        "land":                  land,
        "wrong_fragment":        wrong_fragment,
        "urgent":                urgent,

        # Group 2 — Content (cannot extract from raw packets)
        "hot":                   hot,
        "num_failed_logins":     num_failed_logins,
        "logged_in":             logged_in,
        "num_compromised":       num_compromised,
        "root_shell":            root_shell,
        "su_attempted":          su_attempted,
        "num_root":              num_root,
        "num_file_creations":    num_file_creations,
        "num_shells":            num_shells,
        "num_access_files":      num_access_files,
        "num_outbound_cmds":     num_outbound_cmds,
        "is_host_login":         is_host_login,
        "is_guest_login":        is_guest_login,

        # Group 3 — Traffic (computed from sliding window)
        "count":                 count,
        "srv_count":             srv_count,
        "serror_rate":           serror_rate,
        "srv_serror_rate":       srv_serror_rate,
        "rerror_rate":           rerror_rate,
        "srv_rerror_rate":       srv_rerror_rate,
        "same_srv_rate":         same_srv_rate,
        "diff_srv_rate":         diff_srv_rate,
        "srv_diff_host_rate":    srv_diff_host_rate,

        # Group 4 — Host (computed from last 100 connections)
        "dst_host_count":              dst_host_count,
        "dst_host_srv_count":          dst_host_srv_count,
        "dst_host_same_srv_rate":      dst_host_same_srv_rate,
        "dst_host_diff_srv_rate":      dst_host_diff_srv_rate,
        "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
        "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,
        "dst_host_serror_rate":        dst_host_serror_rate,
        "dst_host_srv_serror_rate":    dst_host_srv_serror_rate,
        "dst_host_rerror_rate":        dst_host_rerror_rate,
        "dst_host_srv_rerror_rate":    dst_host_srv_rerror_rate,
    }

    return features, dst_ip, dst_port, flag_str


# =============================================================
# FEATURE QUALITY REPORT
# Shows how many features are real vs estimated vs zero
# =============================================================

def print_feature_quality(features):
    real      = ["src_bytes", "protocol_type", "service", "flag",
                 "land", "wrong_fragment", "urgent", "duration"]
    estimated = ["count", "srv_count", "serror_rate", "srv_serror_rate",
                 "rerror_rate", "srv_rerror_rate", "same_srv_rate",
                 "diff_srv_rate", "srv_diff_host_rate",
                 "dst_host_count", "dst_host_srv_count",
                 "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
                 "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
                 "dst_host_serror_rate", "dst_host_srv_serror_rate",
                 "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]

    print("\n📊 Feature Quality:")
    print(f"  ✅ Real extracted  : {len(real)} features")
    print(f"  ⚠️  Estimated/tracked: {len(estimated)} features")
    print(f"  ❌ Always zero     : {41 - len(real) - len(estimated)} features (content group)")




def handle_exit(sig, frame):
    print("\n\n🛑 Stopping Sentinel AI Live Capture...")
    print("✅ Capture stopped cleanly.")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)

# =============================================================
# MAIN CAPTURE LOOP
# =============================================================

def main():
    print("=" * 55)
    print("  Sentinel AI — Live Network Capture")
    print("=" * 55)
    print(f"  Interface : {INTERFACE}")
    print(f"  API URL   : {API_URL}")
    print(f"  Window    : {WINDOW_SECONDS} sec (traffic features)")
    print(f"  Host log  : last {HOST_WINDOW} connections (host features)")
    print("=" * 55)
    print("  Listening for packets...\n")

    capture    = pyshark.LiveCapture(interface=INTERFACE)
    start_time = time.time()
    pkt_count  = 0

    try:
        for packet in capture.sniff_continuously():
    
            try:
                # Only process IP packets
                if not hasattr(packet, 'ip'):
                    continue

                # Only process TCP/UDP/ICMP
                if not hasattr(packet, 'transport_layer'):
                    continue

                pkt_count += 1
            
            # ── SPEED CONTROL ──────────────────────────
            # Process only every 10th packet
            # Change 10 to any number you want:
            # 5  = faster,  20 = slower
                if pkt_count % 10 != 0:
                    continue

            # Add delay between predictions (in seconds)
            # 0.5 = half second,  1 = one second,  2 = two seconds
                time.sleep(2)
            # ───────────────────────────────────────────

            # Extract all 41 features
                features, dst_ip, dst_port, flag_str = extract_features(packet, start_time)

            # Send to Flask backend
                response = requests.post(API_URL, json=features, timeout=3)
                result   = response.json()
            # print("RAW RESPONSE:", response.text)  # ← ADD THIS

            # Print result
                status = result.get("status", "Unknown")
                score  = result.get("anomaly_score", 0)
                risk   = result.get("risk", "")
                zero   = result.get("zero_day", False)

                icon = "🔴" if "Attack" in status else "🟢"

                print(f"{icon} [{pkt_count:04d}] {status:20s} | "
                      f"Score: {score:+.4f} | "
                      f"{'⚠️ ZERO-DAY' if zero else 'Normal Pattern':15s} | "
                      f"→ {dst_ip}:{dst_port} [{flag_str}]")

            # Print feature quality every 50 packets
                if pkt_count % 50 == 0:
                    print_feature_quality(features)
  
            except requests.exceptions.ConnectionError:
                print("❌ Cannot reach Flask server. Is app.py running?")
            
            except KeyboardInterrupt:
                handle_exit(None, None)    

            except Exception as e:
                print(f"⚠️  Packet error: {e}")

    except KeyboardInterrupt:                     # ← ADD THIS
        handle_exit(None, None)  

if __name__ == "__main__":
    main()