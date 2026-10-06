import scapy.all as scapy
import numpy as np
import pandas as pd
import joblib
import time
from threading import Thread, Timer
import psycopg2

# --- LOAD MODELS ---
# Using the multi-class model and encoders for SentinelAI
model = joblib.load("model/ids_multi_model.pkl")
scaler = joblib.load("model/scaler.pkl")
encoders = joblib.load("model/encoders.pkl")
target_encoder = joblib.load("model/target_encoder.pkl")
feature_means = joblib.load("model/feature_means.pkl")

# --- DB CONFIG ---
DB_CONFIG = {
    "dbname": "sentinel_db",
    "user": "postgres",
    "password": "NIDS2026",
    "host": "localhost",
    "port": "5432"
}

# --- FLOW STORAGE ---
flows = {}
FLOW_TIMEOUT = 2  # Seconds to wait before processing a flow session

# --- SERVICE MAPPING ---
def get_service(port, proto):
    if port == 80: return "http"
    elif port == 443: return "https_quic" if proto == 17 else "https"
    elif port == 53: return "dns"
    elif port == 21: return "ftp"
    elif port == 22: return "ssh"
    elif port == 25: return "smtp"
    elif port == 110: return "pop3"
    elif port == 143: return "imap"
    elif port == 3306: return "mysql"
    elif port == 0: return "icmp"
    return "private"

# --- SAVE TO DB ---
def save_to_db(data):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO logs 
            (protocol, service, flag, src_bytes, dst_bytes, count, result, probability, source_ip, timestamp)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
        """, data)
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print("DB Error:", e)

# --- PROCESS FLOW ---
def process_flow(flow_id, flow):
    try:
        src_ip, dst_ip, proto = flow_id
        proto_map = {
            1: "icmp",
            2: "igmp",
            6: "tcp",
            17: "udp",
            58: "icmpv6"
        }
        proto_name = proto_map.get(proto, "other")

        sport, dport = flow["sport"], flow["dport"]
        
        # Service detection logic based on well-known ports
        if proto in [1, 58]:
            service = "icmp"
        else:
            port = dport if dport < 1024 else sport
            service = get_service(port, proto)

        src_bytes = flow["src_bytes"]
        dst_bytes = flow["dst_bytes"]
        count = flow["count"]

        # --- ENCODING ---
        try:
            enc_proto = encoders['protocol_type'].transform([proto_name])[0]
            enc_srv = encoders['service'].transform([service])[0]
            enc_flg = encoders['flag'].transform(["SF"])[0]
        except:
            enc_proto, enc_srv, enc_flg = 0, 0, 0

        # --- FEATURE VECTOR ALIGNMENT ---
        input_data = feature_means.copy()
        input_data[0] = flow["duration"]
        input_data[1] = enc_proto
        input_data[2] = enc_srv
        input_data[3] = enc_flg
        input_data[4] = src_bytes
        input_data[5] = dst_bytes
        if len(input_data) > 22:
            input_data[22] = count

        # --- PREDICTION ---
       

        df = pd.DataFrame(
            [input_data],
            columns=scaler.feature_names_in_
        )

        features = scaler.transform(df)
        probs = model.predict_proba(features)[0]
        classes = list(target_encoder.classes_)
        normal_idx = classes.index("Normal")

        if probs[normal_idx] >= 0.5:
            result, prob = "Normal", probs[normal_idx]
        else:
            probs[normal_idx] = 0
            idx = np.argmax(probs)
            result, prob = classes[idx], probs[idx]

        # --- CONSOLE OUTPUT ---
        icon = "✅" if result == "Normal" else "🚨"
        print(f"{icon} {src_ip} → {dst_ip} | {proto_name.upper()} | {service.upper()} | Src:{src_bytes} Dst:{dst_bytes} | Cnt:{count} | Conf:{round(prob * 100, 1)}%")

        # --- ASYNC DB SAVE ---
        db_data = (proto_name, service, "SF", int(src_bytes), int(dst_bytes), int(count), result, float(prob), src_ip)
        Thread(target=save_to_db, args=(db_data,)).start()

    except Exception as e:
        print("Flow analysis error:", e)

# --- BACKGROUND CLEANUP ---
def cleanup_expired_flows():
    """Background thread to process completed sessions and free memory."""
    current_time = time.time()
    expired = []

    # Identify flows that haven't seen a packet in FLOW_TIMEOUT seconds
    for fid, flow in list(flows.items()):
        if (current_time - flow["last_seen"] > FLOW_TIMEOUT or flow["count"] >= 10):
            flow["duration"] = current_time - flow["start_time"]
            process_flow(fid, flow)
            expired.append(fid)

    for fid in expired:
        if fid in flows:
            del flows[fid]
    
    # Schedule next cleanup
    Timer(5.0, cleanup_expired_flows).start()

# --- PACKET HANDLER ---
def process_packet(packet):
    try:
        if not packet.haslayer(scapy.IP):
            return

        ip = packet[scapy.IP]
        proto, src_ip, dst_ip = ip.proto, ip.src, ip.dst
        sport, dport = 0, 0

        if packet.haslayer(scapy.TCP):
            sport, dport = packet[scapy.TCP].sport, packet[scapy.TCP].dport
        elif packet.haslayer(scapy.UDP):
            sport, dport = packet[scapy.UDP].sport, packet[scapy.UDP].dport

        # Unique IDs for Bidirectional Tracking
        flow_id = (src_ip, dst_ip, proto)
        reverse_id = (dst_ip, src_ip, proto)
        pkt_len = len(packet)

        # Update or Create Flow
        if flow_id not in flows:
            flows[flow_id] = {
                "src_bytes": 0, "dst_bytes": 0, "count": 0,
                "sport": sport, "dport": dport,
                "start_time": time.time(), "last_seen": time.time()
            }

        flows[flow_id]["src_bytes"] += pkt_len
        flows[flow_id]["count"] += 1
        flows[flow_id]["last_seen"] = time.time()

        # If a reverse flow exists, add these bytes to its Destination field
        if reverse_id in flows:
            flows[reverse_id]["dst_bytes"] += pkt_len

    except Exception as e:
        pass # Ignore malformed packets

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    print("🚀 SentinelAI: Autonomous Mitigation Engine Starting...")
    print("Capturing flows on interface: Wi-Fi")
    
    # Start the periodic cleanup thread
    cleanup_expired_flows()

    # Begin sniffing
    # Begin sniffing
    scapy.sniff(
        iface="Wi-Fi",  # <--- Change this string
        filter="ip",
        prn=process_packet,
        store=False,
        promisc=True
    )