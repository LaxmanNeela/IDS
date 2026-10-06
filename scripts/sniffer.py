import scapy.all as scapy
import numpy as np
import joblib
import psycopg2
from psycopg2 import pool
from datetime import datetime
import time
from threading import Thread

# --- LOAD MODELS ---
model = joblib.load("model/ids_multi_model.pkl")
scaler = joblib.load("model/scaler.pkl")
encoders = joblib.load("model/encoders.pkl")
target_encoder = joblib.load("model/target_encoder.pkl")
feature_means = joblib.load("model/feature_means.pkl")

# --- DB CONFIG ---
DB_CONFIG = {
    "dbname": "sentinel_db",   # ✅ SAME as Flask
    "user": "postgres",
    "password": "NIDS2026",
    "host": "localhost",
    "port": "5432"
}

db_pool = psycopg2.pool.SimpleConnectionPool(1, 20, **DB_CONFIG)

connection_tracker = {}
connection_time = {}

# --- INIT DB ---
def init_db():
    conn = db_pool.getconn()
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                protocol TEXT,
                service TEXT,
                flag TEXT,
                src_bytes INTEGER,
                dst_bytes INTEGER,
                count INTEGER,
                result TEXT,
                probability REAL,
                source_ip TEXT,
                timestamp TIMESTAMP
            )
        """)
        conn.commit()
        cur.close()
    finally:
        db_pool.putconn(conn)

# --- FEATURE EXTRACTION ---
def get_packet_features(packet):
    try:
        proto, service, flag = "tcp", "other", "SF"
        src_bytes, dst_bytes, src_ip = 0, 0, "0.0.0.0"

        if packet.haslayer(scapy.IP):
            ip = packet[scapy.IP]
            src_ip = ip.src
            src_bytes = ip.len

            if ip.proto == 6:
                proto = "tcp"
            elif ip.proto == 17:
                proto = "udp"
            elif ip.proto == 1:
                proto = "icmp"

        if packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            f = tcp.flags

            if f == 0x02:
                flag = "S0"
            elif f == 0x12:
                flag = "SF"
            elif f == 0x04:
                flag = "REJ"
            else:
                flag = "OTH"

            port = tcp.sport if tcp.sport < 1024 else tcp.dport

        elif packet.haslayer(scapy.UDP):
            udp = packet[scapy.UDP]
            port = udp.sport if udp.sport < 1024 else udp.dport
        else:
            port = 0

        services_map = {80: "http", 443: "http_443", 21: "ftp", 22: "ssh", 53: "domain"}
        service = services_map.get(port, "private")

        if packet.haslayer(scapy.Raw):
            dst_bytes = len(packet[scapy.Raw].load)

        # --- COUNT ---
        key = (src_ip, proto)
        now = time.time()

        if key not in connection_time or now - connection_time[key] > 2:
            connection_tracker[key] = 0

        connection_tracker[key] += 1
        connection_time[key] = now
        count = connection_tracker[key]

        # --- ENCODING ---
        try:
            enc_proto = encoders['protocol_type'].transform([proto])[0]
            enc_srv = encoders['service'].transform([service])[0]
            enc_flg = encoders['flag'].transform([flag])[0]
        except:
            enc_proto, enc_srv, enc_flg = 0, 0, 0

        # --- FEATURE VECTOR ---
        input_data = feature_means.copy()
        input_data[0] = 0
        input_data[1] = enc_proto
        input_data[2] = enc_srv
        input_data[3] = enc_flg
        input_data[4] = src_bytes
        input_data[5] = dst_bytes

        if len(input_data) > 22:
            input_data[22] = count

        # --- MODEL ---
        features = scaler.transform(input_data.reshape(1, -1))
        probs = model.predict_proba(features)[0]

        classes = list(target_encoder.classes_)
        normal_idx = classes.index("Normal")

        if probs[normal_idx] >= 0.5:
            result_text = "Normal"
            final_prob = probs[normal_idx]
        else:
            attack_probs = probs.copy()
            attack_probs[normal_idx] = 0
            idx = np.argmax(attack_probs)
            result_text = classes[idx]
            final_prob = attack_probs[idx]

        # --- DOS RULE ---
        if count > 100:
            result_text = "DoS"
            final_prob = 0.99

        return (
            proto,
            service,
            flag,
            int(src_bytes),
            int(dst_bytes),
            int(count),
            result_text,
            float(final_prob),
            src_ip
        )

    except Exception as e:
        print("❌ ERROR:", e)
        return None


# --- SAVE ---
def save_to_db(data):
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO logs (protocol, service, flag, src_bytes, dst_bytes, count, result, probability, source_ip, timestamp)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (*data, datetime.now()))

        conn.commit()
        cur.close()
    except Exception as e:
        print("❌ DB ERROR:", e)
    finally:
        if conn:
            db_pool.putconn(conn)


def process_packet(packet):
    result = get_packet_features(packet)

    if result:
        proto, srv, flg, s_b, d_b, cnt, res, prob, ip = result

        icon = "✅" if res == "Normal" else "🚨"

        print(f"{icon} [{datetime.now().strftime('%H:%M:%S')}] {ip} | {res} ({round(prob*100,1)}%) | Count:{cnt}")

        Thread(target=save_to_db, args=(result,)).start()


# --- START ---
if __name__ == "__main__":
    init_db()

    print("🚀 Sniffer Started...")
    print("Generating traffic (ping google.com)...")

    scapy.sniff(
        filter="ip",
        iface="Wi-Fi",   # ⚠️ change if needed
        prn=process_packet,
        store=False
    )