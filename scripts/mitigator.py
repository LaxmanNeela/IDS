import psycopg2
from psycopg2 import pool
import subprocess
import time
import platform
import signal
import sys
import ipaddress
from datetime import datetime

# --- CONFIG ---
DB_CONFIG = {
    "dbname": "sentinel_db",
    "user": "postgres",
    "password": "NIDS2026", 
    "host": "localhost",
    "port": "5432"
}

WHITELIST = ["127.0.0.1", "0.0.0.0", "192.168.1.1"]

CONFIDENCE_THRESHOLD = 0.85
ATTACK_THRESHOLD = 3
UNBLOCK_AFTER = 300       # seconds
COOLDOWN_TIME = 60        # prevent re-block spam
ATTACK_RESET_TIME = 10    # reset counter window

# --- STATE ---
blocked_ips = set()
attack_counter = {}
attack_time = {}
block_time = {}
last_block_time = {}

# --- DB POOL ---
db_pool = psycopg2.pool.SimpleConnectionPool(1, 5, **DB_CONFIG)

# --- VALIDATE IP ---
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

# --- INIT DB ---
def init_db():
    conn = db_pool.getconn()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS mitigation_logs (
            id SERIAL PRIMARY KEY,
            ip TEXT,
            action TEXT,
            timestamp TIMESTAMP
        )
    """)

    conn.commit()
    cur.close()
    db_pool.putconn(conn)

# --- LOG ACTION ---
def log_action(ip, action):
    conn = None
    try:
        conn = db_pool.getconn()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO mitigation_logs (ip, action, timestamp)
            VALUES (%s, %s, %s)
        """, (ip, action, datetime.now()))

        conn.commit()
        cur.close()
    except Exception as e:
        print(f"❌ Log Error: {e}")
    finally:
        if conn:
            db_pool.putconn(conn)

# --- BLOCK IP ---
def block_ip_windows(ip):
    if not is_valid_ip(ip):
        print(f"⚠️ Invalid IP skipped: {ip}")
        return False

    if ip in WHITELIST:
        print(f"ℹ️ Whitelisted IP skipped: {ip}")
        return False

    if ip in blocked_ips:
        print(f"⚠️ Already blocked: {ip}")
        return False

    if ip in last_block_time and time.time() - last_block_time[ip] < COOLDOWN_TIME:
        print(f"⏳ Cooldown active for {ip}")
        return False

    rule_name = f"SentinelBlock_{ip.replace('.', '_')}"

    try:
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}"
        ], check=True, capture_output=True)

        print(f"🚫 BLOCKED: {ip}")

        blocked_ips.add(ip)
        block_time[ip] = time.time()
        last_block_time[ip] = time.time()

        log_action(ip, "Blocked")

        return True

    except subprocess.CalledProcessError as e:
        print(f"❌ Firewall Error: {e}")
        return False

# --- UNBLOCK IP ---
def unblock_ip_windows(ip):
    rule_name = f"SentinelBlock_{ip.replace('.', '_')}"

    try:
        subprocess.run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ], check=True, capture_output=True)

        print(f"🔓 UNBLOCKED: {ip}")
        log_action(ip, "Unblocked")

    except subprocess.CalledProcessError:
        pass

# --- CLEANUP HANDLER ---
def graceful_shutdown(sig, frame):
    print("\n🛑 Shutdown detected. Cleaning firewall rules...")
    for ip in list(blocked_ips):
        unblock_ip_windows(ip)
    sys.exit(0)

signal.signal(signal.SIGINT, graceful_shutdown)

# --- PROCESS THREAT ---
def process_threat(ip, result, prob):
    if not is_valid_ip(ip) or ip in WHITELIST:
        return
    if ip in blocked_ips:
        return
    current_time = time.time()

    # Reset counter after time window
    if ip not in attack_time or current_time - attack_time[ip] > ATTACK_RESET_TIME:
        attack_counter[ip] = 0

    attack_counter[ip] = attack_counter.get(ip, 0) + 1
    attack_time[ip] = current_time

    print(f"[INFO] {ip} → Count: {attack_counter[ip]} | Confidence: {round(prob*100,2)}%")

    if attack_counter[ip] >= ATTACK_THRESHOLD:
        block_ip_windows(ip)

# --- MAIN ENGINE ---
# --- MAIN ENGINE ---
def start_engine():
    print("⚔️ SENTINEL AI: Advanced Mitigation Engine Running...")
    
    # 🛑 FIX 2: Establish connection to find the absolute newest ID before starting the loop
    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute("SELECT MAX(id) FROM logs")
        max_id = cur.fetchone()[0]
        last_id = max_id if max_id is not None else 0
        cur.close()
        db_pool.putconn(conn)
        print(f"📡 Sync complete. Listening for NEW threats starting from Log ID: {last_id}")
    except Exception as e:
        print(f"❌ Initial sync error: {e}")
        last_id = 0

    while True:
        conn = None
        try:
            conn = db_pool.getconn()
            cur = conn.cursor()

            cur.execute("""
                SELECT id, source_ip, result, probability
                FROM logs
                WHERE id > %s
                ORDER BY id ASC
            """, (last_id,))

            rows = cur.fetchall()

            for rid, ip, result, prob in rows:
                if result.lower() != "normal" and prob >= CONFIDENCE_THRESHOLD:
                    # process_threat will now silently skip if already in blocked_ips
                    process_threat(ip, result, prob)

                last_id = rid

            cur.close()

        except Exception as e:
            print(f"❌ Engine Error: {e}")

        finally:
            if conn:
                db_pool.putconn(conn)

        # --- AUTO UNBLOCK ---
        current_time = time.time()
        for ip in list(block_time.keys()):
            if current_time - block_time[ip] > UNBLOCK_AFTER:
                unblock_ip_windows(ip)
                blocked_ips.discard(ip)
                del block_time[ip]
                if ip in attack_counter: del attack_counter[ip]
                if ip in attack_time: del attack_time[ip]

        time.sleep(1) # Reduced sleep to 1s for snappier unblocking behavior

# --- START ---
if __name__ == "__main__":
    init_db()
    start_engine()