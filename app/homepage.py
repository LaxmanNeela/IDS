from flask import Flask, render_template, request, Response, jsonify, session, redirect, url_for
import requests
import joblib
import numpy as np
import pandas as pd
import psycopg2
from psycopg2 import extras
import time
import subprocess
import platform
import os

app = Flask(__name__)
app.secret_key = "NIDS2026"

# --- CONFIG ---
DB_CONFIG = {
    "dbname": "sentinel_db",
    "user": "postgres",
    "password": "NIDS2026",
    "host": "localhost",
    "port": "5432"
}

# --- LOAD ML ---
model = joblib.load('model/ids_multi_model.pkl')
scaler = joblib.load('model/scaler.pkl')
encoders = joblib.load('model/encoders.pkl')
target_le = joblib.load('model/target_encoder.pkl')
feature_means = joblib.load('model/feature_means.pkl')

def get_db_conn():
    return psycopg2.connect(**DB_CONFIG)

# --- GLOBAL CONTROL ---
sniffer_process = None
sniffer_paused = False   

# --- LOGIN SYSTEM ---
USERS = {
    "admin": "admin123"
}

def login_required(f):
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username")
        pwd = request.form.get("password")

        if USERS.get(user) == pwd:
            session["user"] = user
            return redirect("/")
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# --- DASHBOARD ---
@app.route('/')
@login_required
def index():
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM logs")
                total = cur.fetchone()[0]

                cur.execute("SELECT COUNT(*) FROM logs WHERE result!='Normal'")
                attacks = cur.fetchone()[0]

        rate = (attacks / total * 100) if total else 0
        return render_template("index.html", total=total, attacks=attacks, attack_rate=round(rate, 2), error=None)
    except Exception as e:
        return render_template("index.html", total=0, attacks=0, attack_rate=0, error=str(e))

@app.route('/api/chart-data')
def get_chart_data():
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor(cursor_factory=extras.RealDictCursor) as cur:
            # 1. Attack Trends (Last 24 hours grouped by hour)
            cur.execute("""
                SELECT date_trunc('hour', timestamp) as hour, COUNT(*) as count
                FROM logs
                WHERE result != 'Normal' 
                AND timestamp > NOW() - INTERVAL '24 hours'
                GROUP BY hour
                ORDER BY hour ASC
            """)
            trends = cur.fetchall()

            # 2. Top 5 Offending IPs
            cur.execute("""
                SELECT source_ip, COUNT(*) as count
                FROM logs
                WHERE result != 'Normal'
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 5
            """)
            top_ips = cur.fetchall()

            return jsonify({
                "trends": trends,
                "top_ips": top_ips
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

# --- MANUAL PREDICTION ---
# Helper parsing logic for manual pipeline validation states
def safe_encode(encoder, value):
    try:
        return encoder.transform([value])[0]
    except:
        return 0

def safe_float(value):
    try:
        return float(value)
    except:
        return 0.0

@app.route("/predict_manual", methods=["POST"])
@login_required
def predict_manual():
    try:
        proto = safe_encode(encoders['protocol_type'], request.form.get('protocol_type'))
        srv = safe_encode(encoders['service'], request.form.get('service'))
        flg = safe_encode(encoders['flag'], request.form.get('flag'))
        
        src = safe_float(request.form.get('src_bytes'))
        dst = safe_float(request.form.get('dst_bytes'))
        count = safe_float(request.form.get('count', 1))

        data = feature_means.copy()
        data[1] = proto; data[2] = srv; data[3] = flg
        data[4] = src; data[5] = dst

        if len(data) > 22:
            data[22] = count

        df = pd.DataFrame([data], columns=scaler.feature_names_in_)
        features = scaler.transform(df)

        probs = model.predict_proba(features)[0]
        classes = list(target_le.classes_)
        normal_idx = classes.index("Normal")

        if probs[normal_idx] >= 0.5:
            result = "✅ Normal"
            prob = probs[normal_idx]
        else:
            probs[normal_idx] = 0
            idx = np.argmax(probs)
            result = f"🚨 {classes[idx]}"
            prob = probs[idx]

        return render_template("index.html", manual_result=result, probability=round(prob*100, 2))
    except Exception as e:
        return f"Error: {e}"

@app.route("/predict_manual_ajax", methods=["POST"])
@login_required
def predict_manual_ajax():
    try:
        proto = safe_encode(encoders['protocol_type'], request.form.get('protocol_type'))
        srv = safe_encode(encoders['service'], request.form.get('service'))
        flg = safe_encode(encoders['flag'], request.form.get('flag'))
        src = safe_float(request.form.get('src_bytes'))
        dst = safe_float(request.form.get('dst_bytes'))
        count = safe_float(request.form.get('count', 1))

        data = feature_means.copy()
        data[1] = proto
        data[2] = srv
        data[3] = flg
        data[4] = src
        data[5] = dst

        if len(data) > 22:
            data[22] = count

        df = pd.DataFrame([data], columns=scaler.feature_names_in_)
        features = scaler.transform(df)

        probs = model.predict_proba(features)[0]
        classes = list(target_le.classes_)
        normal_idx = classes.index("Normal")

        if probs[normal_idx] >= 0.5:
            result = "✅ Normal"
            prob = probs[normal_idx]
        else:
            probs[normal_idx] = 0
            idx = np.argmax(probs)
            result = f"🚨 {classes[idx]}"
            prob = probs[idx]

        # Save prediction to logs table
        db_result = result.replace("✅ ", "").replace("🚨 ", "")

        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO logs (
                        protocol,
                        service,
                        flag,
                        src_bytes,
                        dst_bytes,
                        count,
                        result,
                        probability,
                        source_ip,
                        timestamp
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
                """, (
                    request.form.get('protocol_type'),
                    request.form.get('service'),
                    request.form.get('flag'),
                    int(src),
                    int(dst),
                    int(count),
                    db_result,
                    float(prob),
                    "1.1.1.1"
                ))

        return jsonify({
            "result": result,
            "probability": round(prob * 100, 2)
        })

    except Exception as e:
        return jsonify({"error": str(e)})
# --- SNIFFER CONTROL ---
@app.route('/run-sniffer', methods=['POST'])
@login_required
def run_sniffer():
    global sniffer_process
    try:
        # Prevent duplicate sniffer instances
        if sniffer_process and sniffer_process.poll() is None:
            return jsonify({
                "status": "already_running",
                "message": "Sniffer already active"
            })
            
        sniffer_process = subprocess.Popen(['python', 'scripts/sniffer_flow.py'])
        return jsonify({
            "status": "success",
            "message": "Sniffer started successfully!"
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/pause-sniffer', methods=['POST'])
@login_required
def pause_sniffer():
    global sniffer_paused
    sniffer_paused = True
    return jsonify({"status": "paused"})

@app.route('/resume-sniffer', methods=['POST'])
@login_required
def resume_sniffer():
    global sniffer_paused
    sniffer_paused = False
    return jsonify({"status": "resumed"})

@app.route('/stop-sniffer', methods=['POST'])
@login_required
def stop_sniffer():
    global sniffer_process
    try:
        if sniffer_process and sniffer_process.poll() is None:
            sniffer_process.terminate()
            sniffer_process = None
            return jsonify({"status": "stopped"})
        else:
            return jsonify({"status": "not_running"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/stats')
@login_required
def get_stats():
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM logs")
                total = cur.fetchone()[0]

                cur.execute("SELECT COUNT(*) FROM logs WHERE result != 'Normal'")
                attacks = cur.fetchone()[0]

        rate = round((attacks / total * 100), 2) if total > 0 else 0
        return jsonify({
            "total": total,
            "attacks": attacks,
            "rate": rate
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- LIVE STREAM ---
@app.route('/stream_logs')
@login_required
def stream_logs():
    def generate():
        global sniffer_paused   

        conn = None
        try:
            conn = get_db_conn()
            cur = conn.cursor(cursor_factory=extras.RealDictCursor)

            cur.execute("SELECT MAX(id) FROM logs")
            res = cur.fetchone()
            last_id = res['max'] if res and res['max'] is not None else 0

            while True:
                if sniffer_paused:
                    time.sleep(1)
                    continue
                
                time.sleep(1)
                
                cur.execute("""
                    SELECT id, source_ip, result, probability, timestamp,
                           protocol, service, src_bytes, dst_bytes, count
                    FROM logs
                    WHERE id > %s
                    ORDER BY id ASC LIMIT 20
                """, (last_id,))

                rows = cur.fetchall()

                for r in rows:
                    last_id = r['id']
                    icon = "🚨" if r['result'] != "Normal" else "✅"
                    ts = r['timestamp'].strftime('%H:%M:%S')

                    button = ""
                    if r['result'] != "Normal":
                        button = f"<button class='btn btn-sm btn-danger' onclick='triggerBlock(\"{r['source_ip']}\")'>BLOCK</button>"

                    msg = (
                        f"{icon} [{ts}] {r['result']} | "
                        f"IP:{r['source_ip']} | "
                        f"PROTO:{r['protocol'].upper()} | "
                        f"SERVICE:{r['service'].upper()} | "
                        f"Src:{r['src_bytes']} "
                        f"Dst:{r['dst_bytes']} | "
                        f"Cnt:{r['count']} | "
                        f"Conf:{round(r['probability']*100,1)}% "
                        f"{button}"
                    )

                    yield f"data: {msg}\n\n"

                yield ":\n\n"

        except Exception as e:
            yield f"data: Error in stream: {str(e)}\n\n"
        finally:
            if conn:
                conn.close()

    return Response(generate(), mimetype='text/event-stream')

# --- FIREWALL ---
def block_ip(ip):
    try:
        rule_name = f"SentinelBlock_{ip.replace('.', '_')}"
        if platform.system() == "Windows":
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=SENTINEL_{ip}",
                "dir=in", "action=block",
                f"remoteip={ip}"
            ], check=True)
        elif platform.system() == "Linux":
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        return True
    except Exception:
        return False

geo_cache = {}

@app.route('/api/geolocate', methods=['POST'])
def geolocate_ip():
    data = request.get_json() or {}
    ip = data.get('ip')
    
    if not ip or ip.startswith(('127.', '192.168.', '10.')):
        return jsonify({"status": "skip", "message": "Local IP"})

    if ip in geo_cache:
        return jsonify(geo_cache[ip])

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if response.get("status") == "success":
            geo_data = {
                "status": "success",
                "lat": response.get("lat"),
                "lon": response.get("lon"),
                "city": response.get("city"),
                "country": response.get("country")
            }
            geo_cache[ip] = geo_data
            return jsonify(geo_data)
    except Exception as e:
        print(f"GeoIP Error: {e}")
        
    return jsonify({"status": "failed", "message": "Could not resolve geo-data"})

@app.route('/api/mitigations')
def get_mitigations():
    try:
        conn = psycopg2.connect(dbname="sentinel_db", user="postgres", password="NIDS2026", host="localhost", port="5432")
        cur = conn.cursor()
        cur.execute("SELECT ip, action, timestamp FROM mitigation_logs ORDER BY timestamp DESC LIMIT 5")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        return jsonify([{
            "ip": r[0],
            "action": r[1],
            "time": r[2].strftime("%H:%M:%S")
        } for r in rows])
    except Exception as e:
        return jsonify([])

@app.route('/block-ip', methods=['POST'])
@login_required
def trigger_block():
    data = request.get_json(silent=True) or request.form
    ip = data.get("ip") or data.get("source_ip")
    
    if not ip:
        return jsonify({"status": "error", "message": "No IP address provided"}), 400
        
    if block_ip(ip):
        # 📝 Log the manual action to the database so the UI panel updates!
        try:
            with get_db_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO mitigation_logs (ip, action, timestamp)
                        VALUES (%s, %s, NOW())
                    """, (ip, "Manual Block"))
        except Exception as db_err:
            print(f"Database logging failed: {db_err}")

        return jsonify({"status": "success", "message": f"IP {ip} blocked successfully."})
    else:
        return jsonify({"status": "error", "message": "System firewall rejection encountered."}), 500

# --- START ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)