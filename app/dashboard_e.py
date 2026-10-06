from flask import Flask, render_template, request, Response, jsonify, session, redirect, url_for
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
# --- HELPERS ---
def safe_float(val, default=0):
    try:
        return float(val)
    except:
        return default
def safe_encode(enc, val):
    try:
        return enc.transform([val])[0]
    except:
        return 0
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
        return render_template("index.html", total=total, attacks=attacks, attack_rate=round(rate,2))
    except:
        return render_template("index.html", total=0, attacks=0, attack_rate=0) 
@app.route('/api/chart-data')
def get_chart_data():
    """Returns data for the graphs in JSON format"""
    conn = None
    try:
        conn = get_db_conn() # <-- FIXED: was get_conn()
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
            conn.close() # <-- FIXED: was release_conn(conn)
# --- MANUAL PREDICTION ---
@app.route("/predict_manual", methods=["POST"])
@login_required
def predict_manual():
    try:
        proto = safe_encode(encoders['protocol_type'], request.form.get('protocol_type'))
        srv = safe_encode(encoders['service'], request.form.get('service'))
        flg = safe_encode(encoders['flag'], request.form.get('flag'))
        
        src = safe_float(request.form.get('src_bytes'))
        dst = safe_float(request.form.get('dst_bytes'))
        count = safe_float(request.form.get('count',1))

        data = feature_means.copy()
        data[1]=proto; data[2]=srv; data[3]=flg
        data[4]=src; data[5]=dst

        if len(data)>22:
            data[22]=count

        df = pd.DataFrame([data], columns=scaler.feature_names_in_)
        features = scaler.transform(df)

        probs = model.predict_proba(features)[0]
        classes = list(target_le.classes_)
        normal_idx = classes.index("Normal")

        if probs[normal_idx] >= 0.5:
            result="✅ Normal"
            prob=probs[normal_idx]
        else:
            probs[normal_idx]=0
            idx=np.argmax(probs)
            result=f"🚨 {classes[idx]}"
            prob=probs[idx]

        return render_template("index.html", manual_result=result, probability=round(prob*100,2))
    except Exception as e:
        return f"Error: {e}"
@app.route("/predict_manual_ajax", methods=["POST"])
@login_required
def predict_manual_ajax():
    try:
        proto = safe_encode(
            encoders['protocol_type'],
            request.form.get('protocol_type')
        )
        srv = safe_encode(
            encoders['service'],
            request.form.get('service')
        )
        flg = safe_encode(
            encoders['flag'],
            request.form.get('flag')
        )
        src = safe_float(
            request.form.get('src_bytes')
        )
        dst = safe_float(
            request.form.get('dst_bytes')
        )
        count = safe_float(
            request.form.get('count',1)
        )
        data = feature_means.copy()
        data[1] = proto
        data[2] = srv
        data[3] = flg
        data[4] = src
        data[5] = dst
        if len(data) > 22:
            data[22] = count
        df = pd.DataFrame(
            [data],
            columns=scaler.feature_names_in_
        )
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
        return jsonify({
            "result": result,
            "probability": round(prob * 100, 2)
        })
    except Exception as e:
        return jsonify({
            "error": str(e)
        })
sniffer_process = None
@app.route('/run-sniffer', methods=['POST'])
def run_sniffer():
    global sniffer_process
    try:
        # Prevent duplicate sniffer instances
        if sniffer_process and sniffer_process.poll() is None:
            return jsonify({
                "status": "already_running",
                "message": "Sniffer already active"
            })
        sniffer_process = subprocess.Popen(
            ['python', 'scripts/sniffer_flow.py']
        )
        return jsonify({
            "status": "success",
            "message": "Sniffer started successfully!"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500    
# --- LIVE STREAM ---
@app.route('/stream_logs')
@login_required
def stream_logs():
    def generate():
        conn = None
        try:
            conn = get_db_conn()
            cur = conn.cursor(cursor_factory=extras.RealDictCursor)
            # --- THE FIX: Get the latest ID at the moment the stream starts ---
            cur.execute("SELECT MAX(id) FROM logs")
            res = cur.fetchone()
            # If table is empty, start from 0; otherwise start from the latest ID
            last_id = res['max'] if res and res['max'] is not None else 0
            while True:
                cur.execute("""
                    SELECT id,
                        source_ip,
                        result,
                        probability,
                        timestamp,
                        protocol,
                        service,
                        src_bytes,
                        dst_bytes,
                        count
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
                time.sleep(1)
        except Exception as e:
            yield f"data: Error in stream: {str(e)}\n\n"
        finally:
            if conn:
                conn.close()
    return Response(generate(), mimetype='text/event-stream')
# --- BLOCK API ---
@app.route('/block_api', methods=['POST'])
@login_required
def block_api():
    ip=request.json.get("ip")
    if not ip:
        return jsonify({"error":"No IP"}),400
    if ip.startswith("127.") or ip.startswith("192.168"):
        return jsonify({"error":"Local IP blocked avoided"}),400
    if block_ip(ip):
        return jsonify({"status":"blocked"})
    return jsonify({"status":"failed"}),500
@app.route('/api/stats')
def get_stats():
    conn = get_db_conn()
    cur = conn.cursor()
    # Get total count
    cur.execute("SELECT COUNT(*) FROM logs")
    total = cur.fetchone()[0]
    # Get attack count
    cur.execute("SELECT COUNT(*) FROM logs WHERE result != 'Normal'")
    attacks = cur.fetchone()[0]
    # Calculate rate
    rate = round((attacks / total * 100), 2) if total > 0 else 0    
    cur.close()
    conn.close()    
    return jsonify({
        "total": total,
        "attacks": attacks,
        "rate": rate
    })
# --- FIREWALL ---
def block_ip(ip):
    try:
        if platform.system()=="Windows":
            subprocess.run([
                "netsh","advfirewall","firewall","add","rule",
                f"name=SENTINEL_{ip}",
                "dir=in","action=block",
                f"remoteip={ip}"
            ],check=True)
        return True
    except:
        return False
# --- START ---
if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000,debug=False)