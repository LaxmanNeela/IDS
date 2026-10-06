from flask import Flask, render_template, request, Response, jsonify,session,redirect,url_for
import joblib
import numpy as np
import pandas as pd
import psycopg2
from psycopg2 import extras
import time
import subprocess
import platform


app = Flask(__name__)

# --- CONFIG ---
DB_CONFIG = {
    "dbname": "sentinel_db",
    "user": "postgres",
    "password": "NIDS2026",  # Ensure this matches your PostgreSQL password
    "host": "localhost",
    "port": "5432"
}

# --- LOAD ML ASSETS ---
# Ensure these files exist in the 'model/' directory relative to this script
model = joblib.load('model/ids_multi_model.pkl')
scaler = joblib.load('model/scaler.pkl')
encoders = joblib.load('model/encoders.pkl')
target_le = joblib.load('model/target_encoder.pkl')
feature_means = joblib.load('model/feature_means.pkl')

def get_db_conn():
    return psycopg2.connect(**DB_CONFIG)

def safe_float(val, default=0.0):
    """Safely converts a string to a float, returning a default if it fails."""
    try:
        if val is None or str(val).strip() == "":
            return default
        return float(val)
    except (ValueError, TypeError):
        return default

def safe_encode(encoder, value):
    """Safely encodes categorical data, returning 0 if the label is unknown."""
    try:
        return encoder.transform([value])[0]
    except:
        return 0

@app.route('/')
@login_required
def index():
    """Fetches total stats for the top cards on the dashboard."""
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM logs")
                total = cur.fetchone()[0]
                
                cur.execute("SELECT COUNT(*) FROM logs WHERE result != 'Normal'")
                attacks = cur.fetchone()[0]
                
        attack_rate = (attacks / total * 100) if total > 0 else 0
        return render_template('index.html', total=total, attacks=attacks, attack_rate=round(attack_rate, 2))
    except Exception:
        # Fallback if DB is empty or table doesn't exist yet
        return render_template('index.html', total=0, attacks=0, attack_rate=0)


# --- SIMPLE USER STORE (replace later with DB if needed)
USERS = {
    "admin": "admin123"
}

# --- LOGIN REQUIRED DECORATOR
def login_required(f):
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# --- LOGIN PAGE
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if USERS.get(username) == password:
            session["user"] = username
            return redirect("/")
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


# --- LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/predict_manual", methods=["POST"])
def predict_manual():
    """Handles the form on the 'Manual Testing' tab."""
    try:
        # 1. Clean Inputs
        proto_raw = str(request.form.get('protocol_type', 'tcp')).lower()
        srv_raw = str(request.form.get('service', 'http')).lower()
        flg_raw = str(request.form.get('flag', 'SF')).upper()

        # 2. Encode categorical values
        proto = safe_encode(encoders['protocol_type'], proto_raw)
        srv = safe_encode(encoders['service'], srv_raw)
        flg = safe_encode(encoders['flag'], flg_raw)

        # 3. Build feature array from means
        input_data = feature_means.copy()
        input_data[0] = safe_float(request.form.get('duration'))
        input_data[1] = proto
        input_data[2] = srv
        input_data[3] = flg
        input_data[4] = safe_float(request.form.get('src_bytes'))
        input_data[5] = safe_float(request.form.get('dst_bytes'))

        # Feature index 22 is often 'count' in KDD datasets
        if len(input_data) > 22:
            input_data[22] = safe_float(request.form.get('count', 1))

        # 4. Scale and Predict

        feature_names = scaler.feature_names_in_

        df = pd.DataFrame([input_data], columns=feature_names)

        features = scaler.transform(df)
        probs = model.predict_proba(features)[0]
        classes = list(target_le.classes_)
        normal_idx = classes.index('Normal')

        # 5. Logical Threshold (Normal vs Intrusion)
        if probs[normal_idx] >= 0.5:
            result = "✅ Normal Traffic"
            prob_val = round(probs[normal_idx] * 100, 2)
        else:
            attack_probs = probs.copy()
            attack_probs[normal_idx] = 0
            idx = np.argmax(attack_probs)
            result = f"🚨 Intrusion Detected: {classes[idx]}"
            prob_val = round((1 - probs[normal_idx]) * 100, 2)

        # Re-fetch stats so the UI stays updated
        return render_template("index.html", manual_result=result, probability=prob_val)
    except Exception as e:
        return f"Prediction Error: {str(e)}"

@app.route('/stream_logs')
def stream_logs():
    def generate():
        last_id = 0
        try:
            conn = get_db_conn()
            conn.set_session(autocommit=True)
            with conn.cursor(cursor_factory=extras.RealDictCursor) as cur:
                # Get current max ID to start from 'now'
                cur.execute("SELECT MAX(id) FROM logs")
                res = cur.fetchone()
                if res and res['max']:
                    last_id = res['max']

                while True:
                    # UPDATED: Added src_bytes, dst_bytes, and count to SELECT
                    cur.execute("""
                        SELECT id, source_ip, result, probability, timestamp, 
                               src_bytes, dst_bytes, count
                        FROM logs
                        WHERE id > %s
                        ORDER BY id ASC
                        LIMIT 20
                    """, (last_id,))

                    rows = cur.fetchall()
                    for row in rows:
                        last_id = row['id']
                        status = "🚨" if row['result'] != "Normal" else "✅"
                        ts = row['timestamp'].strftime('%H:%M:%S')
                        
                        # UPDATED: Added the new values to the output string
                        msg = (f"{status} [{ts}] {row['result']} | IP: {row['source_ip']} | "
                               f"Src: {row['src_bytes']}B | Dst: {row['dst_bytes']}B | "
                               f"Cnt: {row['count']} | Conf: {round(row['probability']*100,1)}%")
                        # Inside your stream_logs loop:
                        msg = f"{status} {row['result']} | {row['source_ip']} | "
                        msg += f"<button class='btn btn-sm btn-danger' onclick='triggerBlock(\"{row['source_ip']}\")'>BLOCK</button>"
                        
                        yield f"data: {msg}\n\n"

                    yield ":\n\n" 
                    time.sleep(1)
        except Exception as e:
            yield f"data: ❌ Stream Error: {str(e)}\n\n"
        finally:
            if conn:
                conn.close()

    return Response(generate(), mimetype='text/event-stream')

def block_ip(ip_address):
    """Blocks an IP address based on the Operating System."""
    system = platform.system()
    try:
        if system == "Windows":
            # Command to block IP via Windows Advanced Firewall
            cmd = f'netsh advfirewall firewall add rule name="SENTINEL_BLOCK_{ip_address}" dir=in action=block remoteip={ip_address}'
        else:
            # Command to block IP via Linux iptables
            cmd = f'sudo iptables -A INPUT -s {ip_address} -j DROP'
            
        subprocess.run(cmd, shell=True, check=True)
        print(f"🛡️ SOAR ACTION: Successfully blocked IP {ip_address}")
        return True
    except Exception as e:
        print(f"❌ Failed to block IP: {e}")
        return False
if __name__ == "__main__":
    # host="0.0.0.0" allows other devices on your local network to view the dashboard
    app.run(host="0.0.0.0", port=5000, debug=False)