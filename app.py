import cv2
import base64
import time
import os
import psycopg2
import psycopg2.extras
from flask import Flask, Response, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# AUTH CONFIG
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = generate_password_hash("network2026")
current_frame = None

# ==========================================
# 🗄️ CLOUD DATABASE SETUP (PostgreSQL)
# ==========================================
# Grabs the URL from Render, or uses a local fallback if you are testing on your PC
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://localhost/soc_db')

def get_db_connection():
    """Opens a connection to the PostgreSQL database."""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def init_db():
    """Creates the tables if they don't exist yet."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # PostgreSQL uses SERIAL instead of AUTOINCREMENT
        cur.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id SERIAL PRIMARY KEY,
                time TEXT NOT NULL,
                ip TEXT NOT NULL,
                device_info TEXT NOT NULL,
                username TEXT,
                status TEXT NOT NULL,
                is_threat BOOLEAN NOT NULL
            )
        ''')
        conn.commit()
        cur.close()
        conn.close()
        print("✅ PostgreSQL Database Initialized")
    except Exception as e:
        print(f"⚠️ Database connection failed (normal if building on Render): {e}")

# Run database initialization
init_db()

# ==========================================
# 🛡️ SECURITY & STREAMING LOGIC
# ==========================================
def detect_malicious_intent(user, pw):
    malicious = ["'", "--", "OR 1=1", "DROP", "SELECT", "<SCRIPT>"]
    payload = (str(user) + str(pw)).upper()
    return any(m in payload for m in malicious)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/upload', methods=['POST'])
def upload():
    global current_frame
    data = request.json
    current_frame = data.get('image')
    return jsonify({"status": "received"})

def stream_gen():
    global current_frame
    while True:
        if current_frame is not None:
            try:
                if "," in current_frame:
                    _, encoded = current_frame.split(",", 1)
                    frame_bytes = base64.b64decode(encoded)
                    yield (b'--frame\r\n'
                           b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
            except Exception:
                continue
        time.sleep(0.2)

@app.route('/video_feed')
def video_feed():
    return Response(stream_gen(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = data.get('username', '')
    pw = data.get('password', '')
    
    hacking_attempt = detect_malicious_intent(user, pw)
    valid_auth = (user == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, pw))
    
    if hacking_attempt:
        status = "CRITICAL: INJECTION DETECTED"
        is_threat = True
    elif not valid_auth:
        status = "FAILED AUTHENTICATION"
        is_threat = (user == "admin") 
    else:
        status = "AUTHORIZED ACCESS"
        is_threat = False

    log_time = datetime.now().strftime("%I:%M:%S %p")
    ip_address = request.remote_addr
    device_info = request.headers.get('User-Agent', 'Unknown Device')

    # 💾 SAVE TO POSTGRESQL
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # PostgreSQL uses %s for parameters instead of ?
        cur.execute(
            'INSERT INTO security_logs (time, ip, device_info, username, status, is_threat) VALUES (%s, %s, %s, %s, %s, %s)',
            (log_time, ip_address, device_info, user, status, is_threat)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error saving log: {e}")
    
    return jsonify({"success": valid_auth, "message": status})

@app.route('/api/security_logs', methods=['GET'])
def get_logs():
    """Fetches the 15 most recent logs from PostgreSQL."""
    try:
        conn = get_db_connection()
        # RealDictCursor formats the SQL output into JSON-friendly dictionaries
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('SELECT * FROM security_logs ORDER BY id DESC LIMIT 15')
        logs = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(logs)
    except Exception as e:
        print(f"Error fetching logs: {e}")
        return jsonify([])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
