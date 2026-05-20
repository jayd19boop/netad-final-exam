import cv2
import base64
import time
import os
import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)
# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = generate_password_hash("network2026")
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://localhost/soc_db')

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

def detect_malicious_intent(user, pw):
    malicious = ["'", "--", "OR 1=1", "DROP", "SELECT", "<SCRIPT>"]
    payload = (str(user) + str(pw)).upper()
    return any(m in payload for m in malicious)

@app.route('/')
def home():
    return render_template('index.html')

# ==========================================
# ⚡ WEBSOCKET VIDEO RELAY
# ==========================================
@socketio.on('video_frame')
def handle_frame(data):
    """
    Receives a frame from your laptop (transmitter) and instantly 
    broadcasts it to all connected viewers (the dashboard).
    """
    emit('video_stream', data, broadcast=True, include_self=False)

# ==========================================
# 🛡️ SECURITY ROUTES (Unchanged)
# ==========================================
@app.route('/setup_db_now')
def force_init():
    """A secret manual trigger to build the database table."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
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
        return "<h1 style='color: green;'>✅ SUCCESS: The security_logs table is built and ready!</h1>"
    except Exception as e:
        return f"<h1 style='color: red;'>❌ ERROR: {e}</h1>"
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
    device_info = request.headers.get('User-Agent', 'Unknown Device')
    
    # 🌐 THE REVERSE PROXY FIX: Grab the true IP address
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        ip_address = request.environ.get('REMOTE_ADDR', 'Unknown')
    else:
        ip_address = request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0]

    # 🔒 THE CONNECTION LEAK FIX: Ensure connection always closes
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO security_logs (time, ip, device_info, username, status, is_threat) VALUES (%s, %s, %s, %s, %s, %s)',
            (log_time, ip_address, device_info, user, status, is_threat)
        )
        conn.commit()
        cur.close()
    except Exception as e:
        print(f"Database Error: {e}")
    finally:
        if conn is not None:
            conn.close() # Always close the connection even if it crashes!
    
    return jsonify({"success": valid_auth, "message": status})

@app.route('/api/security_logs', methods=['GET'])
def get_logs():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('SELECT * FROM security_logs ORDER BY id DESC LIMIT 15')
        logs = cur.fetchall()
        cur.close()
        return jsonify(logs)
    except Exception as e:
        print(f"Log Fetch Error: {e}")
        return jsonify([])
    finally:
        if conn is not None:
            conn.close()
            
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5001)
