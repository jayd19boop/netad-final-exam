import cv2
import base64
import time
from flask import Flask, Response, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# AUTH CONFIG
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = generate_password_hash("network2026")
security_logs = []
current_frame = None

def detect_malicious_intent(user, pw):
    """Scans for SQLi characters or common hacking strings."""
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
    while True:
        if current_frame:
            try:
                header, encoded = current_frame.split(",", 1)
                frame_bytes = base64.b64decode(encoded)
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
            except: continue
        time.sleep(0.1)

@app.route('/video_feed')
def video_feed():
    return Response(stream_gen(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = data.get('username', '')
    pw = data.get('password', '')
    
    # SECURITY LOGIC
    hacking_attempt = detect_malicious_intent(user, pw)
    valid_auth = (user == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, pw))
    
    if hacking_attempt:
        status = "CRITICAL: INJECTION DETECTED"
        is_threat = True
    elif not valid_auth:
        status = "FAILED AUTHENTICATION"
        is_threat = (user == "admin") # Flag if they are trying to guess the admin pass
    else:
        status = "AUTHORIZED ACCESS"
        is_threat = False

    log_entry = {
        "time": datetime.now().strftime("%I:%M:%S %p"),
        "ip": request.remote_addr,
        "username": user,
        "status": status,
        "is_threat": is_threat
    }
    security_logs.insert(0, log_entry)
    
    return jsonify({"success": valid_auth, "message": status})

@app.route('/api/security_logs', methods=['GET'])
def get_logs():
    return jsonify(security_logs[:15])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
