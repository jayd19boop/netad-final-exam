import cv2
import time
import secrets
from flask import Flask, Response, request, jsonify, abort, render_template
from flask_cors import CORS
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# Use the exact camera settings that worked for you!
camera = cv2.VideoCapture(0, cv2.CAP_DSHOW) 

# ==========================================
# 🛡️ SECURITY LAYER 1: PASSWORD HASHING
# We never store real passwords. We store a mathematical "hash".
# ==========================================
ADMIN_USERNAME = "admin"
# This is the hash for "network2026"
ADMIN_PASSWORD_HASH = generate_password_hash("network2026")

# ==========================================
# 🛡️ SECURITY LAYER 2: ANTI-BRUTE FORCE
# Track failed attempts and lock out IP addresses.
# ==========================================
failed_attempts = {}
MAX_ATTEMPTS = 3
LOCKOUT_SECONDS = 30

# ==========================================
# 🛡️ SECURITY LAYER 3: SESSION TOKENS
# Prevent direct URL access to the video stream.
# ==========================================
active_tokens = set()
security_logs = []

@app.route('/')
   def home():
       """Serves the main dashboard HTML interface."""
       return render_template('index.html')

def generate_frames():
    while True:
        success, frame = camera.read()
        if not success:
            break
        else:
            ret, buffer = cv2.imencode('.jpg', frame)
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

@app.route('/video_feed')
def video_feed():
    """SECURE VIDEO ROUTE: Requires a valid cryptographic token."""
    token = request.args.get('token')
    
    # If there is no token, or the token is wrong, drop the connection immediately
    if token not in active_tokens:
        abort(403) # 403 Forbidden Error
        
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

def detect_sqli(payload):
    """Basic SQLi detection."""
    suspicious_chars = ["'", '"', ";", "--"]
    suspicious_words = ["OR 1=1", "DROP TABLE", "UNION SELECT"]
    payload_upper = str(payload).upper()
    if any(char in payload for char in suspicious_chars): return True
    if any(word in payload_upper for word in suspicious_words): return True
    return False

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username_attempt = data.get('username', '')
    password_attempt = data.get('password', '')
    ip_address = request.remote_addr

    # --- BRUTE FORCE CHECK ---
    current_time = time.time()
    if ip_address in failed_attempts:
        if failed_attempts[ip_address]['count'] >= MAX_ATTEMPTS:
            time_passed = current_time - failed_attempts[ip_address]['lockout_start']
            if time_passed < LOCKOUT_SECONDS:
                remaining = int(LOCKOUT_SECONDS - time_passed)
                return jsonify({"success": False, "message": f"IP LOCKED. Try again in {remaining}s"})
            else:
                # Reset after lockout period ends
                failed_attempts[ip_address] = {'count': 0, 'lockout_start': 0}

    # --- THREAT DETECTION ---
    is_sqli = detect_sqli(username_attempt) or detect_sqli(password_attempt)
    
    # --- SECURE AUTHENTICATION ---
    # We compare the hash, NOT the plaintext password
    is_valid_user = (username_attempt == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password_attempt))
    
    token = None

    if is_sqli:
        status = "SQL INJECTION DETECTED"
        success = False
    elif is_valid_user:
        status = "Authorized Access"
        success = True
        # Generate a secure, random 32-character token for the video stream
        token = secrets.token_hex(16)
        active_tokens.add(token)
        # Clear any failed attempts on success
        if ip_address in failed_attempts:
            failed_attempts[ip_address] = {'count': 0, 'lockout_start': 0}
    else:
        status = "Invalid Credentials"
        success = False
        # Log the failed attempt for Brute Force tracking
        if ip_address not in failed_attempts:
            failed_attempts[ip_address] = {'count': 1, 'lockout_start': current_time}
        else:
            failed_attempts[ip_address]['count'] += 1
            if failed_attempts[ip_address]['count'] >= MAX_ATTEMPTS:
                failed_attempts[ip_address]['lockout_start'] = current_time
                status = "BRUTE FORCE: IP LOCKED"

    # --- LOGGING ---
    log_entry = {
        "time": datetime.now().strftime("%I:%M:%S %p"),
        "ip": ip_address,
        "username": username_attempt,
        "status": status,
        "is_threat": is_sqli or "BRUTE FORCE" in status
    }
    
    security_logs.insert(0, log_entry)
    if len(security_logs) > 8:
        security_logs.pop()

    return jsonify({"success": success, "message": status, "token": token})

@app.route('/api/security_logs', methods=['GET'])
def get_logs():
    return jsonify(security_logs)

if __name__ == '__main__':
    # Add Security Headers to every response to prevent browser-based attacks (XSS/Clickjacking)
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response

    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)
