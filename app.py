import cv2
import base64
import time
from flask import Flask, Response, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# --- SECURITY CONFIG ---
ADMIN_USERNAME = "admin"
# Hash for "network2026"
ADMIN_PASSWORD_HASH = generate_password_hash("network2026")
security_logs = []
active_tokens = set()

# Global variable to store the frame sent from your laptop
current_frame = None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/upload', methods=['POST'])
def upload():
    """Endpoint for YOUR laptop to push webcam frames to Render."""
    global current_frame
    data = request.json
    current_frame = data.get('image')
    return jsonify({"status": "received"})

def stream_gen():
    """Broadcasts the received frame to anyone watching the dashboard."""
    while True:
        if current_frame:
            try:
                # Extract base64 data and convert to bytes
                header, encoded = current_frame.split(",", 1)
                frame_bytes = base64.b64decode(encoded)
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
            except Exception:
                continue
        time.sleep(0.1) # Limits broadcast to ~10 FPS to save Render memory

@app.route('/video_feed')
def video_feed():
    return Response(stream_gen(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = data.get('username', '')
    pw = data.get('password', '')
    
    is_valid = (user == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, pw))
    
    log_entry = {
        "time": datetime.now().strftime("%I:%M:%S %p"),
        "ip": request.remote_addr,
        "username": user,
        "status": "Authorized Access" if is_valid else "Invalid Credentials",
        "is_threat": False
    }
    security_logs.insert(0, log_entry)
    
    return jsonify({"success": is_valid, "message": log_entry["status"]})

@app.route('/api/security_logs', methods=['GET'])
def get_logs():
    return jsonify(security_logs[:10])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)
