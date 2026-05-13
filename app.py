import cv2
import os
from flask import Flask, Response
from flask_cors import CORS

app = Flask(__name__)
# Enable CORS so your HTML file can fetch the video stream without security blocks
CORS(app) 

# Initialize the camera. 
# '0' uses your computer's default webcam.
# If you are using a network IP camera, replace 0 with the RTSP link, e.g.:
# camera = cv2.VideoCapture('rtsp://admin:password@192.168.1.100:554/stream')
camera = cv2.VideoCapture(0)

def generate_frames():
    """Generator function that continuously reads frames from the camera."""
    while True:
        success, frame = camera.read()
        if not success:
            break
        else:
            # Encode the video frame into JPEG format
            ret, buffer = cv2.imencode('.jpg', frame)
            frame = buffer.tobytes()
            
            # Yield the frame in the byte format required for HTTP multipart streaming
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

@app.route('/video_feed')
def video_feed():
    """Route that serves the continuous video stream."""
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)