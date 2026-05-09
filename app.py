import random
import csv
import io
from flask import Flask, render_template, jsonify, request, Response
from flask_socketio import SocketIO
from datetime import datetime
from detector import PhishingDetector, SAMPLE_PHISHING_ENTRIES

app = Flask(__name__)
app.config['SECRET_KEY'] = 'safenet-2024'
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins='*')

detections = []
stats = {
    "total_scans": 0,
    "threats_detected": 0,
    "last_scan": "Never",
}


def handle_scan(score, is_phishing, explanation):
    stats["total_scans"] += 1
    stats["last_scan"] = datetime.now().strftime('%H:%M:%S')
    socketio.emit('scan_update', {
        "total_scans": stats["total_scans"],
        "threats_detected": stats["threats_detected"],
        "last_scan": stats["last_scan"],
        "score": score,
        "is_phishing": is_phishing,
    })


def handle_detection(entry):
    stats["threats_detected"] += 1
    detections.append(entry)
    socketio.emit('phishing_detected', entry)


detector = PhishingDetector(on_scan=handle_scan, on_detection=handle_detection)
detector.start()


@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/stats')
def get_stats():
    total = stats["total_scans"]
    threats = stats["threats_detected"]
    rate = f"{(threats / max(1, total) * 100):.1f}%"
    return jsonify({**stats, "detection_rate": rate})


@app.route('/api/detections')
def get_detections():
    date = request.args.get('date', '').strip()
    result = [d for d in detections if not date or d['date'] == date]
    return jsonify(list(reversed(result)))


@app.route('/api/simulate', methods=['POST'])
def simulate():
    sample = random.choice(SAMPLE_PHISHING_ENTRIES)
    now = datetime.now()
    entry = {
        "date": now.strftime('%Y-%m-%d'),
        "time": now.strftime('%H:%M:%S'),
        "text": sample["text"],
        "sender": sample["sender"],
        "score": random.randint(6, 10),
        "explanation": "Simulated phishing attempt for demo",
    }
    detections.append(entry)
    stats["threats_detected"] += 1
    socketio.emit('phishing_detected', entry)
    return jsonify(entry)


@app.route('/api/export')
def export_csv():
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=["date", "time", "text", "sender", "score", "explanation"])
    writer.writeheader()
    writer.writerows(detections)
    return Response(
        out.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=phishing_logs.csv"},
    )


if __name__ == '__main__':
    print("🛡️  SafeNet AI starting on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
