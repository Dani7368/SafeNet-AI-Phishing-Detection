import random
import csv
import io
from flask import Flask, render_template, jsonify, request, Response
from flask_socketio import SocketIO
from datetime import datetime
from PIL import Image
from detector import PhishingDetector, SAMPLE_PHISHING_ENTRIES

app = Flask(__name__)
app.config['SECRET_KEY'] = 'safenet-2024'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB max upload
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins='*')

detections = []
stats = {
    "total_scans": 0,
    "threats_detected": 0,
    "last_scan": "Never",
}

detector = PhishingDetector()


def record_scan(score, is_phishing, explanation, text="", sender="Image Upload"):
    stats["total_scans"] += 1
    stats["last_scan"] = datetime.now().strftime('%H:%M:%S')

    socketio.emit('scan_update', {
        "total_scans": stats["total_scans"],
        "threats_detected": stats["threats_detected"],
        "last_scan": stats["last_scan"],
        "score": score,
        "is_phishing": is_phishing,
    })

    if is_phishing:
        stats["threats_detected"] += 1
        now = datetime.now()
        snippet = text.replace("\n", " ").strip()
        entry = {
            "date": now.strftime('%Y-%m-%d'),
            "time": now.strftime('%H:%M:%S'),
            "text": (snippet[:150] + "...") if len(snippet) > 150 else snippet,
            "sender": sender,
            "score": score,
            "explanation": explanation,
        }
        detections.append(entry)
        socketio.emit('phishing_detected', entry)
        return entry

    return None


@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/upload', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({"error": "No image provided"}), 400

    file = request.files['image']
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    try:
        image = Image.open(file.stream).convert('RGB')
    except Exception:
        return jsonify({"error": "Invalid image file"}), 400

    score, explanation, text = detector.analyze_image(image)
    is_phishing = score >= 3

    entry = record_scan(score, is_phishing, explanation, text, sender="Image Upload")

    return jsonify({
        "score": score,
        "explanation": explanation,
        "is_phishing": is_phishing,
        "text_extracted": text[:300] if text else "",
        "entry": entry,
    })


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
    score = random.randint(6, 10)
    entry = {
        "date": now.strftime('%Y-%m-%d'),
        "time": now.strftime('%H:%M:%S'),
        "text": sample["text"],
        "sender": sample["sender"],
        "score": score,
        "explanation": f"HIGH RISK — Phishing score: {score}/10",
    }
    detections.append(entry)
    stats["threats_detected"] += 1
    stats["total_scans"] += 1
    stats["last_scan"] = now.strftime('%H:%M:%S')
    socketio.emit('phishing_detected', entry)
    socketio.emit('scan_update', {**stats, "score": score, "is_phishing": True})
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
    print("SafeNet AI starting on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
