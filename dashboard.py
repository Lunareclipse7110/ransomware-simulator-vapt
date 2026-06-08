# dashboard.py — Flask Real-Time Dashboard

import json
import os
from flask import Flask, render_template, jsonify

app = Flask(__name__)

METRICS_FILE   = "logs/metrics.json"
DETECTION_FILE = "logs/detection.json"
LOG_FILE       = "logs/incidents.log"


def load_json(filepath):
    """Safely load a JSON file."""
    try:
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/metrics")
def api_metrics():
    """Returns simulator attack metrics."""
    return jsonify(load_json(METRICS_FILE))


@app.route("/api/detection")
def api_detection():
    """Returns detection engine state."""
    return jsonify(load_json(DETECTION_FILE))


@app.route("/api/log")
def api_log():
    """Returns last 30 lines of incident log."""
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                lines = f.readlines()
            return jsonify({"log": lines[-30:]})
    except Exception:
        pass
    return jsonify({"log": []})


@app.route("/api/combined")
def api_combined():
    """Returns all data in one call for dashboard efficiency."""
    metrics   = load_json(METRICS_FILE)
    detection = load_json(DETECTION_FILE)
    return jsonify({
        "metrics": metrics,
        "detection": detection
    })


def run_dashboard():
    """Start the Flask dashboard."""
    print("[*] Dashboard running at: http://127.0.0.1:5000")
    app.run(debug=False, use_reloader=False, port=5000)
