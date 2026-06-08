# detector.py — Real-Time Detection Engine (Blue Team Module)

import os
import math
import time
import json
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ──────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────
TARGET_FOLDER      = "test_folder"
LOG_FILE           = "logs/incidents.log"
ENTROPY_THRESHOLD  = 7.2   # Files above this are suspicious
RENAME_THRESHOLD   = 3     # Number of .locked renames before alert
MODIFY_RATE_LIMIT  = 5     # Modifications per 10 seconds = alert

# Shared detection state (read by dashboard)
detection_state = {
    "alerts": [],
    "events": [],
    "locked_count": 0,
    "modification_count": 0,
    "ransomware_detected": False,
    "detection_time": None
}

_on_ransomware_detected_callback = None


def set_detection_callback(callback):
    """Register a callback to trigger when ransomware is detected."""
    global _on_ransomware_detected_callback
    _on_ransomware_detected_callback = callback


def calculate_entropy(filepath: str) -> float:
    """Calculate Shannon entropy of a file."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        if not data:
            return 0.0
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        total = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)
    except Exception:
        return 0.0


def log_incident(message: str):
    """Write an incident to the log file and detection state."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

    detection_state["alerts"].append({
        "time": timestamp,
        "message": message
    })
    print(f"\n⚠️  ALERT: {message}")


def trigger_ransomware_alert(reason: str):
    """Called when ransomware is confirmed detected."""
    if not detection_state["ransomware_detected"]:
        detection_state["ransomware_detected"] = True
        detection_state["detection_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        log_incident(f"🚨 RANSOMWARE DETECTED — Reason: {reason}")
        save_detection_state()
        if _on_ransomware_detected_callback:
            _on_ransomware_detected_callback()


def save_detection_state():
    """Persist detection state to JSON for dashboard."""
    os.makedirs("logs", exist_ok=True)
    with open("logs/detection.json", "w") as f:
        json.dump(detection_state, f, indent=2)


class RansomwareEventHandler(FileSystemEventHandler):
    """Watches the target folder and reacts to suspicious events."""

    def __init__(self):
        super().__init__()
        self._recent_mods = []  # Timestamps of recent modifications
        self._lock = threading.Lock()

    def on_modified(self, event):
        if event.is_directory:
            return
        filepath = event.src_path
        filename = os.path.basename(filepath)

        # Skip ransom note and log files
        if filename in ("READ_ME.txt",) or filepath.startswith("logs"):
            return

        now = time.time()
        entropy = calculate_entropy(filepath)

        event_record = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "event": "modified",
            "file": filename,
            "entropy": entropy
        }
        detection_state["events"].append(event_record)
        detection_state["modification_count"] += 1
        save_detection_state()

        print(f"[DETECT] Modified: {filename} | Entropy: {entropy}")

        # Entropy-based detection
        if entropy > ENTROPY_THRESHOLD:
            log_incident(f"High entropy ({entropy}) detected in: {filename}")
            trigger_ransomware_alert(f"High entropy {entropy} in {filename}")

        # Modification rate detection (sliding window: last 10 seconds)
        with self._lock:
            self._recent_mods = [t for t in self._recent_mods if now - t < 10]
            self._recent_mods.append(now)
            if len(self._recent_mods) >= MODIFY_RATE_LIMIT:
                log_incident(f"Rapid file modification rate: {len(self._recent_mods)} files in 10 seconds")
                trigger_ransomware_alert("Rapid file modification rate exceeded")

    def on_moved(self, event):
        """Triggered when a file is renamed (e.g., to .locked)."""
        if event.is_directory:
            return
        dest = event.dest_path
        filename_dest = os.path.basename(dest)

        if dest.endswith(".locked"):
            detection_state["locked_count"] += 1
            event_record = {
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "event": "renamed_to_locked",
                "file": filename_dest,
                "entropy": None
            }
            detection_state["events"].append(event_record)
            save_detection_state()

            print(f"[DETECT] Renamed to .locked: {filename_dest} | Total locked: {detection_state['locked_count']}")
            log_incident(f"File renamed to .locked: {filename_dest}")

            if detection_state["locked_count"] >= RENAME_THRESHOLD:
                trigger_ransomware_alert(f"{detection_state['locked_count']} files renamed to .locked")

    def on_created(self, event):
        """Detect ransom note creation."""
        if "READ_ME.txt" in event.src_path:
            log_incident("Ransom note READ_ME.txt created!")
            trigger_ransomware_alert("Ransom note (READ_ME.txt) dropped in target folder")


def start_detector():
    """Start the file system observer."""
    os.makedirs("logs", exist_ok=True)
    save_detection_state()

    event_handler = RansomwareEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path=TARGET_FOLDER, recursive=False)
    observer.start()

    print(f"[*] Detection Engine STARTED — Monitoring: {TARGET_FOLDER}/")
    print(f"[*] Entropy threshold: {ENTROPY_THRESHOLD} | Rename threshold: {RENAME_THRESHOLD}")

    return observer
