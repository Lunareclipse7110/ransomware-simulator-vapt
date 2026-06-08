# recover.py — Decrypt files using saved key (Demo Recovery)

import os
import json
from cryptography.fernet import Fernet

METRICS_FILE  = "logs/metrics.json"
TARGET_FOLDER = "test_folder"

def recover():
    with open(METRICS_FILE, "r") as f:
        metrics = json.load(f)

    key = metrics.get("encryption_key")
    if not key:
        print("[!] No encryption key found in metrics.")
        return

    fernet = Fernet(key.encode())
    locked_files = [
        os.path.join(TARGET_FOLDER, f)
        for f in os.listdir(TARGET_FOLDER)
        if f.endswith(".locked")
    ]

    print(f"[*] Recovering {len(locked_files)} files...")
    for filepath in locked_files:
        with open(filepath, "rb") as f:
            data = f.read()
        decrypted = fernet.decrypt(data)
        original_path = filepath.replace(".locked", "")
        with open(original_path, "wb") as f:
            f.write(decrypted)
        os.remove(filepath)
        print(f"[+] Recovered: {os.path.basename(original_path)}")

    ransom_note = os.path.join(TARGET_FOLDER, "READ_ME.txt")
    if os.path.exists(ransom_note):
        os.remove(ransom_note)

    print(f"\n[*] Recovery complete! All {len(locked_files)} files restored.")

if __name__ == "__main__":
    recover()
