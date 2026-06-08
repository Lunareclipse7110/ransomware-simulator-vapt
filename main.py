# main.py — Orchestrator: Runs Simulator + Detector + Dashboard together

import threading
import time
import os
import sys

import simulator
import detector
import dashboard

def main():
    print("=" * 60)
    print("   SAFE RANSOMWARE SIMULATOR — VAPT LAB PROJECT")
    print("=" * 60)
    print()

    # ── Step 1: Verify test files exist ──
    if not os.path.exists("test_folder") or not os.listdir("test_folder"):
        print("[!] test_folder/ is empty. Running create_test_files.py first...")
        os.system("python3 create_test_files.py")
        time.sleep(1)

    # ── Step 2: Start Detection Engine ──
    print("[1/3] Starting Detection Engine...")
    observer = detector.start_detector()

    # Register callback: when ransomware detected → stop simulator
    detector.set_detection_callback(simulator.stop_simulator)
    time.sleep(0.5)

    # ── Step 3: Start Dashboard in background thread ──
    print("[2/3] Starting Flask Dashboard...")
    dash_thread = threading.Thread(target=dashboard.run_dashboard, daemon=True)
    dash_thread.start()
    time.sleep(1)

    print("\n" + "=" * 60)
    print("  Dashboard: http://127.0.0.1:5000")
    print("  Open in your browser BEFORE starting the attack!")
    print("=" * 60)
    input("\n[>] Press ENTER to START the ransomware simulation...\n")

    # ── Step 4: Run Simulator in background thread ──
    print("[3/3] Launching Ransomware Simulator...")
    sim_thread = threading.Thread(target=simulator.run_simulator, daemon=True)
    sim_thread.start()

    # ── Step 5: Wait for simulation to finish ──
    sim_thread.join()

    print("\n" + "=" * 60)
    print("  Simulation ended. Dashboard is still live.")
    print("  Press Ctrl+C to exit.")
    print("=" * 60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
        print("\n[*] All modules stopped. Exiting.")


if __name__ == "__main__":
    main()
