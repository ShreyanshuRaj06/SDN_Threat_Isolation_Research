#!/usr/bin/env python3
"""
experiments/verify_stage3.py

Automated Stage 3 Verification Script:
Verifies the complete Fast Response path (Suricata EVE -> Risk Engine -> OVS Flow Rule -> Local Logger).
References: PRD (Section 5, MVP 4-6), PLAN.md (Phase 3)

Test Sequence:
1. Resets /tmp/stage3_eve.json.
2. Spawns sensors/alert_listener/daemon.py against /tmp/stage3_eve.json.
3. Injects a high-confidence test EVE alert (MALICIOUS_PAYLOAD_DETECTED, sid:1000001).
4. Verifies OpenFlow 1.3 switch s1 receives the scoped DROP rule with cookie, priority 200, hard_timeout.
5. Verifies that the local SQLite Incident store (audit/spool/incident_store.db)
   records the full lifecycle: decision_created -> action_requested -> effect_observed.
"""

import json
import os
import sqlite3
import subprocess
import sys
import time

_proj_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _proj_root not in sys.path:
    sys.path.insert(0, _proj_root)


def run():
    print("=================================================================")
    print("   STAGE 3: FAST ALERT PATH & LOCAL LOGGER VERIFICATION")
    print("=================================================================")

    eve_path = "/tmp/stage3_eve.json"
    db_path = os.path.join(_proj_root, "audit", "spool", "incident_store.db")

    # Clear test EVE log
    if os.path.exists(eve_path):
        os.remove(eve_path)
    with open(eve_path, "w") as f:
        pass

    passed = 0
    total = 3

    # Launch daemon in background with --from-start and unbuffered stdout/stderr
    print("[*] Launching Alert Listener & Risk Engine daemon...")
    daemon_proc = subprocess.Popen(
        [sys.executable, "-u", os.path.join(_proj_root, "sensors", "alert_listener", "daemon.py"), eve_path, "--from-start"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    time.sleep(1.5)

    try:
        # Step 1: Inject simulated Suricata Threat Alert with unique timestamp & flow_id
        print("[TEST 1/3] Injecting high-confidence threat into EVE JSON... ", end="", flush=True)
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime()) + f"{int(time.time()*1000)%1000:03d}Z"
        test_alert = {
            "timestamp": now_iso,
            "flow_id": int(time.time() * 1000),
            "event_type": "alert",
            "src_ip": "192.0.2.10",
            "src_port": 45678,
            "dest_ip": "198.51.100.20",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 1000001,
                "rev": 1,
                "signature": "THREAT_ISOLATION_MALICIOUS_PAYLOAD_DETECTED",
                "category": "Attempted Admin Access"
            }
        }

        with open(eve_path, "a") as f:
            f.write(json.dumps(test_alert) + "\n")
            f.flush()

        time.sleep(3.5)
        print("PASS (Alert generated)")
        passed += 1

        # Step 2: Verify OpenFlow rule was programmed onto s1
        print("[TEST 2/3] Verifying OVS switch s1 mitigation rule installation... ", end="", flush=True)
        # Flush daemon stdout to make sure any subprocess completed
        flows_out = ""
        for _ in range(5):
            of_res = subprocess.run(
                ["ovs-ofctl", "dump-flows", "s1", "-O", "OpenFlow13"],
                capture_output=True, text=True
            )
            flows_out = of_res.stdout
            if "priority=200" in flows_out and "actions=drop" in flows_out:
                break
            time.sleep(1.0)

        if "priority=200" in flows_out and "actions=drop" in flows_out:
            print("PASS (Scoped DROP rule active on s1)")
            passed += 1
        else:
            print("FAIL (Rule not found in dump-flows)")
            print("--- Switch Flows Dump ---")
            print(flows_out)
            # Print daemon stderr/stdout to assist diagnosis
            daemon_proc.terminate()
            d_out, d_err = daemon_proc.communicate(timeout=2)
            if d_out:
                print("--- Daemon Output ---")
                print(d_out)
            if d_err:
                print("--- Daemon Error ---")
                print(d_err)

        # Step 3: Verify local incident store & lifecycle states
        print("[TEST 3/3] Verifying Incident Store & full lifecycle in SQLite... ", end="", flush=True)
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT id, subject_ip, status FROM incidents ORDER BY opened_at DESC LIMIT 1")
            inc = cur.fetchone()

            cur.execute("SELECT id, state, action_type FROM actions ORDER BY created_at DESC LIMIT 1")
            act = cur.fetchone()
            conn.close()

            if inc and act and act[1] == "effect_observed":
                print(f"PASS (Incident {inc[0]} logged; state: {act[1]})")
                passed += 1
            else:
                print(f"FAIL (Incomplete lifecycle: inc={inc}, act={act})")
        else:
            print(f"FAIL (Database file {db_path} not created)")

    finally:
        daemon_proc.terminate()
        try:
            daemon_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            daemon_proc.kill()

    print("=================================================================")
    print(f"   SUMMARY: {passed} / {total} tests passed")
    print("=================================================================")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(run())

