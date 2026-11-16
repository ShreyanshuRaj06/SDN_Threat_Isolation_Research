#!/usr/bin/env python3
"""
experiments/run_all_tests.py

Master test runner for all implemented phases (Phases 1 through 5).
Runs all unit tests, model verification, and cryptographic sealing suites.
"""

import sys
import os
import subprocess
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def run_command(desc: str, cmd: list) -> bool:
    print(f"\n{'='*70}")
    print(f"▶ RUNNING: {desc}")
    print(f"{'='*70}")
    env = os.environ.copy()
    env["PYTHONPATH"] = PROJECT_ROOT

    t0 = time.monotonic()
    proc = subprocess.run(cmd, env=env, cwd=PROJECT_ROOT)
    elapsed = time.monotonic() - t0

    if proc.returncode == 0:
        print(f"\n✔ {desc} PASSED ({elapsed:.2f}s)")
        return True
    else:
        print(f"\n✘ {desc} FAILED with return code {proc.returncode} ({elapsed:.2f}s)")
        return False


def main():
    print("=" * 70)
    print("       AI-DRIVEN SDN THREAT ISOLATION - MASTER VERIFICATION")
    print("=" * 70)

    suites = [
        ("Full Unit Test Suite (38 tests: Phases 1 to 6)", [sys.executable, "-m", "pytest", "tests/", "-v"]),
        ("Stage 4 Verification: AI Inference & Corroboration", [sys.executable, "experiments/verify_stage4.py"]),
        ("Stage 5 Verification: Cryptographic Evidence Sealing", [sys.executable, "experiments/verify_stage5.py"]),
        ("Stage 6 Verification: Resilience, Reconcile & Adaptive Polling", [sys.executable, "experiments/verify_stage6.py"]),
    ]

    results = []
    for desc, cmd in suites:
        ok = run_command(desc, cmd)
        results.append((desc, ok))

    print("\n" + "=" * 70)
    print("                       VERIFICATION SUMMARY")
    print("=" * 70)
    all_passed = True
    for desc, ok in results:
        status = "PASS" if ok else "FAIL"
        symbol = "✔" if ok else "✘"
        print(f"  [{status}] {symbol} {desc}")
        if not ok:
            all_passed = False

    print("=" * 70)
    if all_passed:
        print("  ALL OFFLINE SUITES PASSED (Phases 1 through 5 verified)")
        print("\n  To verify Live Mininet/OVS (Stages 2 & 3), run in WSL:")
        print("    1. Terminal A: cd ~/acnproject && source ~/ryu_venv/bin/activate && ryu-manager controller/ryu_app/sdn_controller.py")
        print("    2. Terminal B: cd ~/acnproject && sudo python3 lab/topology/mininet_topo.py")
        print("    3. Terminal C: cd ~/acnproject && sudo python3 experiments/verify_stage2_runner.py")
        print("                   cd ~/acnproject && sudo python3 experiments/verify_stage3.py")
    else:
        print("  SOME SUITES FAILED")
    print("=" * 70)

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()

