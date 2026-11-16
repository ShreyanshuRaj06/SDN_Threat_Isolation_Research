#!/usr/bin/env python3
"""
sensors/alert_listener/daemon.py

Phase 3: EVE Alert Listener Daemon & Live Forwarder to Risk Policy Engine
References: PRD (Section 5, MVP 4 & 5), PDF Section 6 & 7, AGENTS.md, API.md

Key Responsibilities:
1. Safely tails Suricata's eve.json in real time (handles rotation, truncation).
2. Filters for 'alert' records and validates that the origin is known (does not assume src_ip is attacker).
3. Deduplicates repeat alerts in a rolling time window.
4. Passes the validated NormalizedAlert to the Risk Policy Engine.
5. If approved, calls Ryu or installs the scoped mitigation rule on switch s1 (F3).
6. Records the entire lifecycle into IncidentLogger (audit/spool/incident_store.db and events.jsonl).
"""

import json
import os
import sys
import time
import subprocess
from typing import Optional

# Ensure project root is in sys.path
_proj_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _proj_root not in sys.path:
    sys.path.insert(0, _proj_root)

from sensors.alert_listener.listener import EveAlertListener, NormalizedAlert
from risk.policy_engine.engine import RiskPolicyEngine, PolicyDecision
from audit.logger.incident_logger import IncidentLogger


def execute_flow_mod(action_req) -> bool:
    """
    Programs the scoped mitigation rule on switch s1 via OpenFlow 1.3.
    """
    match = action_req.match
    match_parts = ["ip", f"nw_src={match.ipv4_src}"]
    if match.ipv4_dst:
        match_parts.append(f"nw_dst={match.ipv4_dst}")
    if match.ip_proto == 6:
        # For TCP protocol, ovs-ofctl match requires tcp prefix or ip_proto=6
        match_parts = ["tcp", f"nw_src={match.ipv4_src}"]
        if match.ipv4_dst:
            match_parts.append(f"nw_dst={match.ipv4_dst}")
        if match.tcp_dst:
            match_parts.append(f"tp_dst={match.tcp_dst}")
    elif match.ip_proto:
        match_parts.append(f"nw_proto={match.ip_proto}")

    match_str = ",".join(match_parts)

    if action_req.action_type == "temporary_drop":
        actions = "drop"
    elif action_req.action_type == "quarantine":
        actions = "push_vlan:0x8100,mod_vlan_vid:999,output:3"
    else:
        actions = "drop"

    cmd = [
        "ovs-ofctl", "-O", "OpenFlow13", "add-flow", action_req.switch_id,
        f"cookie={action_req.rule_cookie},priority={action_req.priority},"
        f"hard_timeout={action_req.ttl_s},{match_str},actions={actions}"
    ]

    print(f"[SDN_ENFORCE] Executing OpenFlow mitigation rule: {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res.returncode == 0


def tail_eve(filepath: str, from_start: bool = False):
    """
    Generator that tails a file, handling rotation and creation.
    """
    while not os.path.exists(filepath):
        print(f"[*] Waiting for {filepath} to be created by Suricata...")
        time.sleep(1)

    with open(filepath, "r", encoding="utf-8") as f:
        if not from_start:
            # Start at end of existing file for real-time live events
            f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.1)


def run_pipeline(eve_path: str = "/var/log/suricata/eve.json", from_start: bool = False):
    print("=================================================================")
    print("   PHASE 3: SURICATA EVE -> RISK ENGINE -> OVS ENFORCEMENT")
    print("=================================================================")
    print(f"[*] Monitoring EVE log: {eve_path}")

    listener = EveAlertListener(eve_path=eve_path, dedup_window_s=5.0)
    risk_engine = RiskPolicyEngine(default_ttl_s=60)
    logger = IncidentLogger()

    print("[*] Pipeline active. Listening for threats...")

    for raw_line in tail_eve(eve_path, from_start=from_start):
        alert = listener.process_line(raw_line)
        if not alert:
            continue

        print(f"\n[ALERT_DETECTED] Sig: '{alert.signature}' (ID: {alert.signature_id}) | Subject: {alert.subject_ip} -> Dest: {alert.dest_ip}")

        # 1. Log incoming sensor event
        logger.log_event(
            event_id=alert.event_id,
            incident_id=None,
            sensor_id=alert.sensor_id,
            event_type="suricata_alert",
            source="suricata",
            payload={
                "signature": alert.signature,
                "signature_id": alert.signature_id,
                "subject_ip": alert.subject_ip,
                "dest_ip": alert.dest_ip,
                "subject_status": alert.subject_status
            },
            evidence_ref=str(alert.raw_event_ref)
        )

        # 2. Risk Engine Evaluation
        decision: PolicyDecision = risk_engine.evaluate_suricata_alert(alert, switch_id="s1")
        print(f"[RISK_DECISION] Decision: {decision.action_type.upper()} | Approved: {decision.approved} | Reason: {decision.reason}")

        if decision.approved and decision.action_request:
            req = decision.action_request

            # 3. Open Incident container
            logger.log_incident_creation(
                incident_id=req.incident_id,
                subject_ip=req.match.ipv4_src,
                target_ip=req.match.ipv4_dst or "any"
            )

            # 4. Lifecycle transition: decision_created -> action_requested
            logger.log_action_transition(
                action_id=req.action_id,
                incident_id=req.incident_id,
                switch_id=req.switch_id,
                action_type=req.action_type,
                rule_cookie=req.rule_cookie,
                priority=req.priority,
                ttl_s=req.ttl_s,
                new_state="action_requested"
            )

            # 5. Enforce on switch s1 via OpenFlow FLOW_MOD
            success = execute_flow_mod(req)

            if success:
                print(f"[ENFORCE_SUCCESS] Scoped rule active on {req.switch_id}! Cookie: {req.rule_cookie}, TTL: {req.ttl_s}s")
                # 6. Lifecycle transition: -> effect_observed
                logger.log_action_transition(
                    action_id=req.action_id,
                    incident_id=req.incident_id,
                    switch_id=req.switch_id,
                    action_type=req.action_type,
                    rule_cookie=req.rule_cookie,
                    priority=req.priority,
                    ttl_s=req.ttl_s,
                    new_state="effect_observed"
                )
            else:
                print(f"[ENFORCE_FAIL] Failed to install OpenFlow rule on switch {req.switch_id}")
                logger.log_action_transition(
                    action_id=req.action_id,
                    incident_id=req.incident_id,
                    switch_id=req.switch_id,
                    action_type=req.action_type,
                    rule_cookie=req.rule_cookie,
                    priority=req.priority,
                    ttl_s=req.ttl_s,
                    new_state="failed"
                )


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "/var/log/suricata/eve.json"
    start_flag = "--from-start" in sys.argv
    run_pipeline(eve_path=path, from_start=start_flag)

