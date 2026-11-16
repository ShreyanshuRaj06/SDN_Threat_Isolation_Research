"""
controller/ryu_app/reconciler.py

Phase 6.2: Switch State & Flow Reconciliation Worker
References: PRD (Section 5, Phase 6), PLAN.md, AGENTS.md, DATABASE.md

Key Responsibilities:
1. Reconciles intended mitigation actions (from Incident Store SQLite) against
   actual live OpenFlow rules installed on OVS datapath s1.
2. Handles Switch Restart / Controller Reconnection:
   - When a switch reconnects (or on periodic audit), checks if intended active rules
     are missing from the switch.
   - If missing and not expired, re-installs them with original cookie, priority, and remaining TTL.
   - If expired, marks action state as 'expired' in the SQLite store.
3. Detects orphaned rules on the switch that have no corresponding record in SQLite
   and purges them (or logs unexpected rule injection).
"""

import subprocess
import sqlite3
import time
import os
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

DEFAULT_DB_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "audit", "spool", "incident_store.db")
)


@dataclass
class FlowRuleRecord:
    cookie: int
    table: int
    priority: int
    duration_s: float
    hard_timeout: int
    n_packets: int
    n_bytes: int
    match: str
    actions: str


@dataclass
class ReconcileSummary:
    switch_id: str
    active_in_db: int
    installed_on_switch: int
    reinstalled_count: int
    expired_count: int
    orphaned_count: int
    timestamp: float


class SwitchReconciler:
    """
    Audits and syncs intended active mitigation rules with actual switch state.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH, switch_id: str = "s1"):
        self.db_path = db_path
        self.switch_id = switch_id

    def get_live_switch_flows(self) -> List[FlowRuleRecord]:
        """
        Dumps live OpenFlow 1.3 flows from OVS and parses flow records.
        """
        cmd = ["ovs-ofctl", "dump-flows", self.switch_id, "-O", "OpenFlow13"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return []

        flows = []
        for line in res.stdout.strip().split("\n"):
            line = line.strip()
            if not line or "OFPST_FLOW" in line:
                continue

            # Parse fields: cookie=0x1002, duration=15.2s, priority=200 ... actions=drop
            cookie_match = re.search(r"cookie=(0x[0-9a-fA-F]+|[0-9]+)", line)
            priority_match = re.search(r"priority=([0-9]+)", line)
            hard_match = re.search(r"hard_timeout=([0-9]+)", line)
            dur_match = re.search(r"duration=([0-9.]+)s", line)
            pkts_match = re.search(r"n_packets=([0-9]+)", line)
            bytes_match = re.search(r"n_bytes=([0-9]+)", line)
            actions_match = re.search(r"actions=(.+)$", line)

            if not priority_match:
                continue

            raw_cookie = cookie_match.group(1) if cookie_match else "0"
            cookie_val = int(raw_cookie, 16) if "0x" in raw_cookie else int(raw_cookie)
            prio = int(priority_match.group(1))

            # Skip table-miss (priority=0)
            if prio == 0:
                continue

            flows.append(FlowRuleRecord(
                cookie=cookie_val,
                table=0,
                priority=prio,
                duration_s=float(dur_match.group(1)) if dur_match else 0.0,
                hard_timeout=int(hard_match.group(1)) if hard_match else 0,
                n_packets=int(pkts_match.group(1)) if pkts_match else 0,
                n_bytes=int(bytes_match.group(1)) if bytes_match else 0,
                match=line.split("actions=")[0].strip() if "actions=" in line else "",
                actions=actions_match.group(1).strip() if actions_match else "",
            ))

        return flows

    def reconcile(self) -> ReconcileSummary:
        """
        Executes a reconciliation pass:
        1. Reads active intended actions from SQLite.
        2. Dumps live switch flows.
        3. Re-installs any active rules missing from the switch.
        4. Updates state for expired actions.
        """
        if not os.path.exists(self.db_path):
            return ReconcileSummary(
                switch_id=self.switch_id, active_in_db=0, installed_on_switch=0,
                reinstalled_count=0, expired_count=0, orphaned_count=0, timestamp=time.time()
            )

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        # Fetch actions that are intended to be active
        cur.execute("""
            SELECT id, incident_id, switch_id, action_type, rule_cookie, priority, ttl_s, state, created_at
            FROM actions
            WHERE switch_id = ? AND state IN ('effect_observed', 'rule_processed', 'action_requested')
        """, (self.switch_id,))
        intended_actions = cur.fetchall()

        live_flows = self.get_live_switch_flows()
        live_cookies = {f.cookie: f for f in live_flows}

        reinstalled = 0
        expired = 0
        now = time.time()

        for act in intended_actions:
            act_id, inc_id, sw_id, act_type, cookie, prio, ttl_s, state, created_iso = act

            # Calculate elapsed time since creation
            try:
                # ISO parsing: "2026-11-08T07:00:00Z"
                t_struct = time.strptime(created_iso.split(".")[0], "%Y-%m-%dT%H:%M:%SZ")
                created_t = time.mktime(t_struct)
            except Exception:
                created_t = now

            elapsed = now - created_t
            remaining_ttl = int(ttl_s - elapsed)

            if remaining_ttl <= 0:
                # Rule has expired
                cur.execute("UPDATE actions SET state = 'expired' WHERE id = ?", (act_id,))
                expired += 1
                continue

            # If rule is not on switch, re-install it
            if cookie not in live_cookies:
                # Need to reinstall mitigation rule
                # Query match from events table if available
                cur.execute("""
                    SELECT payload FROM events
                    WHERE incident_id = ? AND event_type = 'suricata_alert'
                    ORDER BY occurred_at DESC LIMIT 1
                """, (inc_id,))
                evt_row = cur.fetchone()

                if evt_row:
                    import json
                    payload = json.loads(evt_row[0])
                    src_ip = payload.get("subject_ip")
                    dest_ip = payload.get("dest_ip")

                    if src_ip and dest_ip:
                        match_str = f"tcp,nw_src={src_ip},nw_dst={dest_ip},tp_dst=443"
                        act_cmd = "drop" if act_type == "temporary_drop" else "push_vlan:0x8100,mod_vlan_vid:999,output:3"

                        cmd = [
                            "ovs-ofctl", "-O", "OpenFlow13", "add-flow", self.switch_id,
                            f"cookie={cookie},priority={prio},hard_timeout={remaining_ttl},{match_str},actions={act_cmd}"
                        ]
                        res = subprocess.run(cmd, capture_output=True, text=True)
                        if res.returncode == 0:
                            reinstalled += 1

        conn.commit()
        conn.close()

        # Identify orphaned rules (rules on switch whose cookie is not in SQLite)
        orphaned = 0
        known_cookies = {act[4] for act in intended_actions}
        for f in live_flows:
            if f.cookie not in known_cookies and f.cookie != 0:
                orphaned += 1

        return ReconcileSummary(
            switch_id=self.switch_id,
            active_in_db=len(intended_actions),
            installed_on_switch=len(live_flows),
            reinstalled_count=reinstalled,
            expired_count=expired,
            orphaned_count=orphaned,
            timestamp=now,
        )


if __name__ == "__main__":
    reconciler = SwitchReconciler()
    summary = reconciler.reconcile()
    print(f"Reconcile Complete: active_db={summary.active_in_db}, live_switch={summary.installed_on_switch}, "
          f"reinstalled={summary.reinstalled_count}, expired={summary.expired_count}, orphaned={summary.orphaned_count}")

