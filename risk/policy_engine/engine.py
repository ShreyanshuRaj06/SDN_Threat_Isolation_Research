#!/usr/bin/env python3
"""
risk/policy_engine/engine.py

Phase 3: Risk Policy Engine (Rule-based Baseline)
References: PRD (Section 5, MVP 5), PDF Section 8 & 9, AGENTS.md, API.md (/v1/actions)

Key Responsibilities:
1. Receives normalized security events (from Suricata EVE listener, Gateway, or future AI models).
2. Evaluates evidence against policy rules:
   - High-confidence signature match -> temporary narrow DROP rule or quarantine.
   - Ambiguous / unverified source -> monitor or rate-limit (never disconnect legitimate users).
3. Constructs authorized, scoped, expiring EnforcementActionRequest with:
   - Unique action_id and rule_cookie
   - Scoped match (never src_ip alone)
   - Explicit priority (200) and hard timeout (e.g. 60s)
   - Evidence references linking back to sensor event
4. Enforces the strict action lifecycle:
   decision_created -> action_requested -> controller_accepted -> rule_processed -> effect_observed
"""

import time
import uuid
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

from controller.ryu_app.enforcement_types import (
    EnforcementActionRequest,
    EnforcementMatch,
    ActionState
)
from sensors.alert_listener.listener import NormalizedAlert


@dataclass
class PolicyDecision:
    decision_id: str
    incident_id: str
    action_type: str                   # temporary_drop, rate_limit, quarantine, monitor
    approved: bool
    reason: str
    action_request: Optional[EnforcementActionRequest] = None
    created_at: float = field(default_factory=time.time)


class RiskPolicyEngine:
    def __init__(self, policy_version: str = "p1", default_ttl_s: int = 60):
        self.policy_version = policy_version
        self.default_ttl_s = default_ttl_s
        self._cookie_counter = 4096  # Starting cookie sequence (0x1000+)
        self.decisions_history: Dict[str, PolicyDecision] = {}

    def _next_cookie(self) -> int:
        self._cookie_counter += 1
        return self._cookie_counter

    def evaluate_suricata_alert(self, alert: NormalizedAlert, switch_id: str = "s1") -> PolicyDecision:
        """
        Evaluates an incoming validated Suricata alert and decides appropriate action.
        """
        decision_id = f"dec-{uuid.uuid4().hex[:8]}"
        incident_id = f"inc-{uuid.uuid4().hex[:8]}"

        # Rule 1: High-confidence payload detection (e.g. malicious test exploit)
        # Authorizes a narrow temporary drop for the exact connection flow
        if "MALICIOUS" in alert.signature.upper() or alert.signature_id == 1000001:
            match = EnforcementMatch(
                ipv4_src=alert.subject_ip,
                ipv4_dst=alert.dest_ip,
                ip_proto=6,  # TCP
                tcp_dst=alert.dest_port
            )
            cookie = self._next_cookie()

            action_req = EnforcementActionRequest(
                incident_id=incident_id,
                action_id=f"act-{uuid.uuid4().hex[:8]}",
                switch_id=switch_id,
                match=match,
                action_type="temporary_drop",
                priority=200,
                ttl_s=self.default_ttl_s,
                rule_cookie=cookie,
                policy_version=self.policy_version,
                evidence_refs=[alert.event_id]
            )

            decision = PolicyDecision(
                decision_id=decision_id,
                incident_id=incident_id,
                action_type="temporary_drop",
                approved=True,
                reason=f"High-confidence signature match: {alert.signature}",
                action_request=action_req
            )

        # Rule 2: Reconnaissance / Port Scan (e.g. 1000002)
        # Lower confidence / exploratory: temporary quarantine or monitor
        elif "RECON" in alert.signature.upper() or alert.signature_id == 1000002:
            match = EnforcementMatch(
                ipv4_src=alert.subject_ip,
                ipv4_dst=alert.dest_ip,
                ip_proto=6
            )
            cookie = self._next_cookie()

            action_req = EnforcementActionRequest(
                incident_id=incident_id,
                action_id=f"act-{uuid.uuid4().hex[:8]}",
                switch_id=switch_id,
                match=match,
                action_type="quarantine",
                priority=200,
                ttl_s=30,  # Shorter observation quarantine
                rule_cookie=cookie,
                policy_version=self.policy_version,
                evidence_refs=[alert.event_id]
            )

            decision = PolicyDecision(
                decision_id=decision_id,
                incident_id=incident_id,
                action_type="quarantine",
                approved=True,
                reason=f"Reconnaissance behavior: quarantine to VLAN 999 for observation",
                action_request=action_req
            )

        else:
            # Low-confidence or unclassified: Monitor only, do not disrupt legitimate hosts
            decision = PolicyDecision(
                decision_id=decision_id,
                incident_id=incident_id,
                action_type="monitor",
                approved=False,
                reason=f"Low-confidence alert ({alert.signature}): monitoring only, no blocking action",
                action_request=None
            )

        self.decisions_history[decision_id] = decision
        return decision

