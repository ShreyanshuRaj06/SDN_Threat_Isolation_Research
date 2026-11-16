# TESTING: AI-Driven SDN Threat Isolation

Comprehensive testing suite covering unit tests, stage verification scripts, and multi-model benchmark evaluation. All 38 unit tests pass cleanly, and Stages 1–6 are verified.

## Priorities (critical first)
1. Enforcement correctness and rollback. 2. No fake outcomes (requested != blocked). 3. Safe failure modes. 4. Timing measurements. 5. Detection quality. 6. Evidence integrity.

## Test cases per feature
### Access gateway
| Scenario | Input | Expected |
|---|---|---|
| Unauthorized SSH | TCP 22 from ordinary device | Denied; absent from OVS counters; gateway event logged |
| Authorized HTTPS | TCP 443 from permitted source | Allowed |
| Rate limit | Burst above tested baseline | Limited, service remains available |
### Telemetry/features
| Scenario | Input | Expected |
|---|---|---|
| Worked example | 1,000/80,000 at t1; 1,300/104,000 at t2 (0.5 s) | 600 pkt/s, 48,000 B/s |
| Counter reset | Switch restart | Sample flagged invalid, no negative rate |
| Missing sample | Skipped poll | Uses actual elapsed time or marks gap |
### Enforcement
| Scenario | Input | Expected |
|---|---|---|
| Scoped DROP | Valid action | Rule with cookie/timeout; effect verified |
| Duplicate request | Same action_id | No duplicate rule (409/idempotent) |
| Too-broad scope | Source-IP only on shared address | 422 rejected/escalated |
| Rollback | Operator request | Exact rule removed; restoration verified |
| Controller restart | Active rule | Reconcile; no unlimited duplicates |
### Suricata + listener
| Scenario | Input | Expected |
|---|---|---|
| Inline drop | Matching traffic | Dropped; EVE alert; separate event types |
| Non-alert EVE records | flow/protocol records | Not treated as block requests |
| Malformed/rotated log | Bad line; rotation | Skipped; read position kept |
| Alert storm | Repeated identical alerts | Deduplicated; bounded queue |
| NAT / response packet | Subject ambiguous | Escalate, no blind block |
### AI/risk (V2)
| Scenario | Input | Expected |
|---|---|---|
| Feature parity | Train vs live features | Identical definitions/scaling/window |
| No future leakage | Time-split data | Evaluation uses only past observations |
| AI unavailable | Service down | Marked unavailable, no fabricated score |
| Outlier only | Isolation Forest hit | Monitor/limit, not broad quarantine |
### Evidence (V2)
| Scenario | Input | Expected |
|---|---|---|
| Seal and verify | Valid bundle | All checks pass |
| Tamper | Modified ciphertext/record | Verification fails and reports where |
| Nonce reuse guard | Two encryptions | Distinct nonces |
| Cloud outage | S3 down | Spooled, later delivered once |

## Negative and failure tests (one at a time, then combinations)
Suricata stop (verify chosen fail policy and no accidental uninspected route), Ryu disconnect (baseline policy, no silent unrestricted forwarding), AI timeout, disk full (loss recorded), clock skew, replayed/expired action request, unauthorized API call (401/403).

## Evaluation experiments
Compare: baseline OVS+Ryu+periodic AI -> +access rules -> +inline Suricata -> +adaptive polling. Same topology/workloads. Repeat across attack-start phases relative to the poll cycle. Report four latencies (median + tail), traffic reaching target, precision/recall/false positives, false blocks, throughput, CPU/RAM, audit loss. The "<15 ms" claim stays unverified until timestamped data supports a defined boundary.

## Data and mocking
Isolated lab, disposable targets, bounded rates. Use documentation IPs (192.0.2.x, 198.51.100.x). Mock S3/CloudWatch with stubs; replay recorded EVE lines for the listener.

## Coverage targets
Every decision-table row in the risk engine has a test; every lifecycle state transition tested; every failure row in the PDF's section 17 exercised.

## Commands
```bash
# Run all unit tests:
pytest tests/

# Run individual stage verifications:
sudo bash experiments/verify_stage1.sh
python3 experiments/verify_stage2_runner.py
python3 experiments/verify_stage3.py
python3 experiments/verify_stage4.py
python3 experiments/verify_stage5.py
python3 experiments/verify_stage6.py

# Run all test runners:
python3 experiments/run_all_tests.py
```

## Manual QA checklist
- [ ] Allowed/denied paths verified
- [ ] Rule scope, cookie, expiry visible in `dump-flows`
- [ ] Rollback works
- [ ] Failure policies behave as decided
- [ ] No cloud dependency on the local block path
- [ ] Evidence verifies; tamper detected
- [ ] No secrets or captures with credentials committed
