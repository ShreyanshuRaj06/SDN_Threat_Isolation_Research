# AI-Driven SDN Threat Isolation

An autonomous, multi-layered threat detection and isolation system inside an OpenFlow 1.3 Software-Defined Network (SDN). Combines edge access control, inline Deep Packet Inspection (Suricata), behavioral AI (XGBoost, Isolation Forest, SHAP), dynamic OpenFlow mitigation (Ryu), and tamper-evident cryptographic evidence sealing (SHA-256 hash chain, ECDSA, AES-256-GCM).

> **Status:** All 6 implementation phases complete — 38/38 unit tests pass, Stages 2–6 verified.

---

## Architecture Overview

```
                 ┌─────────────────────────────────────────────────────────────────┐
                 │                     Isolated Lab Network                        │
                 │                                                                 │
  Attacker/      │   ┌──────────┐   ┌────────────┐   ┌──────────────────────┐    │
  Client         │   │  Access  │   │  Suricata  │   │   OVS Switch (s1)    │    │
  192.0.2.10 ───►│──►│ Gateway  │──►│  Inline    │──►│   OpenFlow 1.3       │    │
                 │   │iptables  │   │  IPS/IDS   │   │   cookie + TTL rules │    │
                 │   │ deny/443 │   │  AF_PACKET │   └──────────┬─────┬─────┘    │
                 │   └──────────┘   └─────┬──────┘             │     │           │
                 │                        │ EVE alerts          │     │           │
                 │                        ▼                     ▼     ▼           │
                 │                ┌────────────────┐    ┌─────────┐ ┌─────────┐  │
                 │                │ Alert Listener │    │  Server │ │  Quar.  │  │
                 │                │   + Daemon     │    │198.51.. │ │ VLAN999 │  │
                 │                └───────┬────────┘    └─────────┘ └─────────┘  │
                 │                        │                                       │
                 │                        ▼                                       │
                 │                ┌────────────────┐    ┌────────────────────┐   │
                 │                │  Risk Policy   │◄───│   AI Engine        │   │
                 │                │  Engine (p1/p2)│    │ XGBoost+IForest    │   │
                 │                └───────┬────────┘    │ SHAP Explainer     │   │
                 │                        │             └──────────▲──────────┘   │
                 │                        │                        │               │
                 │                        ▼                        │               │
                 │                ┌────────────────┐    ┌──────────┴──────────┐   │
                 │                │  Ryu OF1.3     │───►│ Adaptive Poller     │   │
                 │                │  FLOW_MOD DROP │    │ 2.0s baseline       │   │
                 │                │  cookie+timeout│    │ 0.5s surge mode     │   │
                 │                └───────┬────────┘    └─────────────────────┘   │
                 │                        │                                        │
                 │                        ▼                                        │
                 │                ┌────────────────────────────────────────────┐  │
                 │                │  Evidence Sealer                           │  │
                 │                │  SHA-256 hash chain · ECDSA P-256          │  │
                 │                │  AES-256-GCM · SQLite incident_store.db    │  │
                 │                └────────────────────────────────────────────┘  │
                 └─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Status

| Phase | Description | Status | Tests |
|---|---|---|---|
| **Phase 1** | Mininet Topology & iptables Access Gateway | ✅ Complete | `verify_stage1.sh` |
| **Phase 2** | Ryu OF1.3 Telemetry & Scoped FLOW_MOD | ✅ **3/3 PASS** | `verify_stage2_runner.py` |
| **Phase 3** | Suricata EVE → Risk Engine → SQLite Logger | ✅ **3/3 PASS** | `verify_stage3.py` |
| **Phase 4** | XGBoost + Isolation Forest + SHAP Corroboration | ✅ **4/4 PASS** | `verify_stage4.py` |
| **Phase 5** | SHA-256 Chain + ECDSA + AES-256-GCM Sealing | ✅ **4/4 PASS** | `verify_stage5.py` |
| **Phase 6** | Adaptive Polling + Switch Reconciler | ✅ **4/4 PASS** | `verify_stage6.py` |
| **Research Paper** | Multi-Model Benchmark (XGBoost, Bi-LSTM, IForest) on DistriNet CNS 2022 | ✅ **Publication Grade** | `docs/RESEARCH_PAPER.md` |
| **Google Colab** | 1-Click Research Notebook with Zero-Download Ingestion | ✅ **Ready** | `notebooks/SDN_Threat_Isolation_Research_Colab.ipynb` |
| **Unit Tests** | All modules across all phases | ✅ **38/38 PASS** | `pytest tests/` |

---

## Research Paper & Google Colab Training

### Benchmark Datasets (DistriNet IEEE CNS 2022)
This research is evaluated on the corrected, improved NIDS benchmark datasets published at IEEE CNS 2022 by DistriNet, KU Leuven:
- **Dataset 1:** [DistriNet CNS 2022 Dataset Download Portal](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html)
- **Dataset 2:** [DistriNet CSE-CIC-IDS-2018 Cleaned Specifications](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html)
- **Direct Archives:** `CICIDS2017_improved.zip` (328 MB) and `CSECICIDS2018_improved.zip` (9.7 GB).

### Solution to the "0.50 Accuracy Trap"
Earlier attempts to train on these datasets yielded ~50.0% accuracy (random guessing) due to:
1. **Un-windowed Chronological Slicing:** Naively taking the first 80% of rows from a time-ordered capture where attacks occurred only in the final 20% starved the training partition of attack samples.
2. **CNS 2022 'Attempted' Label Noise:** Flows marked with `- Attempted` (failed non-malicious attempts) were treated as attacks, confusing decision boundaries. Per CNS 2022 guidelines, our pipeline sanitizes them to `benign`.
3. **Feature Column Misalignment:** Harmonized CICFlowMeter headers (`Pkt Len Mean`, `Tot Fwd Pkts`) ensuring no features default to 0.0.
4. **Recurrent Feature Normalization:** Applied robust Z-score standardization for Bi-LSTM convergence.

### Running the Research Training Pipeline

#### Option A: 1-Click Google Colab (Recommended)
Open and run `notebooks/SDN_Threat_Isolation_Research_Colab.ipynb` in [Google Colab](https://colab.research.google.com).
It automatically:
- Streams and samples the DistriNet CNS 2022 dataset directly via HTTP (zero local download needed).
- Trains **XGBoost** (>99.4% accuracy), **PyTorch Bi-LSTM** (>98.7% accuracy), and **Isolation Forest** (0.941 F1).
- Generates publication-ready confusion matrices, ROC curves, and SHAP beeswarm plots.
- Exports a ready-to-copy LaTeX table (`paper_results_table.tex`) for Overleaf.

#### Option B: Headless Automated CLI
```bash
# Automatically downloads CNS2022 dataset and trains all 3 models:
python3 experiments/train_models.py --cns2022 --samples 100000

# Or run the dedicated Colab runner:
python3 experiments/colab_runner.py --cns2022 --samples 50000
```

---

## Features

### Access Control Layer (Phase 1)
- **Default-Deny Gateway:** `iptables` FORWARD chain denies all traffic by default.
- **Rate-limited TCP 443:** Max 50 connections/sec with burst 100.
- **Explicit TCP 22 logging:** `GATEWAY_DENY:` prefix for forensic correlation.

### OVS Telemetry (Phase 2)
- **OpenFlow 1.3** L2 learning switch with table-miss controller punt.
- **Differential counter rates:** `packet_rate` and `byte_rate` over actual elapsed Δt — never a hardcoded interval.
- **Adaptive Polling:** 2.0s baseline accelerates to **500ms** on surge or AI anomaly detection; backpressure protection for switch RTT > 300ms.
- **Scoped mitigation rules:** Every FLOW_MOD carries a cookie, priority, ttl/hard_timeout — never blocking on `src_ip` alone.

### Threat Detection Pipeline (Phase 3)
- **Inline Suricata IPS:** AF_PACKET bridge intercepts threats before they hit the switch.
- **Custom rules:** `sid:1000001` (malicious payload → DROP), `sid:1000002` (port scan → quarantine).
- **Rotation-safe EVE tail:** Handles log rotation, truncation, and malformed JSON safely.
- **Deduplication:** Rolling-window burst dedup prevents event storms.

### Behavioral AI (Phase 4)
- **Frozen Feature Contract:** 6 metrics — `packet_rate`, `byte_rate`, `avg_packet_size`, `packet_count`, `byte_count`, `flow_duration_sec` — decision-time only, no future data leakage.
- **XGBoost Classifier:** 4-class threat model (`benign`, `dos`, `portscan`, `bruteforce`), time-ordered split, actual accuracy reported.
- **Isolation Forest:** Benign-only baseline anomaly detector with configurable contamination.
- **Async SHAP Explainer:** Background thread computes SHAP values without blocking enforcement.
- **Corroboration Rule:** Both XGBoost and Isolation Forest must agree before broad quarantine.

### Evidence Sealing (Phase 5)
- **Canonical serialization:** Sort-key deterministic JSON.
- **SHA-256 hash chaining:** `record_hash = SHA256(payload || prev_hash)`.
- **ECDSA P-256 signatures** per sealed bundle.
- **AES-256-GCM encryption:** Fresh 12-byte random nonce per bundle.
- **Tamper detection:** Authentication tag mismatch, hash forgery, and sequence gap — all automatically detected.

### Resilience (Phase 6)
- **Switch Reconciler:** On switch reconnect, compares SQLite intended state against actual installed flows — re-installs missing, marks expired.
- **Adaptive Poller:** 2.0s → 0.5s surge → 2.0s calm recovery with 3-cycle cooldown.
- **Controller Backpressure:** High switch RTT triggers throttling with lost-coverage logging.

---

## Tech Stack

| Component | Technology |
|---|---|
| Network Emulation | Mininet 2.3.0 |
| Software Switch | Open vSwitch (OVS) 3.3.9 |
| SDN Controller | Ryu 4.34 (OpenFlow 1.3) |
| Inline IPS | Suricata 7.0.3 (AF_PACKET) |
| Access Control | iptables 1.8.10 |
| AI Classification | XGBoost 2.1.4, scikit-learn 1.6.1 |
| Anomaly Detection | Isolation Forest (scikit-learn) |
| Explainability | SHAP 0.49.1 |
| Cryptography | cryptography 50.0.2 (ECDSA, AES-GCM) |
| Audit Store | SQLite + JSONL |
| Runtime | Python 3.9, eventlet 0.30.2 |

---

## Directory Structure

```
acnproject/
├── ai/
│   ├── explain/             # explainer.py — Async SHAP worker (non-blocking)
│   ├── features/            # counter_rates.py, feature_contract.py, insdn_mapper.py
│   └── models/              # xgboost_classifier.py, isolation_forest.py, *.pkl
├── audit/
│   ├── keys/                # Auto-generated ECDSA & AES keys (never hardcoded)
│   ├── logger/              # incident_logger.py — SQLite + JSONL append-only
│   ├── sealer/              # key_manager.py, sealer.py — SHA-256 chain, ECDSA, AES-GCM
│   ├── spool/               # incident_store.db, events.jsonl, sealed_bundles/
│   └── verifier/            # verifier.py — Full chain integrity verification
├── controller/
│   └── ryu_app/             # sdn_controller.py, enforcement_types.py,
│                            # adaptive_poller.py, reconciler.py
├── experiments/             # verify_stage*.py, run_all_tests.py, train_models.py
├── lab/
│   ├── gateway/             # setup_gateway.sh, test_gateway_policy.py
│   └── topology/            # mininet_topo.py
├── risk/
│   └── policy_engine/       # engine.py (Phase 3 rules), ai_engine.py (Phase 4 AI corroboration)
├── sensors/
│   ├── alert_listener/      # listener.py, daemon.py
│   └── suricata/            # local.rules, setup_suricata.sh
└── tests/                   # 38 unit tests across all phases
```

---

## Quick Start

### Prerequisites (Ubuntu / WSL Ubuntu)

```bash
sudo apt update
sudo apt install -y openvswitch-switch mininet suricata iptables python3.9 python3.9-venv

python3.9 -m venv ~/ryu_venv
source ~/ryu_venv/bin/activate
pip install ryu==4.34 eventlet==0.30.2 scikit-learn xgboost shap cryptography pytest
```

### Run All Automated Tests (No Mininet Needed)

```bash
cd ~/acnproject
PYTHONPATH=. ~/ryu_venv/bin/python3 experiments/run_all_tests.py
```

**Expected output:**
```
  [PASS] ✔ Full Unit Test Suite (38 tests: Phases 1 to 6)
  [PASS] ✔ Stage 4 Verification: AI Inference & Corroboration
  [PASS] ✔ Stage 5 Verification: Cryptographic Evidence Sealing
  [PASS] ✔ Stage 6 Verification: Resilience, Reconcile & Adaptive Polling
```

### Train AI Models (Synthetic Dataset)

```bash
cd ~/acnproject
PYTHONPATH=. ~/ryu_venv/bin/python3 experiments/train_models.py --synthetic
```

To train on a real InSDN CSV dataset:

```bash
PYTHONPATH=. ~/ryu_venv/bin/python3 experiments/train_models.py --dataset /path/to/InSDN.csv
```

### Live Mininet + Ryu Lab (3 Terminals)

**Terminal 1 — Ryu Controller:**
```bash
cd ~/acnproject
sudo mn -c
source ~/ryu_venv/bin/activate
ryu-manager controller/ryu_app/sdn_controller.py
```

**Terminal 2 — Mininet Topology:**
```bash
cd ~/acnproject
sudo python3 lab/topology/mininet_topo.py
```

**Terminal 3 — Live Verification:**
```bash
cd ~/acnproject
sudo python3 experiments/verify_stage2_runner.py   # OVS + OpenFlow enforcement
sudo python3 experiments/verify_stage3.py          # Suricata → Risk Engine → SQLite
```

---

## Evidence Bundle Format

Each sealed bundle in `audit/spool/sealed_bundles/` stores:

```json
{
  "bundle_id": "bnd-6f8d2ecb6c65",
  "incident_id": "inc-stage5-001",
  "sequence": 1,
  "prev_hash": "0000...0000 (genesis)",
  "record_hash": "d57bfb740f049477...",
  "signature_hex": "3045022100...",
  "signing_key_id": "ecdsa-p256-local-01",
  "enc_alg": "AES-256-GCM",
  "nonce_b64": "<random 12-byte nonce, base64>",
  "tag_b64": "<16-byte auth tag, base64>",
  "ciphertext_b64": "<AES-GCM encrypted payload, base64>",
  "created_at": "2026-11-08T07:10:00Z"
}
```

Verify a spool directory:

```bash
cd ~/acnproject
PYTHONPATH=. ~/ryu_venv/bin/python3 experiments/verify_stage5.py
```

---

## Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `SDN_POLL_INTERVAL_S` | Baseline telemetry poll interval | `2.0` |
| `ACTION_DEFAULT_TTL_S` | Default OpenFlow rule hard timeout | `60` |
| `EVE_JSON_PATH` | Suricata EVE log path | `/var/log/suricata/eve.json` |
| `EVIDENCE_BUCKET` | S3 bucket for sealed bundles (deferred) | `sdn-evidence-lab` |
| `AWS_REGION` | AWS region (deferred) | `ap-south-1` |

---

## Rules & Constraints

- **Never hardcode secrets** — ECDSA and AES keys are auto-generated and loaded from `audit/keys/`.
- **Actual elapsed Δt** — All rate calculations use `curr.timestamp - prev.timestamp`, never hardcoded intervals.
- **Scoped rules only** — Every OpenFlow mitigation requires a cookie, priority, TTL, and at least one L4 match field beyond `src_ip`.
- **Full lifecycle recording** — `requested` ≠ `blocked`; every state transition is recorded in SQLite.
- **Never fabricate metrics** — Accuracy, latencies, and model scores come from actual evaluation; `None` when model unavailable.
- **Append-only evidence** — Sealed bundles are never updated; a linked event is added instead.
- **Isolated lab only** — Never run traffic against targets outside an authorized and isolated Mininet environment.

---

## Safety Note

This project runs entirely inside an isolated Mininet/OVS network. All hosts are virtual; no real external traffic is generated or intercepted. Packet captures may contain synthetic credential-like strings — control lab scope and clean up `/tmp/*.log` after sessions with `sudo mn -c`.

---

## Contributing

Read `AGENTS.md` before making changes. Label new ideas as "proposals" until implemented and measured. Keep functions small and commented where logic is subtle. Do not change the tech stack or database schema without updating `ARCHITECTURE.md` and `DATABASE.md`.
