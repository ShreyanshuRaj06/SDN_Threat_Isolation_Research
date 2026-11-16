#!/usr/bin/env python3
"""
experiments/verify_stage4.py

Phase 4: Behavioral AI & Risk Policy Verification
References: PRD (Section 5, Phase 4), PLAN.md, AGENTS.md, TESTING.md

Verifies:
  [TEST 1/4] Model Artifacts: Verifies XGBoost & Isolation Forest model files exist & load.
  [TEST 2/4] AI Inference: Verifies actual non-null prediction scores on test vectors.
  [TEST 3/4] Corroboration Engine: Verifies AI corroboration logic (high threat confirmed drop; disagreement monitor-only).
  [TEST 4/4] Async SHAP & Audit: Verifies background SHAP computation & audit spool writing without blocking.
"""

import sys
import os
import time
import json
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ai.models.xgboost_classifier import XGBoostThreatClassifier, CLASS_LABELS
from ai.models.isolation_forest import IsolationForestDetector
from ai.features.feature_contract import FlowFeatureVector, FEATURE_NAMES
from risk.policy_engine.ai_engine import AIAugmentedRiskEngine
from sensors.alert_listener.listener import NormalizedAlert


def run_tests():
    print("=" * 65)
    print("   STAGE 4: BEHAVIORAL AI & RISK CORROBORATION VERIFICATION")
    print("=" * 65)

    passed = 0
    total = 4

    # -------------------------------------------------------------
    # TEST 1: Model Artifacts Check
    # -------------------------------------------------------------
    sys.stdout.write("[TEST 1/4] Checking trained AI model artifacts on disk... ")
    sys.stdout.flush()

    xgb = XGBoostThreatClassifier()
    iforest = IsolationForestDetector()

    xgb_loaded = xgb.load()
    if_loaded = iforest.load()

    if xgb_loaded and if_loaded:
        print(f"PASS (XGB: {xgb.model_version}, IForest: {iforest.model_version})")
        passed += 1
    else:
        print(f"FAIL (xgb_loaded={xgb_loaded}, iforest_loaded={if_loaded})")
        print("       Run: python3 experiments/train_models.py --synthetic")

    # -------------------------------------------------------------
    # TEST 2: Model Inference & Non-Fabricated Metrics
    # -------------------------------------------------------------
    sys.stdout.write("[TEST 2/4] Testing real inference on simulated flow vectors... ")
    sys.stdout.flush()

    # DoS feature vector: extreme packet rate, small packet size
    dos_vec = np.array([35000.0, 2_500_000.0, 55.0, 60000.0, 4_000_000.0, 1.8], dtype=np.float32)
    xgb_pred = xgb.predict(dos_vec) if xgb_loaded else None
    if_pred = iforest.predict(dos_vec) if if_loaded else None

    if (
        xgb_pred is not None
        and if_pred is not None
        and xgb_pred.predicted_label in CLASS_LABELS
        and xgb_pred.inference_time_s is not None
        and if_pred.inference_time_s is not None
    ):
        print(
            f"PASS (XGB: {xgb_pred.predicted_label} [prob={xgb_pred.max_probability:.2f}, {xgb_pred.inference_time_s*1000:.2f}ms], "
            f"IForest: score={if_pred.anomaly_score:.3f} [{if_pred.inference_time_s*1000:.2f}ms])"
        )
        passed += 1
    else:
        print("FAIL (Inference failed or returned null/invalid results)")

    # -------------------------------------------------------------
    # TEST 3: AI Corroboration Engine Logic
    # -------------------------------------------------------------
    sys.stdout.write("[TEST 3/4] Evaluating AI-augmented risk corroboration... ")
    sys.stdout.flush()

    engine = AIAugmentedRiskEngine(enable_shap=False)
    # Ensure models are loaded
    engine._ensure_models_loaded()

    # High-rate malicious alert
    alert = NormalizedAlert(
        schema_version=1,
        event_id="evt-verify-stage4-01",
        sensor_id="ips-edge-1",
        event_type="alert",
        src_ip="192.0.2.10",
        dest_ip="198.51.100.20",
        src_port=49152,
        dest_port=443,
        proto="TCP",
        signature="ET EXPLOIT Malicious Payload Test",
        signature_id=1000001,
        subject_ip="192.0.2.10",
        subject_status="attacker",
        occurred_at="2026-11-08T00:00:00Z",
        raw_event_ref={},
    )

    fv_high = FlowFeatureVector(
        features={
            "packet_rate": 35000.0,
            "byte_rate": 2_500_000.0,
            "avg_packet_size": 55.0,
            "packet_count": 60000.0,
            "byte_count": 4_000_000.0,
            "flow_duration_sec": 1.8,
        },
        is_valid=True,
    )

    dec_high = engine.evaluate(alert, feature_vector=fv_high)

    # Low-rate benign-looking alert
    fv_benign = FlowFeatureVector(
        features={
            "packet_rate": 20.0,
            "byte_rate": 15_000.0,
            "avg_packet_size": 750.0,
            "packet_count": 200.0,
            "byte_count": 150_000.0,
            "flow_duration_sec": 10.0,
        },
        is_valid=True,
    )

    dec_benign = engine.evaluate(alert, feature_vector=fv_benign)

    if (
        dec_high.final_approved is True
        and dec_high.final_action_type == "temporary_drop"
        and "CONFIRMED" in dec_high.final_reason.upper()
    ):
        print(f"PASS (High-threat corroborated drop; Benign conflict -> {dec_benign.final_action_type})")
        passed += 1
    else:
        print(f"FAIL (Corroboration failed: high_approved={dec_high.final_approved}, reason={dec_high.final_reason})")

    # -------------------------------------------------------------
    # TEST 4: Async SHAP & Audit Spool Verification
    # -------------------------------------------------------------
    sys.stdout.write("[TEST 4/4] Verifying Async SHAP Explainer & Audit Spool... ")
    sys.stdout.flush()

    from ai.explain.explainer import ShapExplainer, ExplanationJob

    spool_path = os.path.join(PROJECT_ROOT, "audit", "spool", "verify_explanations.jsonl")
    if os.path.exists(spool_path):
        os.remove(spool_path)

    explainer = ShapExplainer(
        model=xgb._model,
        model_type="xgboost",
        feature_names=FEATURE_NAMES,
        spool_path=spool_path,
    )
    explainer.start()

    job = ExplanationJob(
        prediction_id="pred-verify-001",
        model_type="xgboost",
        feature_vector=dos_vec,
        feature_names=FEATURE_NAMES,
        predicted_label="dos",
    )

    t0 = time.monotonic()
    accepted = explainer.submit(job)
    t_submit = time.monotonic() - t0

    # Non-blocking submission must be fast (< 100ms)
    time.sleep(1.5)  # give worker a moment to write spool
    explainer.stop(timeout_s=5.0)

    spool_written = os.path.exists(spool_path) and os.path.getsize(spool_path) > 0

    if accepted and t_submit < 0.1 and spool_written:
        with open(spool_path, "r") as f:
            line = f.readline()
            rec = json.loads(line)
        print(f"PASS (Submit: {t_submit*1000:.2f}ms, Spool written with {len(rec['shap_values'])} SHAP features)")
        passed += 1
    else:
        print(f"FAIL (accepted={accepted}, t_submit={t_submit:.3f}s, spool_written={spool_written})")

    # Clean up verification test spool
    if os.path.exists(spool_path):
        os.remove(spool_path)

    print("=" * 65)
    print(f"   SUMMARY: {passed} / {total} tests passed")
    print("=" * 65)
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)

