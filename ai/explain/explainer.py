"""
ai/explain/explainer.py

Phase 4.5: Async SHAP Explainer Worker
References: PRD (Section 5, Phase 4), DESIGN.md, AGENTS.md, ARCHITECTURE.md, DATABASE.md

Key Constraints (AGENTS.md):
- MUST NOT block the urgent enforcement path (Ryu event loop or Risk Engine).
- SHAP computation runs in a background thread pool, decoupled from inference.
- Explanation results are written to the audit spool (JSONL) for later review.
- If SHAP is unavailable (import error), the explainer logs a warning and skips quietly.
- If the queue is full, the entry is dropped and the dropped count is recorded
  (record lost coverage — AGENTS.md requirement).

Design:
  - Caller submits (prediction_id, model, feature_vector, feature_names) to queue.
  - Worker thread picks up the job, computes SHAP values, writes JSON.
  - Non-blocking: submit() returns immediately; caller never waits for SHAP.
"""

import logging
import queue
import threading
import time
import json
import os
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
import numpy as np

logger = logging.getLogger(__name__)

EXPLANATION_SPOOL_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "audit", "spool", "explanations.jsonl"
)
EXPLANATION_SPOOL_PATH = os.path.normpath(EXPLANATION_SPOOL_PATH)

# Maximum pending jobs before we drop (record lost coverage)
MAX_QUEUE_SIZE = 50


@dataclass
class ExplanationJob:
    """A single explanation request submitted to the async worker."""
    prediction_id: str                   # links back to XGBPrediction or IForest result
    model_type: str                      # "xgboost" or "iforest"
    feature_vector: np.ndarray           # 1D array, shape (n_features,)
    feature_names: List[str]             # must match feature_vector length
    predicted_label: Optional[str] = None
    submitted_at: float = 0.0           # filled in by submit()


@dataclass
class ExplanationResult:
    """Computed SHAP explanation for one prediction."""
    prediction_id: str
    model_type: str
    feature_names: List[str]
    shap_values: Dict[str, float]        # {feature_name: shap_value}
    base_value: Optional[float]          # expected model output (SHAP base)
    predicted_label: Optional[str]
    computed_at: float
    compute_duration_s: float            # actual elapsed, never hardcoded


class ShapExplainer:
    """
    Background worker that asynchronously computes SHAP values.

    Usage:
        explainer = ShapExplainer(model, model_type="xgboost", feature_names=FEATURE_NAMES)
        explainer.start()
        explainer.submit(job)        # non-blocking
        # ... later ...
        explainer.stop()
    """

    def __init__(
        self,
        model,                        # fitted sklearn/XGBoost model object
        model_type: str,              # "xgboost" or "iforest"
        feature_names: List[str],
        spool_path: str = EXPLANATION_SPOOL_PATH,
        n_background: int = 100,      # background samples for KernelExplainer
        background_data: Optional[np.ndarray] = None,
    ):
        self._model        = model
        self._model_type   = model_type
        self._feature_names = feature_names
        self._spool_path   = spool_path
        self._n_background = n_background
        self._background   = background_data  # optional pre-supplied background

        self._queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self._dropped_count = 0          # record lost coverage
        self._processed_count = 0

        # Lazily initialised SHAP explainer object
        self._shap_explainer = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Starts the background worker thread."""
        if self._worker is not None and self._worker.is_alive():
            return  # Already running
        self._stop_event.clear()
        self._worker = threading.Thread(
            target=self._worker_loop,
            name="shap-explainer-worker",
            daemon=True,              # Dies with main process automatically
        )
        self._worker.start()
        logger.info("[SHAP] Async explainer worker started (model_type=%s)", self._model_type)

    def stop(self, timeout_s: float = 5.0) -> None:
        """Signals the worker to stop and waits up to timeout_s seconds."""
        self._stop_event.set()
        if self._worker is not None:
            self._worker.join(timeout=timeout_s)
        logger.info(
            "[SHAP] Explainer stopped. processed=%d dropped=%d",
            self._processed_count, self._dropped_count
        )

    # ------------------------------------------------------------------
    # Submission (non-blocking, called from enforcement/risk path)
    # ------------------------------------------------------------------

    def submit(self, job: ExplanationJob) -> bool:
        """
        Submits an explanation job to the async queue.

        Returns True if accepted, False if dropped (queue full).
        Dropping is ALWAYS logged to record lost coverage (AGENTS.md).
        """
        job.submitted_at = time.monotonic()
        try:
            self._queue.put_nowait(job)
            return True
        except queue.Full:
            self._dropped_count += 1
            logger.warning(
                "[SHAP] Queue full — explanation dropped for prediction_id=%s "
                "(total_dropped=%d). Coverage gap recorded.",
                job.prediction_id, self._dropped_count
            )
            return False

    # ------------------------------------------------------------------
    # Worker loop (runs in background thread)
    # ------------------------------------------------------------------

    def _worker_loop(self) -> None:
        """Main background thread: picks jobs from queue and computes SHAP."""
        while not self._stop_event.is_set():
            try:
                job: ExplanationJob = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                self._process_job(job)
                self._processed_count += 1
            except Exception as exc:
                # Never crash the worker; log and continue
                logger.error(
                    "[SHAP] Error computing explanation for %s: %s",
                    job.prediction_id, exc, exc_info=True
                )
            finally:
                self._queue.task_done()

    def _process_job(self, job: ExplanationJob) -> None:
        """Computes SHAP values for one job and writes to spool."""
        try:
            import shap as _shap
        except ImportError:
            logger.warning("[SHAP] shap package not installed; skipping explanation.")
            return

        t_start = time.monotonic()

        # Lazily build the explainer (expensive, done once)
        if self._shap_explainer is None:
            self._shap_explainer = self._build_explainer(_shap)

        X = job.feature_vector.reshape(1, -1).astype(np.float64)

        # Compute SHAP values
        shap_vals = self._shap_explainer(X)

        # For multi-output (XGB multiclass), shap_vals.values shape is (1, n_feat, n_classes).
        # For anomaly models, shape is (1, n_feat).
        # We store the max-class SHAP values for XGB, or the single vector for IForest.
        if hasattr(shap_vals, "values"):
            vals = shap_vals.values[0]  # shape (n_feat,) or (n_feat, n_classes)
            base = None
            if hasattr(shap_vals, "base_values"):
                bv = shap_vals.base_values[0]
                base = float(np.mean(bv)) if hasattr(bv, "__len__") else float(bv)
            if vals.ndim == 2:
                # Multiclass: use max-class (most likely prediction) SHAP values
                vals = vals[:, int(np.argmax(vals.sum(axis=0)))]
        else:
            vals = np.array(shap_vals[0], dtype=np.float64)
            base = None

        shap_dict = {
            name: float(v)
            for name, v in zip(job.feature_names, vals)
        }

        t_end = time.monotonic()

        result = ExplanationResult(
            prediction_id=job.prediction_id,
            model_type=job.model_type,
            feature_names=job.feature_names,
            shap_values=shap_dict,
            base_value=base,
            predicted_label=job.predicted_label,
            computed_at=time.time(),
            compute_duration_s=t_end - t_start,  # actual elapsed
        )

        self._write_spool(result)
        logger.debug(
            "[SHAP] Explanation for %s written (%.3fs)",
            job.prediction_id, result.compute_duration_s
        )

    def _build_explainer(self, shap_module) -> Any:
        """
        Builds the appropriate SHAP explainer for the model type.
        - XGBoost: TreeExplainer (fast, exact).
        - IsolationForest: TreeExplainer with output_type='raw_values'.
        Falls back to KernelExplainer (slower, model-agnostic) if tree explainer fails.
        """
        try:
            explainer = shap_module.TreeExplainer(self._model)
            logger.info("[SHAP] Using TreeExplainer for %s", self._model_type)
            return explainer
        except Exception as e:
            logger.warning("[SHAP] TreeExplainer failed (%s); falling back to KernelExplainer.", e)

        # KernelExplainer needs background data
        if self._background is not None:
            bg = self._background[:self._n_background]
        else:
            # Minimal zero background (not ideal but safe)
            n_feat = len(self._feature_names)
            bg = np.zeros((min(self._n_background, 10), n_feat), dtype=np.float64)

        # For classification, wrap predict_proba; for anomaly, wrap decision_function
        if hasattr(self._model, "predict_proba"):
            fn = self._model.predict_proba
        else:
            fn = self._model.decision_function

        explainer = shap_module.KernelExplainer(fn, bg)
        logger.info("[SHAP] Using KernelExplainer for %s", self._model_type)
        return explainer

    # ------------------------------------------------------------------
    # Spool writer
    # ------------------------------------------------------------------

    def _write_spool(self, result: ExplanationResult) -> None:
        """Appends explanation as a JSONL record. Never overwrites existing records."""
        os.makedirs(os.path.dirname(self._spool_path), exist_ok=True)
        record = {
            "prediction_id": result.prediction_id,
            "model_type": result.model_type,
            "feature_names": result.feature_names,
            "shap_values": result.shap_values,
            "base_value": result.base_value,
            "predicted_label": result.predicted_label,
            "computed_at": result.computed_at,
            "compute_duration_s": result.compute_duration_s,
        }
        with open(self._spool_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    @property
    def dropped_count(self) -> int:
        return self._dropped_count

    @property
    def processed_count(self) -> int:
        return self._processed_count

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

