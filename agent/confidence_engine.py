"""
agent/confidence_engine.py
===========================
AEGIS - Layer 2 Confidence Engine
----------------------------------
Computes a calibrated confidence score in [0.0, 1.0] for a fused threat
verdict, answering "how much should this specific verdict be trusted" --
a question that is separate from, and complementary to, the verdict's
severity (LOW/MEDIUM/HIGH/CRITICAL) produced by fusion_engine.get_verdict().

    confidence = completeness_factor * agreement_factor

completeness_factor
    How much of the expected model coverage actually fired for this event,
    weighted by each model's reliability. A high-severity verdict built on
    1 of 3 expected models is less trustworthy than one built on 3 of 3.

agreement_factor
    How tightly the sub-scores that DID fire agree with each other,
    weighted by reliability. Two models both saying "0.85" is trustworthy;
    one saying "0.9" and another saying "0.2" is not, even though both
    fired. Falls back to a conservative constant when fewer than two
    models fired, since agreement cannot be assessed from a single voice.

Design decisions
-----------------
* Reliability weights and expected-model tables are static, module-level
  config so they can be tuned without touching the calculation logic.
* If a ThreatFusionEngine instance is supplied, model validity flags
  (_windows_labels_valid, etc.) are read directly from it, so a model
  excluded from fuse() is automatically excluded here too -- no duplicate
  "is this model trustworthy right now" logic to keep in sync by hand.
* compute_confidence() is a pure function over its inputs (no hidden
  state) so it is trivial to unit-test and to call once per event.
* AgentTrustTracker is a separate, optional class for the per-agent
  RUNNING trust score that builds up over time from past accuracy. It is
  intentionally decoupled from compute_confidence() -- per-event
  confidence works standalone; running trust is an enrichment on top,
  persisted to SQLite so it slots straight into the Layer 3 schema once
  that exists.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)

# ===========================================================================
# Static config -- tune here, not in the calculation logic below
# ===========================================================================

# Per-model reliability weight, based on verification status recorded in
# PROGRESS_CHECKLIST.md. These are DISTINCT from fusion_engine's blend
# weights (which control threat-score influence) -- these control how much
# a model's presence/absence and agreement/disagreement affects CONFIDENCE.
MODEL_RELIABILITY_WEIGHTS: Dict[str, float] = {
    "ember":    1.0,   # verified 6/6 against real samples
    "hdfs":     0.9,   # verified, label-inversion bug fixed
    "linux":    0.9,   # verified, multiclass-scoring bug fixed
    "cicids":   0.9,   # verified, had + fixed a label-serialization bug
    "zero_day": 0.7,   # directional check only; encoder vocab limitation
    "windows":  0.0,   # excluded -- session-ID labels, no threat semantics
}

# Which models are expected to fire for a given telemetry/event type.
# Mirrors fusion_engine's public scoring methods 1:1:
#   score_process_event(syscall_sequence=...)   -> "linux"
#   score_process_event(api_call_sequence=...)  -> "windows"
#   score_network_flow(...)                     -> "cicids"
#   score_file(...)                              -> "ember"
#   score_log_line(...)                          -> "hdfs"
#   score_windows_event(...)                     -> "zero_day"
EXPECTED_MODELS_BY_EVENT_TYPE: Dict[str, List[str]] = {
    "process_linux":   ["linux"],
    "process_windows": ["windows"],
    "network":         ["cicids"],
    "file":            ["ember"],
    "log_line":        ["hdfs"],
    "windows_event":   ["zero_day"],
}

# Confidence assigned when only one model fired -- there is nothing to
# compare it against, so we deliberately do NOT default to 1.0 (which would
# claim perfect agreement from a single, unconfirmed voice).
SINGLE_MODEL_FALLBACK = 0.6

# Normalizes weighted variance into [0, 1]. Sub-scores live in [0, 1], so
# variance is naturally bounded; 0.25 corresponds to two scores at opposite
# extremes (e.g. 0.0 and 1.0), which we treat as "zero agreement".
MAX_EXPECTED_VARIANCE = 0.25


# ===========================================================================
# Result type
# ===========================================================================
@dataclass
class ConfidenceResult:
    confidence: float
    completeness_factor: float
    agreement_factor: float
    models_fired: List[str] = field(default_factory=list)
    models_expected: List[str] = field(default_factory=list)
    models_missing: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict:
        return {
            "confidence": round(self.confidence, 4),
            "completeness_factor": round(self.completeness_factor, 4),
            "agreement_factor": round(self.agreement_factor, 4),
            "models_fired": self.models_fired,
            "models_expected": self.models_expected,
            "models_missing": self.models_missing,
        }


# ===========================================================================
# Core calculation
# ===========================================================================
def compute_confidence(
    sub_scores: Dict[str, Optional[float]],
    event_type: str,
    *,
    fusion_engine=None,
    weights: Optional[Dict[str, float]] = None,
    expected_models: Optional[List[str]] = None,
    single_model_fallback: float = SINGLE_MODEL_FALLBACK,
    max_expected_variance: float = MAX_EXPECTED_VARIANCE,
) -> ConfidenceResult:
    """
    Compute calibrated confidence for one event's fused verdict.

    Parameters
    ----------
    sub_scores : dict[str, float | None]
        The SAME dict you would pass to ThreatFusionEngine.fuse() -- raw
        per-model scores for this event (a subset of "linux", "windows",
        "cicids", "ember", "hdfs", "zero_day"). None means unavailable.
    event_type : str
        One of EXPECTED_MODELS_BY_EVENT_TYPE's keys ("network", "file",
        "log_line", "process_linux", "process_windows", "windows_event").
        Used to look up which models SHOULD have fired. Unknown event
        types fall back to treating every key present in sub_scores as
        "expected" (completeness becomes trivially 1.0 -- a deliberate,
        logged degradation, not a silent one).
    fusion_engine : ThreatFusionEngine, optional
        If supplied, reliability weights are auto-adjusted to 0.0 for any
        model whose validity flag (_windows_labels_valid / _linux_labels_
        valid / _hdfs_labels_valid) is False on THIS engine instance --
        keeping confidence in sync with fuse()'s own exclusion logic
        without duplicating it.
    weights : dict[str, float], optional
        Override MODEL_RELIABILITY_WEIGHTS. Missing keys fall back to the
        module default.
    expected_models : list[str], optional
        Override EXPECTED_MODELS_BY_EVENT_TYPE for this call.

    Returns
    -------
    ConfidenceResult
    """
    resolved_weights = dict(MODEL_RELIABILITY_WEIGHTS)
    if weights:
        resolved_weights.update(weights)

    if fusion_engine is not None:
        for model_key, attr in (
            ("linux", "_linux_labels_valid"),
            ("windows", "_windows_labels_valid"),
            ("hdfs", "_hdfs_labels_valid"),
        ):
            if hasattr(fusion_engine, attr) and not getattr(fusion_engine, attr):
                resolved_weights[model_key] = 0.0

        if hasattr(fusion_engine, "model_compatibility"):
            for model_key, comp in fusion_engine.model_compatibility.items():
                if not comp.get("compatible", True):
                    resolved_weights[model_key] = 0.0

    expected = expected_models or EXPECTED_MODELS_BY_EVENT_TYPE.get(event_type)
    if expected is None:
        logger.warning(
            "[confidence] Unknown event_type '%s' -- falling back to "
            "treating all provided sub_scores as expected (completeness "
            "will be trivially 1.0).",
            event_type,
        )
        expected = list(sub_scores.keys())

    # Drop zero-weight models from the expected set -- a model with 0
    # reliability (e.g. "windows" today) contributes nothing to either the
    # numerator or denominator, and including it only risks a spurious
    # division-by-zero if it were the ONLY expected model for a type.
    expected = [m for m in expected if resolved_weights.get(m, 0.0) > 0.0]

    fired = [
        m
        for m, score in sub_scores.items()
        if score is not None and resolved_weights.get(m, 0.0) > 0.0
    ]
    missing = [m for m in expected if m not in fired]

    # ---- completeness_factor -------------------------------------------------
    expected_weight_sum = sum(resolved_weights.get(m, 0.0) for m in expected)
    if expected_weight_sum == 0.0:
        # Nothing meaningfully expected for this event type -- do not
        # penalize completeness for a gap that isn't really a gap.
        completeness_factor = 1.0
    else:
        fired_expected_weight_sum = sum(
            resolved_weights.get(m, 0.0) for m in expected if m in fired
        )
        completeness_factor = fired_expected_weight_sum / expected_weight_sum

    # ---- agreement_factor -----------------------------------------------------
    if len(fired) == 0:
        # No usable data at all -- confidence is 0 regardless of completeness
        # math above (which can look artificially fine if expected == []).
        return ConfidenceResult(
            confidence=0.0,
            completeness_factor=completeness_factor,
            agreement_factor=0.0,
            models_fired=fired,
            models_expected=expected,
            models_missing=missing,
        )
    elif len(fired) == 1:
        agreement_factor = single_model_fallback
    else:
        ws = [resolved_weights[m] for m in fired]
        scores = [float(sub_scores[m]) for m in fired]
        total_w = sum(ws)
        weighted_mean = sum(w * s for w, s in zip(ws, scores)) / total_w
        weighted_var = sum(w * (s - weighted_mean) ** 2 for w, s in zip(ws, scores)) / total_w
        agreement_factor = 1.0 - min(weighted_var / max_expected_variance, 1.0)

    confidence = max(0.0, min(1.0, completeness_factor * agreement_factor))

    return ConfidenceResult(
        confidence=confidence,
        completeness_factor=completeness_factor,
        agreement_factor=agreement_factor,
        models_fired=fired,
        models_expected=expected,
        models_missing=missing,
    )


# ===========================================================================
# AgentTrustTracker -- optional per-agent running trust, built over time
# ===========================================================================
class AgentTrustTracker:
    """
    Tracks a per-agent running trust score that evolves over time based on
    whether that agent's past verdicts turned out to be correct.

    This is DELIBERATELY separate from compute_confidence(): per-event
    confidence works standalone from data available right now; running
    trust is a slower-moving signal about the agent itself, meant to feed
    Layer 2's weighted-vote calculation once the tier semantics are
    confirmed. Persisted to SQLite so it plugs into Layer 3's eventual
    schema with zero rework -- this table can be adopted as-is.

    Trust update rule: exponential moving average.
        new_trust = alpha * (1.0 if was_correct else 0.0) + (1 - alpha) * old_trust
    New agents start at a neutral 0.5 (neither trusted nor distrusted).
    """

    def __init__(self, db_path: Union[str, Path] = "aegis_trust.db", alpha: float = 0.2) -> None:
        self.db_path = Path(db_path)
        self.alpha = alpha
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_trust (
                agent_id      TEXT PRIMARY KEY,
                trust_score   REAL    NOT NULL DEFAULT 0.5,
                total_events  INTEGER NOT NULL DEFAULT 0,
                correct_events INTEGER NOT NULL DEFAULT 0,
                last_updated  TEXT
            )
            """
        )
        self._conn.commit()

    def get_trust(self, agent_id: str) -> float:
        row = self._conn.execute(
            "SELECT trust_score FROM agent_trust WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        return float(row[0]) if row else 0.5

    def record_outcome(self, agent_id: str, was_correct: bool) -> float:
        """
        Update agent_id's running trust score after a verdict outcome is
        known (e.g. confirmed by an admin, or by consensus with peers).
        Returns the new trust score.
        """
        old_trust = self.get_trust(agent_id)
        new_trust = self.alpha * (1.0 if was_correct else 0.0) + (1 - self.alpha) * old_trust
        now = datetime.now(timezone.utc).isoformat()

        self._conn.execute(
            """
            INSERT INTO agent_trust (agent_id, trust_score, total_events, correct_events, last_updated)
            VALUES (?, ?, 1, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                trust_score = excluded.trust_score,
                total_events = agent_trust.total_events + 1,
                correct_events = agent_trust.correct_events + excluded.correct_events,
                last_updated = excluded.last_updated
            """,
            (agent_id, new_trust, 1 if was_correct else 0, now),
        )
        self._conn.commit()
        logger.info(
            "[trust] agent=%s  was_correct=%s  trust %.3f -> %.3f",
            agent_id, was_correct, old_trust, new_trust,
        )
        return new_trust

    def close(self) -> None:
        self._conn.close()


# ===========================================================================
# Runnable demo
# ===========================================================================
if __name__ == "__main__":
    import pprint

    print("=" * 65)
    print("  AEGIS - ConfidenceEngine  smoke-test demo")
    print("=" * 65)

    # ------------------------------------------------------------------
    # Case 1: network event, only cicids expected AND fired -> full
    # completeness, but single-model fallback caps agreement.
    # ------------------------------------------------------------------
    print("\n[demo] Case 1 -- network event, cicids fires alone:")
    r1 = compute_confidence({"cicids": 0.82}, event_type="network")
    pprint.pprint(r1.as_dict())

    # ------------------------------------------------------------------
    # Case 2: process event on Linux, both linux + zero_day expected,
    # both fire, but scores disagree sharply -> low agreement drags
    # confidence down even though completeness is perfect.
    # ------------------------------------------------------------------
    print("\n[demo] Case 2 -- process event, linux + zero_day disagree:")
    r2 = compute_confidence(
        {"linux": 0.75, "zero_day": 0.30},
        event_type="process_linux",
        expected_models=["linux", "zero_day"],
    )
    pprint.pprint(r2.as_dict())

    # ------------------------------------------------------------------
    # Case 3: same as case 2 but scores agree closely -> high confidence.
    # ------------------------------------------------------------------
    print("\n[demo] Case 3 -- process event, linux + zero_day agree:")
    r3 = compute_confidence(
        {"linux": 0.80, "zero_day": 0.78},
        event_type="process_linux",
        expected_models=["linux", "zero_day"],
    )
    pprint.pprint(r3.as_dict())

    # ------------------------------------------------------------------
    # Case 4: process event on Linux, zero_day did not fire at all ->
    # incomplete coverage drags confidence down even with no disagreement
    # to speak of.
    # ------------------------------------------------------------------
    print("\n[demo] Case 4 -- process event, zero_day missing entirely:")
    r4 = compute_confidence(
        {"linux": 0.80, "zero_day": None},
        event_type="process_linux",
        expected_models=["linux", "zero_day"],
    )
    pprint.pprint(r4.as_dict())

    # ------------------------------------------------------------------
    # Case 5: windows_advanced fires but is excluded via reliability
    # weight 0.0 -- confirms it never contributes, matching fuse()'s own
    # validity guard.
    # ------------------------------------------------------------------
    print("\n[demo] Case 5 -- windows fires but is weight-excluded:")
    r5 = compute_confidence(
        {"windows": 0.95},
        event_type="process_windows",
    )
    pprint.pprint(r5.as_dict())

    # ------------------------------------------------------------------
    # AgentTrustTracker demo (uses a throwaway in-memory-like file)
    # ------------------------------------------------------------------
    print("\n[demo] AgentTrustTracker -- running trust over 3 outcomes:")
    tracker = AgentTrustTracker(db_path="demo_trust.db")
    for outcome in [True, True, False]:
        tracker.record_outcome("agent-001", was_correct=outcome)
    print(f"  Final trust for agent-001: {tracker.get_trust('agent-001'):.3f}")
    tracker.close()

    print("\n" + "=" * 65)
    print("  Demo complete.")
    print("=" * 65)
