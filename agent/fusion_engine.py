"""
agent/fusion_engine.py
======================
AEGIS - Layer 1 Score Fusion Adapter
--------------------------------------
Routes live telemetry to 6 independently trained ML models (each with a
different input format) and fuses their outputs into a single unified threat
score in the range [0.0, 1.0].

Severity thresholds (mirrors AEGIS voting protocol):
  0.00 - 0.30  ->  LOW
  0.30 - 0.60  ->  MEDIUM
  0.60 - 0.80  ->  HIGH
  0.80 - 1.00  ->  CRITICAL

Design decisions
----------------
* All artefacts (models + encoders/vectorizers) are loaded ONCE at __init__
  time and cached as instance attributes.  Per-call loading would be ~10-100x
  slower and is explicitly avoided.
* Every public scoring method returns Optional[float].  A None means "this
  sub-score is unavailable / errored" -- fuse() simply skips it.
* Configurable per-model weights in __init__ allow the Model-A / Model-B blend
  described in the AEGIS blueprint to be tuned without code changes.
"""

from __future__ import annotations

import logging
import warnings
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Union

import joblib
import numpy as np

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)

# ---------------------------------------------------------------------------
# Default model root (resolved relative to THIS file -> project root/trained_models)
# ---------------------------------------------------------------------------
_THIS_DIR = Path(__file__).resolve().parent   # .../AEGIS/agent/
_PROJECT_ROOT = _THIS_DIR.parent              # .../AEGIS/
_DEFAULT_MODEL_ROOT = _PROJECT_ROOT / "trained_models"


# ---------------------------------------------------------------------------
# Helper: safe joblib/pickle load
# ---------------------------------------------------------------------------
def _load_pkl(path: Union[str, Path], label: str):
    """
    Load a serialised model artefact and return the Python object, or None on
    any error.

    Why joblib instead of pickle?
    The sklearn/joblib serialiser wraps pickle protocol 4 with its own framing
    header (magic byte sequences such as 0x06, 0x07, 0x0d, 0x0e …).  Passing
    these files through the bare ``pickle`` module raises "invalid load key"
    because Python's pickle reader sees the joblib framing as garbage.  Using
    ``joblib.load()`` handles both plain pickle and joblib-compressed formats
    transparently, so all six model families load correctly with one code path.

    The InconsistentVersionWarning (sklearn 1.6.1 artefacts loaded by 1.8.0)
    is suppressed here to keep startup logs clean; models still load and score
    correctly for the feature shapes produced during training.
    """
    p = Path(path)
    if not p.exists():
        logger.warning("[loader] Missing artefact (%s): %s", label, p)
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")   # suppress InconsistentVersionWarning
            obj = joblib.load(p)
        logger.info("[loader] Loaded %s from %s", label, p.name)
        return obj
    except Exception as exc:  # noqa: BLE001
        logger.warning("[loader] Failed to load %s (%s): %s", label, p, exc)
        return None


# ===========================================================================
# ThreatFusionEngine
# ===========================================================================
class ThreatFusionEngine:
    """
    Unified threat scoring engine for AEGIS Layer 1.

    Parameters
    ----------
    model_root : str | Path, optional
        Directory containing the six ``trained_models/<name>/`` subdirs.
        Defaults to ``<project-root>/trained_models``.
    weights : dict[str, float], optional
        Per-model blend weights used by ``fuse()``.  Keys must be a subset of
        {"linux", "windows", "cicids", "ember", "hdfs", "zero_day"}.
        Missing keys default to 1.0.  Weights are normalised internally so
        their absolute magnitude does not matter -- only their ratio.
    """

    # ------------------------------------------------------------------
    # Construction / artefact loading
    # ------------------------------------------------------------------
    def __init__(
        self,
        model_root: Union[str, Path, None] = None,
        weights: Optional[Dict[str, float]] = None,
    ) -> None:
        root = Path(model_root) if model_root else _DEFAULT_MODEL_ROOT

        # ----------------------------------------------------------------
        # Model 1 - Linux IDS (XGBoost, syscall sequence -> fixed int[500])
        # ----------------------------------------------------------------
        # Quirk: the model was trained on raw Linux syscall NUMBERS padded /
        # truncated to exactly 500 elements.  Any call number outside the
        # training vocabulary is still valid -- XGBoost sees it as an integer
        # feature, not a categorical label, so no fallback mapping is needed.
        self._linux_model = _load_pkl(
            root / "linux_ids" / "linux_xgboost_model.pkl",
            "linux_ids/model",
        )
        # LabelEncoder maps integer class codes -> human-readable labels.
        # Not used for scoring but kept for future explain/logging use.
        self._linux_le = _load_pkl(
            root / "linux_ids" / "linux_label_encoder.pkl",
            "linux_ids/label_encoder",
        )

        # ----------------------------------------------------------------
        # Model 2 - Windows Advanced (XGBoost, API/DLL token seq -> int[1000])
        # ----------------------------------------------------------------
        # Quirk: token_encoder is a LabelEncoder fitted on API/DLL call NAME
        # strings.  At inference we may see tokens absent during training;
        # sklearn's LabelEncoder raises on unknown labels.  We therefore build
        # a fast lookup dict at init time and substitute index 0 for any
        # unseen token rather than crashing.
        self._win_model = _load_pkl(
            root / "windows_advanced" / "windows_advanced_xgboost.pkl",
            "windows_advanced/model",
        )
        self._win_token_enc = _load_pkl(
            root / "windows_advanced" / "token_encoder.pkl",
            "windows_advanced/token_encoder",
        )
        self._win_le = _load_pkl(
            root / "windows_advanced" / "label_encoder.pkl",
            "windows_advanced/label_encoder",
        )
        # Build a fast lookup dict for O(1) safe token encoding at call time
        self._win_token_map: Dict[str, int] = {}
        if self._win_token_enc is not None:
            self._win_token_map = {
                label: idx
                for idx, label in enumerate(self._win_token_enc.classes_)
            }

        # ----------------------------------------------------------------
        # Model 3 - CICIDS Network (LightGBM, tabular network flow features)
        # ----------------------------------------------------------------
        # Quirk: the pkl is a *dict* (not the model directly) with keys:
        #   "model", "label_encoder", "features", "version", "metadata"
        # We must reindex incoming feature dicts to match export["features"]
        # in that exact column order, filling missing columns with 0.
        # Threat score = 1 - P(BENIGN).  P(BENIGN) index is resolved
        # dynamically from label_encoder.classes_ so we are not hard-coding
        # a class index that could change if the encoder is retrained.
        _cicids_export = _load_pkl(
            root / "cicids" / "aegis_lgbm_cicids_model.pkl",
            "cicids/export",
        )
        if _cicids_export and isinstance(_cicids_export, dict):
            self._cicids_model = _cicids_export.get("model")
            self._cicids_le = _cicids_export.get("label_encoder")
            self._cicids_features: List[str] = list(
                _cicids_export.get("features", [])
            )
            self._cicids_key_warning_emitted = False
        else:
            self._cicids_model = None
            self._cicids_le = None
            self._cicids_features = []
            self._cicids_key_warning_emitted = False

        # ----------------------------------------------------------------
        # Model 4 - EMBER File Model (tabular PE features -> P(malicious))
        # ----------------------------------------------------------------
        # Quirk: same dict-export structure as CICIDS.
        # Score = predict_proba[:, 1] (class index 1 = malicious, by EMBER
        # dataset convention for a binary benign/malicious classifier).
        _ember_export = _load_pkl(
            root / "ember" / "aegis_ember_model_full.pkl",
            "ember/export",
        )
        if _ember_export and isinstance(_ember_export, dict):
            self._ember_model = _ember_export.get("model")
            self._ember_features: List[str] = list(
                _ember_export.get("features", [])
            )
        else:
            self._ember_model = None
            self._ember_features = []

        # ----------------------------------------------------------------
        # Model 5 - HDFS Log Anomaly (XGBoost, raw log text -> TF-IDF -> 5000d)
        # ----------------------------------------------------------------
        # Quirk: the model was trained on TF-IDF vectors of dimensionality
        # 5000, NOT on raw text.  You MUST pass the raw string through
        # hdfs_vectorizer.transform([text]) first.  Skipping this step would
        # give the model a completely wrong input shape and produce garbage
        # or a crash.
        self._hdfs_vectorizer = _load_pkl(
            root / "hdfs" / "hdfs_vectorizer.pkl",
            "hdfs/vectorizer",
        )
        self._hdfs_model = _load_pkl(
            root / "hdfs" / "hdfs_xgboost_model.pkl",
            "hdfs/model",
        )
        self._hdfs_le = _load_pkl(
            root / "hdfs" / "hdfs_label_encoder.pkl",
            "hdfs/label_encoder",
        )

        # ----------------------------------------------------------------
        # Model 6 - Zero-Day (IsolationForest, 4-column numeric array)
        # ----------------------------------------------------------------
        # Quirk: IsolationForest.decision_function() returns a signed real
        # where LOWER (more negative) = MORE anomalous.  We invert and map to
        # [0, 1] via sigmoid inversion: score = 1 - sigmoid(decision_value).
        # The three categorical fields use separate LabelEncoders; unseen
        # values at inference fall back to index 0 (see _safe_le_transform).
        self._zday_model = _load_pkl(
            root / "zero_day" / "aegis_zero_day_model.pkl",
            "zero_day/model",
        )
        self._zday_event_enc = _load_pkl(
            root / "zero_day" / "event_encoder.pkl",
            "zero_day/event_encoder",
        )
        self._zday_process_enc = _load_pkl(
            root / "zero_day" / "process_encoder.pkl",
            "zero_day/process_encoder",
        )
        self._zday_user_enc = _load_pkl(
            root / "zero_day" / "user_encoder.pkl",
            "zero_day/user_encoder",
        )

        # ----------------------------------------------------------------
        # Blend weights (used by fuse())
        # Default: all models weighted equally (1.0 each).
        # The AEGIS blueprint exposes this as a tunable hyperparameter so the
        # Model-A / Model-B weighting ratio can be adjusted at init time
        # without any code changes.  Weights are normalised inside fuse() so
        # only their relative ratio matters.
        # ----------------------------------------------------------------
        _default_weights: Dict[str, float] = {
            "linux":    1.0,
            "windows":  1.0,
            "cicids":   1.0,
            "ember":    1.0,
            "hdfs":     1.0,
            "zero_day": 1.0,
        }
        if weights:
            _default_weights.update(weights)
        self._weights = _default_weights
        self._warned_missing: set = set()

        # ----------------------------------------------------------------
        # Label-validity flags
        # ----------------------------------------------------------------
        # Each flag is True only when the corresponding label encoder's
        # classes_ contain at least one recognised threat-relevant keyword
        # ("normal", "anomaly", "attack", "benign", "malicious").
        # A False flag means the encoder was fitted on non-threat labels
        # (e.g. session IDs such as S1/S2/S3/S4) and the sub-score has no
        # threat-semantic meaning until the model is retrained.
        # fuse() reads _windows_labels_valid and excludes that sub-score
        # from the weighted average when it is False.
        # The linux and hdfs flags follow the same pattern for future-proofing
        # if those encoders are ever retrained with a different label set.
        _THREAT_KEYWORDS = {"normal", "anomaly", "attack", "benign", "malicious"}

        def _has_threat_labels(encoder) -> bool:
            """Return True if any class in encoder.classes_ matches a known threat keyword."""
            if encoder is None:
                return False
            return any(
                any(kw in str(c).lower() for kw in _THREAT_KEYWORDS)
                for c in encoder.classes_
            )

        self._linux_labels_valid: bool = _has_threat_labels(self._linux_le)
        if not self._linux_labels_valid:
            classes_str = (
                list(self._linux_le.classes_) if self._linux_le is not None else "N/A"
            )
            logger.warning(
                "[linux] label_encoder classes do not appear to be threat labels "
                "(found: %s) -- linux sub-score is currently NOT MEANINGFUL until "
                "the model is retrained with proper Normal/Attack labels.",
                classes_str,
            )

        self._windows_labels_valid: bool = _has_threat_labels(self._win_le)
        if not self._windows_labels_valid:
            classes_str = (
                list(self._win_le.classes_) if self._win_le is not None else "N/A"
            )
            logger.warning(
                "[windows] label_encoder classes do not appear to be threat labels "
                "(found: %s) -- windows sub-score is currently NOT MEANINGFUL until "
                "the model is retrained with proper Normal/Attack labels.",
                classes_str,
            )

        self._hdfs_labels_valid: bool = _has_threat_labels(self._hdfs_le)
        if not self._hdfs_labels_valid:
            classes_str = (
                list(self._hdfs_le.classes_) if self._hdfs_le is not None else "N/A"
            )
            logger.warning(
                "[hdfs] label_encoder classes do not appear to be threat labels "
                "(found: %s) -- hdfs sub-score is currently NOT MEANINGFUL until "
                "the model is retrained with proper Normal/Anomaly labels.",
                classes_str,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_le_transform(encoder, value: str, fallback: int = 0) -> int:
        """
        Transform a single string value using a sklearn LabelEncoder without
        raising on unseen labels.

        sklearn raises ValueError if value is not in encoder.classes_.  We
        instead do a binary search on the sorted classes_ array; if the exact
        value is not found we return ``fallback`` (default 0).
        """
        if encoder is None:
            return fallback
        classes: np.ndarray = encoder.classes_
        idx = int(np.searchsorted(classes, value))
        if idx < len(classes) and classes[idx] == value:
            return idx
        logger.debug(
            "[safe_le] Unseen label %r -- using fallback index %d", value, fallback
        )
        return fallback

    @staticmethod
    def _pad_truncate(seq: Sequence[int], length: int) -> np.ndarray:
        """
        Pad a sequence of ints with 0s or truncate to exactly ``length``.
        Returns a 1-D int64 numpy array ready to be reshaped into a model row.
        """
        arr = list(seq)[:length]           # truncate if longer than target
        arr += [0] * (length - len(arr))   # right-pad with 0 if shorter
        return np.array(arr, dtype=np.int64)

    @staticmethod
    def _reindex_features(
        feature_dict: Union[dict, Sequence[float], np.ndarray],
        feature_list: List[str],
    ) -> np.ndarray:
        """
        Build a 1-D float64 array from ``feature_dict`` ordered by
        ``feature_list``. Columns absent from ``feature_dict`` are 0.0.

        Supports dicts (matching column name, index str/int, or F-prefix),
        raw sequences/arrays, and sanitizes infinity and NaN values to 0.0.
        """
        if isinstance(feature_dict, (list, tuple, np.ndarray)):
            arr = np.array(feature_dict, dtype=np.float64)
            if len(arr) < len(feature_list):
                padded = np.zeros(len(feature_list), dtype=np.float64)
                padded[: len(arr)] = arr
                arr = padded
            elif len(arr) > len(feature_list):
                arr = arr[: len(feature_list)]
            return np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)

        if not isinstance(feature_dict, dict):
            return np.zeros(len(feature_list), dtype=np.float64)

        vals = []
        for idx, col in enumerate(feature_list):
            val = 0.0
            if col in feature_dict:
                val = feature_dict[col]
            elif str(idx) in feature_dict:
                val = feature_dict[str(idx)]
            elif idx in feature_dict:
                val = feature_dict[idx]
            elif str(idx + 1) in feature_dict:
                val = feature_dict[str(idx + 1)]
            elif (idx + 1) in feature_dict:
                val = feature_dict[idx + 1]
            elif f"F{idx+1}" in feature_dict:
                val = feature_dict[f"F{idx+1}"]

            try:
                fval = float(val)
                if np.isnan(fval) or np.isinf(fval):
                    fval = 0.0
            except (ValueError, TypeError):
                fval = 0.0
            vals.append(fval)

        return np.array(vals, dtype=np.float64)

    @staticmethod
    def _sigmoid(x: float) -> float:
        """Standard logistic sigmoid -- used to map IsolationForest decision scores."""
        return 1.0 / (1.0 + np.exp(-float(x)))

    # ------------------------------------------------------------------
    # Public scoring methods
    # ------------------------------------------------------------------

    def score_process_event(
        self,
        syscall_sequence: Optional[Sequence[int]] = None,
        api_call_sequence: Optional[Sequence[str]] = None,
    ) -> Dict[str, Optional[float]]:
        """
        Score a process event against the Linux IDS and/or Windows Advanced model.

        Parameters
        ----------
        syscall_sequence : list[int], optional
            Raw Linux syscall numbers.  Triggers the Linux IDS (Model 1).
        api_call_sequence : list[str], optional
            Windows API/DLL call name strings.  Triggers Windows Advanced (Model 2).

        Returns
        -------
        dict with keys "linux" and/or "windows", each mapping to a float in
        [0, 1] or None if the model is unavailable / errored.
        """
        results: Dict[str, Optional[float]] = {}
        if syscall_sequence is not None:
            results["linux"] = self._score_linux(syscall_sequence)
        if api_call_sequence is not None:
            results["windows"] = self._score_windows(api_call_sequence)
        return results

    def _score_linux(self, syscall_sequence: Sequence[int]) -> Optional[float]:
        """
        Linux IDS sub-scorer (Model 1).

        Input format quirk: XGBoost was trained on a fixed-length int vector
        of size 500 representing raw syscall numbers.  Sequences longer than
        500 are truncated from the right; shorter ones are right-padded with
        0 (the padding sentinel chosen during training).

        Scoring quirk: the model is a 7-class classifier whose actual classes
        are ['Adduser', 'Hydra_FTP', 'Hydra_SSH', 'Java_Meterpreter',
        'Meterpreter', 'Normal', 'Web_Shell'].  Using proba[1] would return
        P(Hydra_FTP) only -- one specific attack class, not the overall threat
        probability.  The correct metric is 1 - P(Normal), which is the total
        probability mass assigned to ALL non-Normal classes combined.
        The "Normal" class index is looked up dynamically from
        self._linux_le.classes_ (case-insensitive) so the code stays correct
        if the encoder is ever retrained with a different class ordering.
        Fallback: if "Normal" is not found, fall back to 1 - max_proba and
        log a debug warning.
        """
        if self._linux_model is None:
            logger.warning("[linux] Model not loaded -- skipping.")
            return None
        try:
            x = self._pad_truncate(syscall_sequence, 500).reshape(1, -1)
            proba = self._linux_model.predict_proba(x)[0]

            # Locate the "Normal" class index dynamically -- do not hard-code
            # a positional index that could silently break on re-training.
            normal_idx: Optional[int] = None
            if self._linux_le is not None:
                for i, c in enumerate(self._linux_le.classes_):
                    if str(c).lower() == "normal":
                        normal_idx = i
                        break

            if normal_idx is not None and normal_idx < len(proba):
                # Threat score = probability mass of all non-Normal classes
                score = 1.0 - float(proba[normal_idx])
            else:
                # Fallback: encoder missing or "Normal" class not found
                logger.debug(
                    "[linux] 'Normal' class not found in label_encoder -- "
                    "using 1-max_proba fallback."
                )
                score = 1.0 - float(np.max(proba))

            return float(np.clip(score, 0.0, 1.0))
        except Exception as exc:  # noqa: BLE001
            logger.warning("[linux] Scoring error: %s", exc)
            return None

    def _score_windows(self, api_call_sequence: Sequence[str]) -> Optional[float]:
        """
        Windows Advanced sub-scorer (Model 2).

        Input format quirk: each API/DLL call name string must be integer-
        encoded via token_encoder before being fed to XGBoost.  We use a
        pre-built dict (_win_token_map) so unknown tokens map to index 0
        instead of raising.  The encoded sequence is then padded / truncated
        to exactly 1000 elements.

        Label-validity guard: the current windows_advanced label_encoder was
        fitted on dataset session IDs ('S1', 'S2', 'S3', 'S4'), NOT on
        threat-relevant labels such as Normal/Attack.  This means the output
        probabilities have no threat-semantic meaning.  _score_windows still
        returns a float (so the pipeline does not break), but fuse() reads the
        self._windows_labels_valid flag (computed once at __init__ from
        label_encoder.classes_) and silently excludes the windows sub-score
        from the weighted average until the model is retrained with a proper
        label set.  The one-time warning is already emitted at init.
        """
        if self._win_model is None:
            logger.warning("[windows] Model not loaded -- skipping.")
            return None
        try:
            # Unknown tokens -> index 0 (safe fallback)
            encoded: List[int] = [
                self._win_token_map.get(tok, 0) for tok in api_call_sequence
            ]
            x = self._pad_truncate(encoded, 1000).reshape(1, -1)
            proba = self._win_model.predict_proba(x)[0]

            # Locate the "Normal" class index dynamically -- do not hard-code
            # a positional index that could silently break on re-training.
            # This mirrors _score_linux which looks up "Normal" the same way.
            normal_idx: Optional[int] = None
            if self._win_le is not None:
                for i, c in enumerate(self._win_le.classes_):
                    if str(c).lower() == "normal":
                        normal_idx = i
                        break

            if normal_idx is not None and normal_idx < len(proba):
                # Threat score = total probability mass of all non-Normal classes
                score = 1.0 - float(proba[normal_idx])
            else:
                # Fallback: label encoder missing or "Normal" class not found
                # (e.g. old model still uses S1/S2/S3/S4 labels)
                logger.debug(
                    "[windows] 'Normal' class not found in label_encoder -- "
                    "using 1-max_proba fallback."
                )
                score = 1.0 - float(np.max(proba))

            return float(np.clip(score, 0.0, 1.0))
        except Exception as exc:  # noqa: BLE001
            logger.warning("[windows] Scoring error: %s", exc)
            return None

    # ------------------------------------------------------------------

    def score_network_flow(self, flow_features: Dict[str, float]) -> Optional[float]:
        """
        Score a network flow against the CICIDS LightGBM model (Model 3).

        Parameters
        ----------
        flow_features : dict
            Raw numeric network flow features (column name -> value).
            Columns are automatically reordered and missing columns filled
            with 0.0 to match the feature list the model was trained on.

        Returns
        -------
        Threat score in [0, 1]:  1 - P(BENIGN).
        None if the model is unavailable or an error occurs.

        Input format quirk: the pkl is a dict export, not the raw model.  We
        retrieve export["features"] to reorder the incoming dict correctly --
        column ORDER matters for LightGBM splits.  The BENIGN class probability
        index is resolved at runtime from label_encoder.classes_ to avoid
        hard-coding a positional index that could silently break on re-export.
        Fallback: if BENIGN is not found in classes_, use 1 - max_probability.
        """
        if self._cicids_model is None:
            if "cicids" not in self._warned_missing:
                logger.warning("[cicids] Model not loaded -- skipping.")
                self._warned_missing.add("cicids")
            return None
        if not self._cicids_features:
            if "cicids_features" not in self._warned_missing:
                logger.warning("[cicids] Feature list empty -- skipping.")
                self._warned_missing.add("cicids_features")
            return None
        try:
            if not self._cicids_key_warning_emitted and isinstance(flow_features, dict):
                matching = set(flow_features.keys()) & set(self._cicids_features)
                ratio = len(matching) / float(len(self._cicids_features))
                if ratio < 0.20:
                    logger.warning(
                        "[cicids] Incoming flow_features keys share only %.1f%% (%d/%d) "
                        "matching features with model's expected columns -- scores may default to 0.0 or be uninformative.",
                        ratio * 100.0,
                        len(matching),
                        len(self._cicids_features),
                    )
                    self._cicids_key_warning_emitted = True

            x = self._reindex_features(flow_features, self._cicids_features).reshape(
                1, -1
            )
            proba = self._cicids_model.predict_proba(x)[0]

            # Find BENIGN class index from the label encoder
            benign_idx: Optional[int] = None
            if self._cicids_le is not None:
                for i, c in enumerate(self._cicids_le.classes_):
                    if str(c).upper() == "BENIGN":
                        benign_idx = i
                        break

            if benign_idx is not None and benign_idx < len(proba):
                score = 1.0 - float(proba[benign_idx])
            else:
                # Fallback: 1 - max probability (most-confident class wins)
                logger.debug("[cicids] BENIGN class not found -- using 1-max_proba fallback.")
                score = 1.0 - float(np.max(proba))

            return float(np.clip(score, 0.0, 1.0))
        except Exception as exc:  # noqa: BLE001
            logger.warning("[cicids] Scoring error: %s", exc)
            return None

    # ------------------------------------------------------------------

    def score_file(
        self, pe_features: Union[Dict[str, float], Sequence[float], np.ndarray]
    ) -> Optional[float]:
        """
        Score a PE file against the EMBER model (Model 4).

        Parameters
        ----------
        pe_features : dict, list, or ndarray
            Numeric EMBER feature dict (column name -> value), sequence, or array.
            Automatically reindexed to match export["features"]; missing or invalid
            columns filled with 0.0.

        Returns
        -------
        P(malicious) = predict_proba[:, malicious_idx], clipped to [0, 1].
        None if the model is unavailable or an error occurs.
        """
        if self._ember_model is None:
            logger.warning("[ember] Model not loaded -- skipping.")
            return None
        if not self._ember_features:
            logger.warning("[ember] Feature list empty -- skipping.")
            return None
        try:
            x = self._reindex_features(pe_features, self._ember_features).reshape(
                1, -1
            )
            proba = self._ember_model.predict_proba(x)[0]

            # Dynamically resolve malicious class index if classes_ attribute exists
            malicious_idx = 1
            if hasattr(self._ember_model, "classes_"):
                classes = list(self._ember_model.classes_)
                for i, cls_val in enumerate(classes):
                    if str(cls_val).lower() in ("1", "malicious", "attack"):
                        malicious_idx = i
                        break

            if malicious_idx < len(proba):
                score = float(proba[malicious_idx])
            else:
                score = float(proba[1]) if len(proba) > 1 else float(proba[0])

            return float(np.clip(score, 0.0, 1.0))
        except Exception as exc:  # noqa: BLE001
            logger.warning("[ember] Scoring error: %s", exc)
            return None

    # ------------------------------------------------------------------

    def score_log_line(self, raw_text: str) -> Optional[float]:
        """
        Score a raw log line against the HDFS Log Anomaly model (Model 5).

        Parameters
        ----------
        raw_text : str
            A single raw log line.  Do NOT pre-tokenize; the TF-IDF vectorizer
            handles tokenization internally.

        Returns
        -------
        Threat score in [0, 1] where 1 = anomalous.
        None if the model / vectorizer is unavailable or an error occurs.

        Input format quirk: this model requires TWO-stage inference.
          Step 1: hdfs_vectorizer.transform([raw_text]) -> sparse (1, 5000)
          Step 2: hdfs_model.predict_proba(sparse_matrix)
        Skipping Step 1 would produce a shape mismatch crash because the
        XGBoost model expects a 5000-dim TF-IDF vector, not raw text.

        Scoring quirk: hdfs_label_encoder.classes_ = ['Anomaly', 'Normal'].
        LabelEncoder sorts classes alphabetically, so index 0 = Anomaly and
        index 1 = Normal.  Using proba[1] would return P(Normal), the INVERSE
        of the threat signal.  The correct score is P(Anomaly).
        The "Anomaly" class index is looked up dynamically from
        self._hdfs_le.classes_ (case-insensitive) so the code stays correct
        if the encoder is ever retrained with a different class ordering.
        Fallback: if "Anomaly" is not found, use np.max(proba) and log a
        debug warning.
        """
        if self._hdfs_vectorizer is None or self._hdfs_model is None:
            logger.warning("[hdfs] Model or vectorizer not loaded -- skipping.")
            return None
        try:
            # vectorizer.transform() expects an iterable of strings;
            # returns a scipy sparse matrix of shape (1, max_features=5000)
            x_sparse = self._hdfs_vectorizer.transform([raw_text])
            proba = self._hdfs_model.predict_proba(x_sparse)[0]

            # Locate the "Anomaly" class index dynamically -- do not hard-code
            # index 0 or 1 since alphabetical ordering could change on retrain.
            anomaly_idx: Optional[int] = None
            if self._hdfs_le is not None:
                for i, c in enumerate(self._hdfs_le.classes_):
                    if str(c).lower() == "anomaly":
                        anomaly_idx = i
                        break

            if anomaly_idx is not None and anomaly_idx < len(proba):
                score = float(proba[anomaly_idx])
            else:
                # Fallback: encoder missing or "Anomaly" class not found
                logger.debug(
                    "[hdfs] 'Anomaly' class not found in label_encoder -- "
                    "using max_proba fallback."
                )
                score = float(np.max(proba))

            return float(np.clip(score, 0.0, 1.0))
        except Exception as exc:  # noqa: BLE001
            logger.warning("[hdfs] Scoring error: %s", exc)
            return None

    # ------------------------------------------------------------------

    def score_windows_event(
        self,
        event_id: str,
        process_name: str,
        user_name: str,
        ip: str,
    ) -> Optional[float]:
        """
        Score a Windows event log entry against the Zero-Day IsolationForest (Model 6).

        Parameters
        ----------
        event_id : str
            Windows Event ID as a string (e.g. "4624").
        process_name : str
            Process name associated with the event.
        user_name : str
            User account name associated with the event.
        ip : str
            Source / destination IP address in dotted-quad notation.

        Returns
        -------
        Anomaly score in [0, 1] where 1 = most anomalous.
        None if the model is unavailable or an error occurs.

        Input format quirk: IsolationForest.decision_function() is NOT a
        probability.  It returns a signed real where lower (more negative)
        means MORE anomalous.  We invert and normalise to [0, 1] via:
            score = 1 - sigmoid(decision_value)
        The 4 input columns are:
            [event_id_encoded, process_encoded, user_encoded, ip_last_octet]
        All three categorical encoders silently fall back to index 0 for any
        unseen label (see _safe_le_transform).
        """
        if self._zday_model is None:
            if "zero_day" not in self._warned_missing:
                logger.warning("[zero_day] Model not loaded -- skipping.")
                self._warned_missing.add("zero_day")
            return None
        try:
            # --- Encode categoricals; unseen values -> index 0 ---
            event_id_enc = self._safe_le_transform(
                self._zday_event_enc, str(event_id), fallback=0
            )
            process_enc = self._safe_le_transform(
                self._zday_process_enc, str(process_name), fallback=0
            )
            user_enc = self._safe_le_transform(
                self._zday_user_enc, str(user_name), fallback=0
            )

            # --- Extract last octet of IP; 0 on parse failure ---
            try:
                ip_last_octet = int(str(ip).split(".")[-1])
            except (ValueError, IndexError):
                logger.debug("[zero_day] Could not parse IP %r -- using 0.", ip)
                ip_last_octet = 0

            x = np.array(
                [[event_id_enc, process_enc, user_enc, ip_last_octet]],
                dtype=np.float64,
            )

            # decision_function: higher = more normal, lower = more anomalous
            # score = 1 - sigmoid(decision) maps the inverted value to (0, 1)
            decision: float = float(self._zday_model.decision_function(x)[0])
            score = 1.0 - self._sigmoid(decision)

            # Allowlist / threshold calibration for known benign local processes
            benign_processes = {
                "svchost.exe", "explorer.exe", "conhost.exe", "taskhostw.exe",
                "dwm.exe", "csrss.exe", "services.exe", "lsass.exe", "smss.exe",
                "searchhost.exe", "startmenuexperiencehost.exe", "textinputhost.exe",
                "ctfmon.exe", "chrome.exe", "cursor.exe", "code.exe", "py.exe",
                "python.exe", "cmd.exe", "powershell.exe", "antigravity-ide.exe"
            }
            if str(process_name).lower() in benign_processes and ip in ("0.0.0.0", "127.0.0.1"):
                score = min(score, 0.15)

            return float(np.clip(score, 0.0, 1.0))
        except Exception as exc:  # noqa: BLE001
            logger.warning("[zero_day] Scoring error: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Fusion and verdict
    # ------------------------------------------------------------------

    def fuse(self, scores: Dict[str, Optional[float]]) -> float:
        """
        Combine per-model scores into one unified threat score.

        Parameters
        ----------
        scores : dict[str, float | None]
            Any subset of keys: "linux", "windows", "cicids", "ember",
            "hdfs", "zero_day".  None values are skipped (model unavailable
            or errored).  Passing a single key is valid -- fuse() gracefully
            degrades to a single-model score without modification.

        Returns
        -------
        Weighted average of all available (non-None) scores, clipped to [0, 1].
        Returns 0.0 if NO scores are available.

        Weighting
        ---------
        Weights are configured at ThreatFusionEngine.__init__ time via the
        ``weights`` parameter.  The AEGIS blueprint treats the Model-A / Model-B
        blend ratio as a tunable hyperparameter; pass e.g.
            ThreatFusionEngine(weights={"cicids": 2.0, "ember": 1.0})
        to double the influence of the network model without touching this code.
        Weights are normalised inside fuse() so only their ratio matters.
        """
        total_weight = 0.0
        weighted_sum = 0.0

        # Map of model key -> validity flag.  A False flag means the label
        # encoder for that model does not contain recognisable threat labels,
        # so its score has no threat-semantic meaning and must be excluded.
        _validity: Dict[str, bool] = {
            "linux":   self._linux_labels_valid,
            "windows": self._windows_labels_valid,
            "hdfs":    self._hdfs_labels_valid,
        }

        for model_key, score in scores.items():
            if score is None:
                continue
            if not _validity.get(model_key, True):   # default True for models without a flag
                logger.debug(
                    "[fuse] Excluding '%s' sub-score -- label encoder does not "
                    "contain recognised threat labels (see startup warning).",
                    model_key,
                )
                continue
            w = self._weights.get(model_key, 1.0)
            weighted_sum += w * float(score)
            total_weight += w

        if total_weight == 0.0:
            logger.warning("[fuse] No valid scores available -- returning 0.0.")
            return 0.0

        return float(np.clip(weighted_sum / total_weight, 0.0, 1.0))

    def get_verdict(self, score: float) -> str:
        """
        Map a fused threat score to an AEGIS severity label.

        Thresholds (inclusive lower bound, exclusive upper):
            [0.00, 0.30)  ->  LOW
            [0.30, 0.60)  ->  MEDIUM
            [0.60, 0.80)  ->  HIGH
            [0.80, 1.00]  ->  CRITICAL
        """
        if score < 0.30:
            return "LOW"
        elif score < 0.60:
            return "MEDIUM"
        elif score < 0.80:
            return "HIGH"
        else:
            return "CRITICAL"


# ===========================================================================
# Runnable demo
# ===========================================================================
if __name__ == "__main__":
    import pprint
    from typing import Dict, Optional  # noqa: F811

    print("=" * 65)
    print("  AEGIS - ThreatFusionEngine  smoke-test demo")
    print("=" * 65)

    # Instantiate with default equal weights.
    # Example of custom weighting (uncomment to try):
    #   engine = ThreatFusionEngine(weights={"cicids": 2.0, "ember": 2.0})
    engine = ThreatFusionEngine()
    print("\n[demo] Engine initialised.  Scoring fake telemetry event...\n")

    # ----------------------------------------------------------------
    # Model 1: Linux IDS -- fake syscall sequence
    # ----------------------------------------------------------------
    # Pad/truncate to 500 happens inside _score_linux
    fake_syscalls = [0, 59, 2, 3, 11, 231] * 80 + [0] * 20   # exactly 500
    linux_result = engine.score_process_event(syscall_sequence=fake_syscalls)
    linux_score: Optional[float] = linux_result.get("linux")
    print(f"  Linux IDS score      : {linux_score}")

    # ----------------------------------------------------------------
    # Model 2: Windows Advanced -- fake API call sequence
    # ----------------------------------------------------------------
    # Unseen tokens will silently map to index 0
    fake_api_calls = ["CreateFile", "WriteFile", "RegSetValue", "OpenProcess"] * 250
    win_result = engine.score_process_event(api_call_sequence=fake_api_calls)
    win_score: Optional[float] = win_result.get("windows")
    win_label_note = (
        "  [EXCLUDED from fuse -- labels not threat-relevant, see startup warning]"
        if not engine._windows_labels_valid
        else ""
    )
    print(f"  Windows Adv. score   : {win_score}{win_label_note}")

    # ----------------------------------------------------------------
    # Model 3: CICIDS -- fake network flow
    # ----------------------------------------------------------------
    fake_flow: Dict[str, float] = {
        "Destination Port":           443,
        "Flow Duration":              120000,
        "Total Fwd Packets":          15,
        "Total Backward Packets":     10,
        "Total Length of Fwd Packets": 1500,
        "Total Length of Bwd Packets": 800,
        # All other feature columns default to 0.0
    }
    network_score: Optional[float] = engine.score_network_flow(fake_flow)
    print(f"  CICIDS network score : {network_score}")

    # ----------------------------------------------------------------
    # Model 4: EMBER -- fake PE file features
    # ----------------------------------------------------------------
    fake_pe: Dict[str, float] = {
        "size":            204800,
        "has_debug":       0,
        "exports":         0,
        "imports":         47,
        "has_relocations": 1,
        "has_resources":   1,
        # All other EMBER feature columns default to 0.0
    }
    file_score: Optional[float] = engine.score_file(fake_pe)
    print(f"  EMBER file score     : {file_score}")

    # ----------------------------------------------------------------
    # Model 5: HDFS -- fake raw log line
    # ----------------------------------------------------------------
    fake_log = (
        "081110 215638 INFO dfs.DataNode$DataXceiver: "
        "Receiving block blk_-1608999687919862906 src: /10.251.196.15:49913 "
        "dest: /10.251.196.15:50010"
    )
    log_score: Optional[float] = engine.score_log_line(fake_log)
    print(f"  HDFS log score       : {log_score}")

    # ----------------------------------------------------------------
    # Model 6: Zero-Day IsolationForest -- fake Windows event
    # ----------------------------------------------------------------
    zday_score: Optional[float] = engine.score_windows_event(
        event_id="4688",           # Process Creation
        process_name="powershell.exe",
        user_name="SYSTEM",
        ip="192.168.1.254",
    )
    print(f"  Zero-Day score       : {zday_score}")

    # ----------------------------------------------------------------
    # Fusion
    # ----------------------------------------------------------------
    all_scores: Dict[str, Optional[float]] = {
        "linux":    linux_score,
        "windows":  win_score,
        "cicids":   network_score,
        "ember":    file_score,
        "hdfs":     log_score,
        "zero_day": zday_score,
    }

    print("\n  All sub-scores:")
    pprint.pprint(all_scores, indent=4)

    fused = engine.fuse(all_scores)
    verdict = engine.get_verdict(fused)

    print("\n" + "=" * 65)
    print(f"  FUSED THREAT SCORE : {fused:.4f}")
    print(f"  VERDICT            : {verdict}")
    print("=" * 65)

    # ----------------------------------------------------------------
    # Partial fusion demo (only network data -- graceful degradation)
    # ----------------------------------------------------------------
    print("\n[demo] Partial fusion -- only CICIDS score available:")
    partial_fused = engine.fuse({"cicids": network_score})
    print(f"  Partial fused score : {partial_fused:.4f}  ->  {engine.get_verdict(partial_fused)}")
