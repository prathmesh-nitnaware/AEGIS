# AEGIS Progress Checklist

**Summary:**
- **Layer 1 — EDR Agent (Models, Fusion, Collectors, Heartbeat, Confidence):** 35 / 50 items complete (70.0%)
- **Layer 2 — Peer Voting Protocol:** 0 / 4 items complete (0.0%)
- **Layer 3 — Command Node + Dashboard:** 0 / 6 items complete (0.0%)
- **Cross-cutting:** 0 / 2 items complete (0.0%)
- **Overall Completion:** 35 / 62 items complete (56.5%)

---

## Layer 1 — EDR Agent

### 1a. Model training (per model)

#### Linux IDS (`linux_ids`)
- [x] Model trained and serialized (`trained_models/linux_ids/linux_xgboost_model.pkl`, `XGBClassifier` via `joblib.load`; trained via `ml_notebooks/linux_ids/Linux_XGBoost.ipynb`)
- [x] Label encoder artifact present (`trained_models/linux_ids/linux_label_encoder.pkl` — 7 classes: `Adduser`, `Hydra_FTP`, `Hydra_SSH`, `Java_Meterpreter`, `Meterpreter`, `Normal`, `Web_Shell`)
- [x] Label mapping verified correct (`agent/diagnostics/check_linux_label_mapping.py` — real samples)
- [x] Usable threat score achievable (`1 - P(Normal)`, dynamic index lookup of "Normal" class)

#### Windows Advanced (`windows_advanced`)
- [x] Model trained and serialized (`trained_models/windows_advanced/windows_advanced_xgboost.pkl`, `XGBClassifier`; trained via `ml_notebooks/windows_advanced/Windows_Advanced_XGBoost.ipynb`)
- [x] Encoder artifacts present (`token_encoder.pkl`, `label_encoder.pkl`)
- [ ] Label mapping verified correct — *not yet independently verified against real samples*
- [ ] **[BLOCKED]** Usable threat score achievable — *labels are session IDs (S1–S4), not Normal/Attack; needs relabeling from ADFA-WD folder structure + retraining*

#### CICIDS Network (`cicids`)
- [x] Model trained and serialized (`trained_models/cicids/aegis_lgbm_cicids_model.pkl`, dict export containing LightGBM model; trained via `ml_notebooks/cicids/cicids_training.ipynb`)
- [x] Label encoder + feature list present (embedded inside the dict export)
- [x] Label mapping verified (`agent/diagnostics/check_cicids_label_mapping.py` — found and fixed a critical integer-label serialization bug; re-fit encoder, re-exported `.pkl`)
- [x] Usable threat score achievable (`1 - P(BENIGN)`, dynamic index lookup of "BENIGN" class)

#### EMBER File Model (`ember`)
- [x] Model trained and serialized (`trained_models/ember/aegis_ember_model_full.pkl`, dict export containing LightGBM model; trained via `ml_notebooks/ember/ember.ipynb`)
- [x] Feature list present (embedded inside the dict export)
- [x] Label mapping verified correct (`agent/diagnostics/check_ember_label_mapping.py` — 6/6 PASS on real samples)
- [x] Usable threat score achievable (`P(malicious)`, class index 1)

#### HDFS Log Anomaly (`hdfs`)
- [x] Model trained and serialized (`trained_models/hdfs/hdfs_xgboost_model.pkl`, `XGBClassifier`; trained via `ml_notebooks/hdfs/HDFS_Anomaly_Detection.ipynb`)
- [x] Vectorizer + label encoder present (`hdfs_vectorizer.pkl` — 5000-dim TF-IDF; `hdfs_label_encoder.pkl`)
- [x] Label mapping verified correct (`agent/diagnostics/check_hdfs_label_mapping.py` — found and fixed label inversion: alphabetical sort placed "Anomaly" at index 0, "Normal" at index 1)
- [x] Usable threat score achievable (`P(Anomaly)`, dynamic index lookup)

#### Zero-Day Anomaly (`zero_day`)
- [x] Model trained and serialized (`trained_models/zero_day/aegis_zero_day_model.pkl`, `IsolationForest`; trained via `ml_notebooks/Zero_day/ZeroDay_Detection.ipynb`)
- [x] Three categorical encoders present (`event_encoder.pkl`, `process_encoder.pkl`, `user_encoder.pkl`)
- [x] Label mapping verified (directional check via `agent/diagnostics/check_zeroday_label_mapping.py` — formula verified; encoder vocabulary limitation documented, diagnostic margin below acceptable bar)
- [x] Usable threat score achievable (`1 - sigmoid(decision_function)`)

---

### 1b. Fusion adapter (`agent/fusion_engine.py`)
- [x] `ThreatFusionEngine` class with one scoring method per model (`_score_linux`, `_score_windows`, `score_network_flow`, `score_file`, `score_log_line`, `score_windows_event`)
- [x] `fuse()` implemented — configurable per-model weights, normalized by ratio, graceful degradation for missing/`None` sub-scores
- [x] `get_verdict()` implemented — `<0.30` LOW, `<0.60` MEDIUM, `<0.80` HIGH, `>=0.80` CRITICAL
- [x] HDFS label-inversion bug fixed and verified
- [x] Linux 7-class multiclass-scoring bug fixed and verified (`1 - P(Normal)` instead of a single wrong class probability)
- [x] Windows Advanced excluded from `fuse()` via validity guard (`_windows_labels_valid`, keyword-based check on `label_encoder.classes_`)
- [x] Same validity-guard pattern also computed for Linux and HDFS (`_linux_labels_valid`, `_hdfs_labels_valid`) as future-proofing, even though both currently pass

---

### 1c. Live telemetry collectors

#### Linux IDS (`linux_ids`)
- [ ] Live collector built — *syscall capture mechanism undecided (e.g. auditd/eBPF/ptrace); must output raw syscall numbers, pad/truncate to 500*
- [ ] Collector tested end-to-end against `fusion_engine.py`

#### Windows Advanced (`windows_advanced`)
- [ ] Live collector built — *API/DLL call capture, tokenized via `token_encoder`, pad/truncate to 1000*
- [ ] Collector tested end-to-end (score will be excluded from `fuse()` until labels are fixed, but plumbing can still be tested)

#### CICIDS Network (`cicids`)
- [ ] Live collector built — *network flow feature extraction, must match `_cicids_features` column order exactly*
- [ ] Collector tested end-to-end

#### EMBER File Model (`ember`)
- [ ] Live collector built — *PE file feature extraction on write/execution, needs a PE-parsing library (not specified in project docs)*
- [ ] Collector tested end-to-end

#### HDFS Log Anomaly (`hdfs`)
- [ ] Live collector built — *raw log line capture. **Block-level grouping rule still undesigned**: `score_log_line()` only accepts one line at a time; the documented "block-level concatenated" requirement has no implementation anywhere and must be built into this collector*
- [ ] Collector tested end-to-end

#### Zero-Day Anomaly (`zero_day`)
- [ ] Live collector built — *capture `event_id`, `process_name`, `user_name`, `ip` per discrete event*
- [ ] Collector tested end-to-end

---

### 1d. Heartbeat mechanism (`agent/heartbeat.py`)
- [x] `HeartbeatEmitter` implemented — background thread, 5s default interval (AEGIS spec), payload = `agent_id`, `status`, `cpu`, `timestamp`; interruptible via `threading.Event`; CPU-threshold-based `"degraded"` status (sustained-cycle logic, not in original spec — practical addition)
- [x] `SilenceDetector` implemented — 15s default silence threshold (AEGIS spec), thread-safe multi-agent tracking, alarm suppression/re-arm on recovery (practical addition, not in original spec); currently runs as a local in-process stub, not yet wired to a live networked Command Node (Layer 3 not built)

---

### 1e. Confidence engine (`agent/confidence_engine.py`)
- [x] `ConfidenceResult` dataclass implemented (`confidence`, `completeness_factor`, `agreement_factor`, `models_fired`, `models_expected`, `models_missing`)
- [x] `compute_confidence()` implemented — `completeness_factor` (expected model coverage, reliability-weighted) × `agreement_factor` (variance-based agreement between fired sub-scores, reliability-weighted); single-model fallback constant (0.6) instead of assuming perfect trust from one voice
- [x] Per-model reliability weights configured, mirroring `PROGRESS_CHECKLIST.md` verification status (`ember` 1.0, `hdfs`/`linux`/`cicids` 0.9, `zero_day` 0.7, `windows` 0.0)
- [x] Auto-sync with `ThreatFusionEngine` validity flags — if a `fusion_engine` instance is passed in, `_linux_labels_valid` / `_windows_labels_valid` / `_hdfs_labels_valid` automatically zero out reliability weight, keeping confidence exclusions in sync with `fuse()`'s own exclusions without duplicated logic
- [x] `AgentTrustTracker` implemented — per-agent running trust score via exponential moving average, persisted to SQLite (`agent_trust` table: `agent_id`, `trust_score`, `total_events`, `correct_events`, `last_updated`), new agents start neutral at 0.5
- [ ] Wired into the live agent pipeline — *not yet connected to any real event stream; currently demo-only (5 standalone test cases in `if __name__ == "__main__":`)*
- [ ] Heartbeat/silence-alarm integration — *open design question: should a `SilenceDetector` alarm/recovery event feed into `AgentTrustTracker.record_outcome()`? Not specified in any AEGIS source document; deferred until Layer 2 design begins (see Open Design Items below)*

---

## Layer 2 — Peer Voting Protocol
*(Correctly not started — this is explicit Phase 2 scope per Blueprint §9's Phased Build Plan; Phase 1 (single agent) is not yet complete)*
- [ ] VotingRequest broadcast implemented — *no ZeroMQ or peer messaging in repository*
- [ ] Peer correlation-check logic implemented
- [ ] Weighted vote calculation implemented (2.0 / 1.0 / 0.5 / 0.3 multipliers per Blueprint §4.3)
- [ ] Tested with 2+ agents on separate processes/machines

---

## Layer 3 — Command Node + Dashboard
- [ ] FastAPI backend scaffolded
- [ ] SQLite schema defined and used (note: `confidence_engine.py`'s `agent_trust` table is already designed to slot into this schema with no rework once it exists)
- [ ] Vote aggregation + verdict computation implemented
- [ ] Response action dispatch implemented (`LOG`, `ALERT`, `KILL_PROCESS`, `ISOLATE_HOST`)
- [ ] Streamlit dashboard exists
- [ ] Admin Trust System (Identity Context, Behavioral Pattern Analysis, Pre-Announced Maintenance Windows w/ dual approval)

---

## Cross-cutting
- [ ] `progress_status.md` reconciled with this checklist — *stale, e.g. still lists EMBER as untrained*
- [ ] VM test environment set up (VirtualBox, 3 host-only VMs) — *deferred until live single-agent pipeline runs end-to-end*

---

## Open Design Items (Tracked, Not Blocking Current Work)
- **Heartbeat ↔ AgentTrustTracker integration** — whether silence/recovery events should affect an agent's long-term trust score. Undocumented in any AEGIS source material. Candidate approaches to revisit at Layer 2 time: (a) auto-penalize trust on silence, (b) never auto-penalize since silence may indicate the agent was the *victim* of an attack, not unreliable, (c) let the Command Node apply the existing §4.3 "unreliable" ×0.3 vote-weight multiplier contextually per-incident without touching the long-term `AgentTrustTracker` score.
- **HDFS block-level grouping rule** — undefined anywhere: is a "block" a time window, a session ID, or the dataset's native `blk_` identifiers? Must be resolved before the HDFS collector can be built correctly.
- **Syscall capture mechanism (Linux collector)** — not specified (auditd vs eBPF vs ptrace, etc.)
- **API/DLL call capture mechanism (Windows collector)** — not specified
- **PE feature extraction library (EMBER collector)** — not specified
- **Model-to-telemetry routing logic** — no router exists yet; each collector is expected to call its own matching `fusion_engine.py` method independently, but this has never been stated as an explicit design decision
- **Single-agent scope definition** — unclear whether "Phase 1 complete" requires all 6 models wired, or just the 4 currently-verified ones (Linux, HDFS, EMBER, CICIDS), with Windows Advanced and Zero-Day following once unblocked