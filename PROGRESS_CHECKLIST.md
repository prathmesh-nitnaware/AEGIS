# AEGIS Progress Checklist

**Summary:**
- **Layer 1 — EDR Agent:** 28 / 44 items complete (63.6%)
- **Layer 2 — Peer Voting Protocol:** 0 / 4 items complete (0.0%)
- **Layer 3 — Command Node + Dashboard:** 0 / 6 items complete (0.0%)
- **Cross-cutting:** 0 / 2 items complete (0.0%)
- **Overall Completion:** 28 / 56 items complete (50.0%)

---

## Layer 1 — EDR Agent

### 1a. Model training (per model)

#### Linux IDS (`linux_ids`)
- [x] Model trained and serialized (`trained_models/linux_ids/linux_xgboost_model.pkl` verified loading `XGBClassifier` via `joblib.load`; trained via `ml_notebooks/linux_ids/Linux_XGBoost.ipynb`)
- [x] Label encoder / vectorizer / feature list artifacts present (`trained_models/linux_ids/linux_label_encoder.pkl` verified)
- [x] Label mapping verified correct (verified against real samples via `agent/diagnostics/check_linux_label_mapping.py`)
- [x] Usable threat/anomaly score achievable (`1 - P(Normal)` score calculated across multiclass labels)

#### Windows Advanced (`windows_advanced`)
- [x] Model trained and serialized (`trained_models/windows_advanced/windows_advanced_xgboost.pkl` verified loading `XGBClassifier` via `joblib.load`; trained via `ml_notebooks/windows_advanced/Windows_Advanced_XGBoost.ipynb`)
- [x] Label encoder / vectorizer / feature list artifacts present (`trained_models/windows_advanced/token_encoder.pkl` and `label_encoder.pkl` verified)
- [ ] Label mapping verified correct — *Note: not yet independently verified against real samples*
- [ ] **[BLOCKED]** Usable threat/anomaly score achievable — *Note: labels are session IDs (S1-S4), not Normal/Attack — needs relabeling before this can be marked done*

#### CICIDS Network (`cicids`)
- [x] Model trained and serialized (`trained_models/cicids/aegis_lgbm_cicids_model.pkl` verified loading dict export containing LightGBM model via `joblib.load`; trained via `ml_notebooks/cicids/cicids_training.ipynb`)
- [x] Label encoder / vectorizer / feature list artifacts present (`label_encoder` and `features` list embedded inside `aegis_lgbm_cicids_model.pkl` dict export)
- [x] Label mapping verified (diagnosed via `agent/diagnostics/check_cicids_label_mapping.py` — revealed critical integer-label serialization bug)
- [x] Usable threat/anomaly score achievable (`1 - P(BENIGN)` score calculated dynamically when string labels are present)

#### EMBER File Model (`ember`)
- [x] Model trained and serialized (`trained_models/ember/aegis_ember_model_full.pkl` verified loading dict export containing LightGBM model via `joblib.load`; trained via `ml_notebooks/ember/ember.ipynb`)
- [x] Label encoder / vectorizer / feature list artifacts present (`features` list embedded inside `aegis_ember_model_full.pkl` dict export)
- [x] Label mapping verified correct (verified against real samples via `agent/diagnostics/check_ember_label_mapping.py` — 6/6 PASS)
- [x] Usable threat/anomaly score achievable (`P(malicious)` score calculated via binary classifier index 1)

#### HDFS Log Anomaly (`hdfs`)
- [x] Model trained and serialized (`trained_models/hdfs/hdfs_xgboost_model.pkl` verified loading `XGBClassifier` via `joblib.load`; trained via `ml_notebooks/hdfs/HDFS_Anomaly_Detection.ipynb`)
- [x] Label encoder / vectorizer / feature list artifacts present (`trained_models/hdfs/hdfs_vectorizer.pkl` [5000-dim TF-IDF] and `hdfs_label_encoder.pkl` verified)
- [x] Label mapping verified correct (verified against real samples via `agent/diagnostics/check_hdfs_label_mapping.py`)
- [x] Usable threat/anomaly score achievable (`P(Anomaly)` score calculated dynamically)

#### Zero-Day Anomaly (`zero_day`)
- [x] Model trained and serialized (`trained_models/zero_day/aegis_zero_day_model.pkl` verified loading `IsolationForest` via `joblib.load`; trained via `ml_notebooks/Zero_day/ZeroDay_Detection.ipynb`)
- [x] Label encoder / vectorizer / feature list artifacts present (`event_encoder.pkl`, `process_encoder.pkl`, `user_encoder.pkl` verified)
- [x] Label mapping verified (directional check run via `agent/diagnostics/check_zeroday_label_mapping.py` — formula verified, encoder vocabulary limitation documented)
- [x] Usable threat/anomaly score achievable (IsolationForest decision score inverted and mapped via `1 - sigmoid(decision)`)

---

### 1b. Fusion adapter (`agent/fusion_engine.py`)
- [x] ThreatFusionEngine class exists with one scoring method per model (`_score_linux`, `_score_windows`, `score_network_flow`, `score_file`, `score_log_line`, `score_windows_event`)
- [x] `fuse()` implemented with configurable weights (accepts `weights` dict, normalizes weights, handles missing sub-scores gracefully)
- [x] `get_verdict()` implemented with correct thresholds (`<0.30` LOW, `<0.60` MEDIUM, `<0.80` HIGH, `>=0.80` CRITICAL)
- [x] HDFS label-inversion bug fixed and verified (dynamically resolves `"Anomaly"` index to score anomaly probability)
- [x] Linux multiclass-scoring bug fixed and verified (dynamically resolves `"Normal"` index and computes `1 - P(Normal)`)
- [x] Windows Advanced excluded from `fuse()` via validity guard (`_windows_labels_valid` check ignores non-threat session ID labels)

---

### 1c. Live telemetry collectors

#### Linux IDS (`linux_ids`)
- [ ] Live collector built for model input — *Note: Collector component not yet implemented for linux_ids*
- [ ] Collector tested against fusion adapter end-to-end — *Note: Live data integration test pending collector implementation*

#### Windows Advanced (`windows_advanced`)
- [ ] Live collector built for model input — *Note: Collector component not yet implemented for windows_advanced*
- [ ] Collector tested against fusion adapter end-to-end — *Note: Live data integration test pending collector implementation*

#### CICIDS Network (`cicids`)
- [ ] Live collector built for model input — *Note: Collector component not yet implemented for cicids*
- [ ] Collector tested against fusion adapter end-to-end — *Note: Live data integration test pending collector implementation*

#### EMBER File Model (`ember`)
- [ ] Live collector built for model input — *Note: Collector component not yet implemented for ember*
- [ ] Collector tested against fusion adapter end-to-end — *Note: Live data integration test pending collector implementation*

#### HDFS Log Anomaly (`hdfs`)
- [ ] Live collector built for model input — *Note: Collector component not yet implemented for hdfs*
- [ ] Collector tested against fusion adapter end-to-end — *Note: Live data integration test pending collector implementation*

#### Zero-Day Anomaly (`zero_day`)
- [ ] Live collector built for model input — *Note: Collector component not yet implemented for zero_day*
- [ ] Collector tested against fusion adapter end-to-end — *Note: Live data integration test pending collector implementation*

---

### 1d. Heartbeat mechanism
- [ ] Heartbeat emitter implemented — *Note: No heartbeat emitter code found in repository*
- [ ] Silence-detection logic on receiving side — *Note: No silence-detection receiving logic found in repository*

---

## Layer 2 — Peer Voting Protocol
- [ ] VotingRequest broadcast implemented — *Note: No ZeroMQ or peer messaging implementation found in repository*
- [ ] Peer correlation-check logic implemented — *Note: Peer correlation logic not yet created*
- [ ] Weighted vote calculation implemented — *Note: Weighted voting logic (2.0/1.0/0.5/0.3) not yet created*
- [ ] Tested with 2+ agents on separate processes/machines — *Note: Pending Layer 2 protocol implementation*

---

## Layer 3 — Command Node + Dashboard
- [ ] FastAPI backend scaffolded — *Note: No FastAPI backend code found in repository*
- [ ] SQLite schema defined and used — *Note: No SQLite database schema or setup found in repository*
- [ ] Vote aggregation + verdict computation implemented — *Note: Command node vote aggregation not yet implemented*
- [ ] Response action dispatch implemented — *Note: Response dispatch engine (log/alert/kill/isolate) not yet implemented*
- [ ] Streamlit dashboard exists — *Note: No Streamlit dashboard files found in repository*
- [ ] Admin Trust System — *Note: Admin trust system (identity, behavior, maintenance windows) not yet implemented*

---

## Cross-cutting
- [ ] `progress_status.md` matches this checklist — *Note: progress_status.md is stale (e.g. lists EMBER model as pending when aegis_ember_model_full.pkl is trained and working)*
- [ ] VM test environment set up — *Note: VirtualBox test harness pending live agent completion*
