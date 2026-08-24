# Windows Advanced EDR Model Documentation

## Model Status: VALID BUT QUARANTINED

> [!WARNING]
> **COMPATIBILITY WARNING:** The Windows Advanced XGBoost model is fully trained and mathematically valid, but it is currently **NOT COMPATIBLE** with the live Windows telemetry collection available in this EDR agent. It has been safely quarantined and excluded from live fusion and confidence calculations.

---

### Specifications

* **Training dataset:**
  ADFA-WD-SAA (`Full_Process_Traces`)

* **Training representation:**
  Fixed-length sequences of `1000` integer-encoded **module+offset** calling tokens (e.g. `ntdll.dll+0x16d33`, `kernel32.dll+0xb50b`).

* **Live telemetry currently available:**
  Sysmon Event ID 7 (Image Loaded) **DLL names** (e.g. `ntdll.dll`, `kernel32.dll`).

* **Compatibility:**
  **NOT COMPATIBLE** (Clean DLL names share 0% overlap with the calling-offset vocabulary, causing all-zeros feature vectors).

* **Live fusion:**
  **DISABLED SAFELY** (Scoring returns `None`/unavailable with explicit telemetry mismatch alerts; excluded from fusion weighted averages).

* **Retraining:**
  **NOT CURRENTLY REQUIRED** (The model itself is correctly trained; the mismatch is a serving representation gap).

---

### Future Work & Next Steps
To re-enable Windows endpoint classification in the ThreatFusionEngine, do one of the following:
1. **Implement Offset Collection:** Upgrade the live telemetry provider (e.g. via ETW call stack walking or user-space API hooking) to capture calling addresses/offsets, and supply them in `dll_name+offset` format to match the model's feature contract.
2. **Train a Live-Aligned Model:** Train a new Windows model using realistically observable features (e.g. raw image load DLL name sequences or Event ID 10 call stacks).
