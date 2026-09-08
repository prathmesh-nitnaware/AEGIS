# AEGIS - Stage 1: Linux Live Telemetry & Model 1 Validation

This stage validates the live end-to-end telemetry pipeline for **Model 1: Linux IDS (`linux_ids`)**.

> [!NOTE]
> **Status:** Stage 1 live telemetry collector validation is **COMPLETE & INTEGRATED** into `agent/linux_collector.py` and orchestrated via `agent/run_all.py`.

---

## Architecture Overview

```
 ┌─────────────────────────────────────────────────────────┐
 │               Linux Kernel / Synthetic Stream           │
 └────────────────────────────┬────────────────────────────┘
                              │ ftrace / synthetic
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │       SyscallCollector (agent/linux_collector.py)       │
 └────────────────────────────┬────────────────────────────┘
                              │ SyscallEvent / syscall_number
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │        SyscallBuffer (agent/linux_collector.py)         │
 │       Pads/Truncates sequence to int64[500]             │
 └────────────────────────────┬────────────────────────────┘
                              │ syscall_sequence (500 ints)
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │        ThreatFusionEngine (agent/fusion_engine.py)      │
 │  Score: 1 - P(Normal) via trained linux_xgboost_model   │
 └─────────────────────────────────────────────────────────┘
```

---

## Target Classes

The trained Linux IDS model (`linux_xgboost_model.pkl`) evaluates system call integer vectors of length 500 across 7 distinct classes:

1. **Normal** — Clean process execution (`read`, `write`, `openat`, `futex`, etc.)
2. **Adduser** — Unauthorized user account creation (`/etc/passwd` modifications, privilege changes)
3. **Hydra_FTP** — Rapid FTP brute-force connection loop
4. **Hydra_SSH** — Rapid SSH authentication probe loop
5. **Java_Meterpreter** — Memory allocation, `ptrace`, dynamic payload execution via Java process
6. **Meterpreter** — Native Linux shellcode execution, socket connect, executable memory mapping
7. **Web_Shell** — Pipe redirection, process spawn (`execve`), HTTP stream execution

---

## Validation & Execution

Execute the validation script from the AEGIS workspace root:

```bash
python experiments/stage1/validate_linux_live.py
```

### Verified Behaviors
- Verification of `SyscallBuffer` sequence length formatting (exact 500 elements).
- Background `SyscallCollector` thread lifecycle.
- End-to-end scoring of target classes via `ThreatFusionEngine._score_linux()`.
- Normal sequences produce a low threat score (`LOW` verdict), while attack sequences produce elevated threat scores (`HIGH` or `CRITICAL` verdicts).
- Production integration completed in `agent/linux_collector.py` and `agent/run_all.py`.
