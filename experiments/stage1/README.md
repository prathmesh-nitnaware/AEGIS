# AEGIS - Stage 1: Linux Live Telemetry & Model 1 Validation

This stage validates the live end-to-end telemetry pipeline for **Model 1: Linux IDS (`linux_ids`)**.

---

## Architecture Overview

```
 ┌─────────────────────────────────────────────────────────┐
 │               Linux Kernel / Synthetic Stream           │
 └────────────────────────────┬────────────────────────────┘
                              │ ftrace / synthetic
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │       SyscallCollector (agent/telemetry/linux/)         │
 └────────────────────────────┬────────────────────────────┘
                              │ SyscallEvent / syscall_number
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │        SyscallBuffer (agent/telemetry/linux/)           │
 │       Padds/Truncates sequence to int64[500]           │
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

## Running Live Validation

Execute the validation script from the AEGIS workspace root:

```bash
python3 stage1/validate_linux_live.py
```

### Expected Output
- Verification of `SyscallBuffer` sequence length formatting (exact 500 elements).
- Background `SyscallCollector` thread lifecycle tests.
- End-to-end scoring of all 7 target classes via `ThreatFusionEngine.score_process_event()`.
- Assertion that normal sequences receive a low threat score (`LOW` verdict) while attack sequences produce elevated threat scores (`HIGH` or `CRITICAL` verdicts).



# AEGIS Linux Live Telemetry — Stage 1

## Objective

Validate whether syscall IDs captured from the live Linux environment
are compatible with the representation used by the trained AEGIS Linux
XGBoost model.

## Current model

- Model: XGBoost
- Input: 500 integer syscall IDs
- Classes:
  - Adduser
  - Hydra_FTP
  - Hydra_SSH
  - Java_Meterpreter
  - Meterpreter
  - Normal
  - Web_Shell

## Stage 1 flow

Linux kernel
    ↓
bpftrace
    ↓
raw syscall events
    ↓
syscall ID
    ↓
per-process sequence
    ↓
500 values
    ↓
Linux XGBoost
    ↓
P(Normal)
    ↓
1 - P(Normal)

## Important

The per-process sequence strategy is currently an experimental
Stage 1 design. It is not yet the final AEGIS inference-window policy.

The live syscall representation must be validated against the
ADFA-LD training representation before the collector is considered
production-ready.
