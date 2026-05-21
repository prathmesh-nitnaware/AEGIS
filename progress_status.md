# Project AEGIS – Progress State Report

---

## 📅 Repository Activity
- **Repository:** [AEGIS](https://github.com/prathmesh-nitnaware/AEGIS)
- **Owner:** Prathmesh Nitnaware
- **Commits to Date:** Multiple commits including model training updates
- **Primary Development Language:** Jupyter Notebook (100%)

---

## ✅ Tasks Completed Till Now

### 1. ML Model Training & Purpose

#### 🗂️ HDFS Dataset (Big Data Logs)
- **Algorithm:** XGBoost + TD‑IFS (Tree‑based Isolation Forest Strategy)
- **Purpose:**  
  - Detect anomalies in distributed file system logs (HDFS).  
  - Identify ransomware‑like bulk file operations, unusual write patterns, and log tampering.  
- **Role in AEGIS:**  
  - Integrated into **Layer 1 (EDR Agent)** for anomaly detection in enterprise‑scale distributed storage systems.  
  - Provides **early warning signals** for attacks targeting big‑data clusters.  

---

#### 🐧 Linux Dataset
- **Algorithm:** XGBoost
- **Purpose:**  
  - Detect malicious process/file behaviours specific to Linux environments.  
  - Identify privilege escalation attempts, suspicious parent‑child process chains, and persistence mechanisms.  
- **Role in AEGIS:**  
  - Strengthens **Linux endpoint monitoring**.  
  - Used by agents running on Linux machines to classify known attack patterns with high confidence.  

---

#### 🪟 Advanced Windows Dataset
- **Algorithm:** XGBoost
- **Purpose:**  
  - Detect advanced persistence and privilege escalation behaviours in Windows telemetry.  
  - Identify registry modifications, startup key changes, and LOLBins misuse.  
- **Role in AEGIS:**  
  - Provides **supervised detection** for Windows endpoints.  
  - Complements anomaly detection by catching **known attack signatures**.  

---

#### 🌐 CICIDS Dataset (Canadian Institute for Cybersecurity Intrusion Detection)
- **Algorithm:** LightGBM
- **Purpose:**  
  - Network intrusion detection trained on labelled traffic data.  
  - Classifies known attack patterns: DoS, DDoS, brute force, port scans, botnet traffic.  
- **Role in AEGIS:**  
  - Integrated into **network telemetry analysis**.  
  - Provides **high‑confidence classification** of suspicious network flows.  
  - Used in **peer voting protocol** when anomalies are network‑related.  

---

#### 📜 Windows Logs Dataset
- **Algorithm:** Isolation Forest (unsupervised anomaly detection)
- **Purpose:**  
  - Detect statistical anomalies in Windows log activity.  
  - Identify zero‑day and novel threats without requiring labelled data.  
- **Role in AEGIS:**  
  - Acts as the **zero‑day detection engine** for Windows endpoints.  
  - Complements supervised models by catching **unknown behaviours**.  
  - Integrated into **heartbeat + anomaly scoring pipeline**.  

---

### 2. Repository Structure
- **`ml_notebooks/`**
  - Contains Jupyter notebooks documenting the training process for each dataset.
  - Includes preprocessing steps, feature engineering, and evaluation metrics.

- **`trained_models/`**
  - Stores serialized trained models (likely `.pkl` or `.joblib` format).
  - Models available for direct integration into the AEGIS agent pipeline.

- **`.gitignore`**
  - Updated to exclude unnecessary files during commits (logs, temp files, etc.).

---

### 3. Commit Highlights
- **Commit:** *“Trained HDFS Dataset using XGBoost + TD‑IFS”*  
- **Commit:** *“Trained XGBoost model on Linux and Advanced Windows Dataset”*  
- **Commit:** *“Trained CICIDS Dataset model using LightGBM for intrusion detection”*  
- **Commit:** *“Trained Windows Logs Dataset using Isolation Forest”*  

---

## 📊 Current State of Models
| Dataset              | Algorithm(s)         | Purpose                                      | Role in AEGIS |
|----------------------|----------------------|----------------------------------------------|---------------|
| HDFS Logs            | XGBoost + TD‑IFS     | Anomaly detection in distributed logs        | Detect ransomware/file anomalies in big‑data clusters |
| Linux System Dataset | XGBoost              | Detect malicious process/file behaviours     | Strengthen Linux endpoint monitoring |
| Advanced Windows     | XGBoost              | Detect persistence & privilege escalation    | Supervised detection for Windows endpoints |
| CICIDS Network Data  | LightGBM             | Intrusion detection (DoS, DDoS, brute force) | Network telemetry classification |
| Windows Logs         | Isolation Forest     | Zero‑day anomaly detection in logs           | Unsupervised anomaly detection for Windows endpoints |

---

## 🔍 Integration Status
- **Agent ML Pipeline:**  
  - Models are ready for integration into Layer 1 (EDR Agent).  
  - Hybrid scoring (Isolation Forest + Random Forest) described in blueprint now extended with **XGBoost + LightGBM + Isolation Forest** models for OS‑specific and network intrusion detection.  

- **Next Steps:**  
  - Benchmark trained models against EMBER dataset for process/file features.  
  - Integrate SHAP explainability for Random Forest/XGBoost/LightGBM outputs.  
  - Deploy trained models into agent daemon for real‑time scoring.  

---

## 📌 Pending Tasks
- Implement **peer voting protocol** in repo (currently blueprint only).  
- Add **Command Node backend (FastAPI + SQLite)**.  
- Build **Streamlit dashboard** for live monitoring.  
- Conduct **malware testing in VirtualBox VMs** with Wireshark verification.  

---

## 🧪 Evaluation Metrics (Planned)
- Detection Rate (TPR)  
- False Positive Rate  
- Mean Time to Detect (MTTD)  
- Mean Time to Respond (MTTR)  
- Heartbeat alarm latency  

---

## 🔗 Repository Link
GitHub: [AEGIS Project](https://github.com/prathmesh-nitnaware/AEGIS)

---
