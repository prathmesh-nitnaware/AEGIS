"""
ml_notebooks/windows_advanced/retrain_windows.py
=================================================
AEGIS - Windows Advanced XGBoost Model Retraining Script
---------------------------------------------------------
Re-trains the Windows Advanced model (Model 2) on the ADFA-WD-SAA dataset
using PROPER binary threat labels:

    S1  ->  "Normal"   (legitimate user / baseline sessions)
    S2  ->  "Attack"   (Hydra FTP brute-force)
    S3  ->  "Attack"   (Hydra SSH brute-force)
    S4  ->  "Attack"   (Drive-by Download exploit)

This fixes the original notebook which used the raw folder names S1/S2/S3/S4
as class labels -- session IDs that carry no threat-semantic meaning and cause
fusion_engine.py's _has_threat_labels() check to fail, excluding the Windows
sub-score from fuse() entirely.

Outputs (written to trained_models/windows_advanced/):
    windows_advanced_xgboost.pkl  -- retrained XGBClassifier
    token_encoder.pkl             -- LabelEncoder fitted on API/DLL call names
    label_encoder.pkl             -- Binary LabelEncoder: classes_=["Attack","Normal"]

Run from the project root:
    python ml_notebooks/windows_advanced/retrain_windows.py
"""

from __future__ import annotations

import io
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np

# Force UTF-8 stdout on Windows console
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_HERE         = Path(__file__).resolve().parent   # .../ml_notebooks/windows_advanced/
_PROJECT_ROOT = _HERE.parent.parent               # .../AEGIS/

if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

DATASET_PATH = (
    _PROJECT_ROOT
    / "Dataset"
    / "ADFA_dataset"
    / "ADFA-WD-SAA_Master"
    / "ADFA-WD-SAA_Master"
    / "Full_Process_Traces"
)
OUTPUT_DIR = _PROJECT_ROOT / "trained_models" / "windows_advanced"
SEQ_LEN    = 1000   # fixed vector length expected by XGBoost
MIN_TOKENS = 5      # skip near-empty .GHC files (1-2 tokens pad to mostly zeros)

SEP  = "=" * 72
DASH = "-" * 72

# ---------------------------------------------------------------------------
# Label mapping  (S1 = Normal,  S2/S3/S4 = Attack)
# ---------------------------------------------------------------------------
LABEL_MAP: Dict[str, str] = {
    "S1": "Normal",
    "S2": "Attack",
    "S3": "Attack",
    "S4": "Attack",
}


def load_dataset(root: Path) -> Tuple[List[List[str]], List[str]]:
    """
    Walk DATASET_PATH recursively; read every .GHC file (whitespace-separated
    API/DLL call tokens).  Derive the binary label from the top-level
    session folder (S1/S2/S3/S4) via LABEL_MAP.
    """
    try:
        from tqdm import tqdm
        _use_tqdm = True
    except ImportError:
        _use_tqdm = False

    all_sequences: List[List[str]] = []
    all_labels: List[str] = []
    skipped = 0

    print(f"\nReading dataset from: {root}")
    print("Label map: S1 -> Normal  |  S2/S3/S4 -> Attack\n")

    for session_dir in sorted(root.iterdir()):
        if not session_dir.is_dir():
            continue
        session_key = session_dir.name     # "S1", "S2", "S3", "S4"
        threat_label = LABEL_MAP.get(session_key)
        if threat_label is None:
            print(f"  [SKIP] Unknown session folder: {session_dir.name}")
            continue

        ghc_files = list(session_dir.rglob("*.GHC"))
        if not ghc_files:
            print(f"  [WARN] No .GHC files found in {session_dir.name}")
            continue

        print(f"  {session_key} -> '{threat_label}'  ({len(ghc_files)} .GHC files)")

        file_iter = (
            tqdm(ghc_files, desc=f"    {session_key}", leave=False)
            if _use_tqdm else ghc_files
        )
        for fp in file_iter:
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore").strip()
                tokens = content.split()
                if len(tokens) >= MIN_TOKENS:
                    all_sequences.append(tokens)
                    all_labels.append(threat_label)
                else:
                    skipped += 1
            except Exception as exc:
                print(f"\n  [ERROR] Reading {fp}: {exc}")
                skipped += 1

    print(f"\nLoaded  : {len(all_sequences)} sequences")
    print(f"Skipped : {skipped} empty / unreadable files")
    print(f"Label distribution: {Counter(all_labels)}")
    return all_sequences, all_labels


def build_token_encoder(all_sequences: List[List[str]]):
    """Fit a LabelEncoder on every unique API/DLL token seen in training data."""
    from sklearn.preprocessing import LabelEncoder

    all_tokens = sorted({tok for seq in all_sequences for tok in seq})
    print(f"\nUnique API/DLL tokens: {len(all_tokens)}")
    le = LabelEncoder()
    le.fit(all_tokens)
    return le


def encode_sequences(
    all_sequences: List[List[str]],
    token_map: Dict[str, int],
    seq_len: int,
) -> np.ndarray:
    """
    Encode each token via token_map (unknown tokens -> 0),
    then pad / truncate each sequence to exactly seq_len integers.
    Returns a 2-D int64 array of shape (N, seq_len).
    """
    print(f"\nEncoding {len(all_sequences)} sequences to length {seq_len}...")
    rows = []
    for seq in all_sequences:
        encoded = [token_map.get(tok, 0) for tok in seq]
        if len(encoded) >= seq_len:
            encoded = encoded[:seq_len]
        else:
            encoded = encoded + [0] * (seq_len - len(encoded))
        rows.append(encoded)
    return np.array(rows, dtype=np.int64)


def train_model(X: np.ndarray, y_enc: np.ndarray):
    """Train XGBClassifier with same hyperparameters as the original notebook."""
    from xgboost import XGBClassifier

    clf = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )
    print("\nTraining XGBClassifier...")
    clf.fit(X, y_enc)
    return clf


def evaluate_model(clf, X_test: np.ndarray, y_test: np.ndarray, label_names: List[str]) -> None:
    """Print accuracy and classification report on the held-out test split."""
    from sklearn.metrics import classification_report, accuracy_score

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nTest Accuracy: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=label_names))


def save_artefacts(clf, token_enc, label_enc, output_dir: Path) -> None:
    """Serialize all three artefacts to output_dir (overwriting old ones)."""
    output_dir.mkdir(parents=True, exist_ok=True)

    model_path = output_dir / "windows_advanced_xgboost.pkl"
    token_path = output_dir / "token_encoder.pkl"
    label_path = output_dir / "label_encoder.pkl"

    joblib.dump(clf,       model_path)
    joblib.dump(token_enc, token_path)
    joblib.dump(label_enc, label_path)

    print(f"\n{SEP}")
    print("  Artefacts saved to trained_models/windows_advanced/:")
    print(f"    windows_advanced_xgboost.pkl  ({model_path.stat().st_size:,} bytes)")
    print(f"    token_encoder.pkl             ({token_path.stat().st_size:,} bytes)")
    print(f"    label_encoder.pkl             ({label_path.stat().st_size:,} bytes)")
    print(f"\n  label_encoder.classes_ = {list(label_enc.classes_)}")
    print(SEP)


def main() -> int:
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder
    from imblearn.over_sampling import RandomOverSampler

    print(SEP)
    print("  AEGIS - Windows Advanced XGBoost Model Retraining")
    print("  Re-labelling: S1=Normal, S2/S3/S4=Attack")
    print(SEP)

    # ------------------------------------------------------------------
    # 1. Load raw sequences + binary labels
    # ------------------------------------------------------------------
    if not DATASET_PATH.exists():
        print(f"\n[FAIL] Dataset path not found:\n  {DATASET_PATH}")
        return 1

    all_sequences, all_labels = load_dataset(DATASET_PATH)

    if not all_sequences:
        print("\n[FAIL] No sequences loaded -- check dataset path and .GHC files.")
        return 1

    # ------------------------------------------------------------------
    # 2. Build token encoder (API/DLL call names -> integer IDs)
    # ------------------------------------------------------------------
    token_enc = build_token_encoder(all_sequences)
    token_map: Dict[str, int] = {
        label: idx for idx, label in enumerate(token_enc.classes_)
    }

    # ------------------------------------------------------------------
    # 3. Encode sequences + encode binary labels
    # ------------------------------------------------------------------
    X = encode_sequences(all_sequences, token_map, SEQ_LEN)

    label_enc = LabelEncoder()
    y_enc = label_enc.fit_transform(all_labels)
    print(f"\nLabel encoder classes  : {list(label_enc.classes_)}")
    print(f"Encoded distribution   : {Counter(y_enc.tolist())}")

    # ------------------------------------------------------------------
    # 4. Train / test split (stratified)
    # ------------------------------------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.20, random_state=42, stratify=y_enc
    )
    print(f"\nTrain: {X_train.shape[0]} samples  |  Test: {X_test.shape[0]} samples")

    # ------------------------------------------------------------------
    # 5. Oversample minority class on training set only
    # ------------------------------------------------------------------
    print(f"\nBefore oversampling: {Counter(y_train.tolist())}")
    ros = RandomOverSampler(random_state=42)
    X_train_res, y_train_res = ros.fit_resample(X_train, y_train)
    print(f"After oversampling : {Counter(y_train_res.tolist())}")

    # ------------------------------------------------------------------
    # 6. Train XGBoost
    # ------------------------------------------------------------------
    clf = train_model(X_train_res, y_train_res)

    # ------------------------------------------------------------------
    # 7. Evaluate on held-out test set
    # ------------------------------------------------------------------
    evaluate_model(clf, X_test, y_test, list(label_enc.classes_))

    # ------------------------------------------------------------------
    # 8. Save all three artefacts
    # ------------------------------------------------------------------
    save_artefacts(clf, token_enc, label_enc, OUTPUT_DIR)

    print("\n[SUCCESS] Windows Advanced model retrained with proper Normal/Attack labels.")
    print("          Run: python agent/diagnostics/check_windows_label_mapping.py")
    print("          to verify the new model end-to-end.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
