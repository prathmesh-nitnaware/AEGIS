import io
import os
import sys
import warnings
import joblib
import numpy as np
import pandas as pd

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

warnings.filterwarnings("ignore")


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

DATASET_DIR = os.path.join(
    BASE_DIR,
    "Dataset",
    "CICIDS"
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "trained_models",
    "cicids",
    "aegis_lgbm_cicids_model.pkl"
)

CSV_FILES = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
]

# Process dataset in small pieces to avoid RAM problems
CHUNK_SIZE = 25000


# ============================================================
# LOAD MODEL
# ============================================================

print("=" * 75)
print("AEGIS CICIDS2017 MODEL EVALUATION")
print("=" * 75)

print("\nLoading model...")

bundle = joblib.load(MODEL_PATH)

model = bundle["model"]
label_encoder = bundle["label_encoder"]
model_features = bundle["features"]

classes = list(label_encoder.classes_)

print("Model          :", type(model).__name__)
print("Features       :", len(model_features))
print("Classes        :", len(classes))

print("\nClasses:")

for i, c in enumerate(classes):
    print(f"{i:2d} : {c}")


# ============================================================
# LABEL NORMALIZATION
# ============================================================

def normalize_label(label):
    label = str(label).strip()
    # Normalize unicode dash characters to standard hyphens/spaces
    label = label.replace("–", "-").replace("—", "-")
    label = " ".join(label.split())

    # Exact match in model classes
    if label in classes:
        return label

    # Case-insensitive match
    for c in classes:
        if c.lower() == label.lower():
            return c

    # Handle Web Attack labels
    if "Web Attack" in label:
        if "Brute Force" in label:
            return next(c for c in classes if "Web Attack" in c and "Brute Force" in c)
        if "Sql Injection" in label or "SQL Injection" in label:
            return next(c for c in classes if "Web Attack" in c and "Sql Injection" in c)
        if "XSS" in label:
            return next(c for c in classes if "Web Attack" in c and "XSS" in c)

    # Try mapping hyphenated spaces or space-separated hyphens
    label_hyph = label.replace(" ", "-")
    for c in classes:
        if c.replace(" ", "-").lower() == label_hyph.lower():
            return c

    return label



# ============================================================
# GLOBAL RESULTS
# ============================================================

all_true = []
all_pred = []

total_rows = 0


# ============================================================
# PROCESS DATASET
# ============================================================

print("\n" + "=" * 75)
print("PROCESSING DATASET")
print("=" * 75)


for filename in CSV_FILES:

    path = os.path.join(DATASET_DIR, filename)

    if not os.path.exists(path):
        print(f"\n[ERROR] Missing file: {filename}")
        continue

    print("\n" + "-" * 75)
    print("FILE:", filename)
    print("-" * 75)

    # --------------------------------------------------------
    # SELECT ENCODING
    # --------------------------------------------------------
    #
    # The WebAttacks file contains Windows-1252 characters.
    # The other CICIDS files are read as UTF-8.
    #

    if "WebAttacks" in filename:
        encoding = "cp1252"
    else:
        encoding = "utf-8"

    print("Encoding:", encoding)

    # --------------------------------------------------------
    # CREATE CHUNK READER
    # --------------------------------------------------------

    reader = pd.read_csv(
        path,
        encoding=encoding,
        low_memory=False,
        chunksize=CHUNK_SIZE
    )

    file_rows = 0

    # --------------------------------------------------------
    # PROCESS EACH CHUNK
    # --------------------------------------------------------

    for chunk_number, df in enumerate(reader, start=1):

        # ----------------------------------------------------
        # CLEAN COLUMN NAMES
        # ----------------------------------------------------

        df.columns = (
            df.columns
            .astype(str)
            .str.strip()
        )

        # ----------------------------------------------------
        # FIND LABEL COLUMN
        # ----------------------------------------------------

        label_col = None

        for col in df.columns:

            if col.lower() == "label":
                label_col = col
                break

        if label_col is None:

            raise RuntimeError(
                f"Label column not found in {filename}"
            )

        # Filter out NaN/null rows in label column
        df = df[df[label_col].notna()].copy()
        df = df[df[label_col].astype(str).str.strip().str.lower() != "nan"].copy()
        if len(df) == 0:
            continue

        # ----------------------------------------------------
        # NORMALIZE LABELS
        # ----------------------------------------------------

        y_text = (
            df[label_col]
            .astype(str)
            .map(normalize_label)
        )

        # ----------------------------------------------------
        # CHECK FOR UNKNOWN LABELS
        # ----------------------------------------------------

        unknown = set(y_text) - set(classes)

        if unknown:

            print("\n[ERROR] Unknown labels:")

            for x in sorted(unknown):
                print(repr(x))

            print("\nExpected classes:")

            for x in classes:
                print(repr(x))

            raise RuntimeError(
                "Dataset labels do not match model classes."
            )

        # ----------------------------------------------------
        # CHECK MODEL FEATURES
        # ----------------------------------------------------

        missing = [
            f for f in model_features
            if f not in df.columns
        ]

        if missing:

            print("\nMissing features:")

            for f in missing:
                print(f)

            raise RuntimeError(
                "Dataset is missing model features."
            )

        # ----------------------------------------------------
        # SELECT EXACT MODEL FEATURES
        # ----------------------------------------------------

        X = df[model_features].copy()

        # ----------------------------------------------------
        # CONVERT FEATURES TO NUMERIC
        # ----------------------------------------------------

        for col in X.columns:

            X[col] = pd.to_numeric(
                X[col],
                errors="coerce"
            )

        # ----------------------------------------------------
        # CLEAN NaN AND INFINITY
        # ----------------------------------------------------

        X = X.replace(
            [np.inf, -np.inf],
            np.nan
        )

        X = X.fillna(0)

        # ----------------------------------------------------
        # ENCODE TRUE LABELS
        # ----------------------------------------------------

        y_true = label_encoder.transform(y_text)

        # ----------------------------------------------------
        # MODEL PREDICTION
        # ----------------------------------------------------

        y_pred = model.predict(X)

        y_pred = np.asarray(y_pred).astype(int)

        # ----------------------------------------------------
        # STORE RESULTS
        # ----------------------------------------------------

        all_true.extend(
            y_true.tolist()
        )

        all_pred.extend(
            y_pred.tolist()
        )

        file_rows += len(df)
        total_rows += len(df)

        # ----------------------------------------------------
        # PROGRESS
        # ----------------------------------------------------

        if chunk_number % 5 == 0:

            print(
                f"  Chunk {chunk_number} | "
                f"Rows processed: {file_rows:,}"
            )

    print(
        f"File complete: {file_rows:,} rows"
    )


# ============================================================
# FINAL RESULTS
# ============================================================

y_true = np.array(all_true)
y_pred = np.array(all_pred)

print("\n" + "=" * 75)
print("FINAL RESULTS")
print("=" * 75)

print(
    "Total samples:",
    f"{total_rows:,}"
)

# ------------------------------------------------------------
# Accuracy
# ------------------------------------------------------------

# ------------------------------------------------------------
# Accuracy & Balanced Accuracy
# ------------------------------------------------------------
accuracy = accuracy_score(y_true, y_pred)
balanced_accuracy = balanced_accuracy_score(y_true, y_pred)

# ------------------------------------------------------------
# Macro Precision, Recall, F1
# ------------------------------------------------------------
macro_precision = precision_score(y_true, y_pred, average="macro", zero_division=0)
macro_recall = recall_score(y_true, y_pred, average="macro", zero_division=0)
macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)

print(f"\nAccuracy          : {accuracy:.6f}")
print(f"Balanced Accuracy : {balanced_accuracy:.6f}")
print(f"Macro Precision   : {macro_precision:.6f}")
print(f"Macro Recall      : {macro_recall:.6f}")
print(f"Macro F1          : {macro_f1:.6f}")
print(f"Weighted F1       : {weighted_f1:.6f}")



# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print("\n" + "=" * 75)
print("CLASSIFICATION REPORT")
print("=" * 75)

print(
    classification_report(
        y_true,
        y_pred,
        labels=list(range(len(classes))),
        target_names=classes,
        zero_division=0,
        digits=4
    )
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

print("\n" + "=" * 75)
print("CONFUSION MATRIX")
print("=" * 75)

cm = confusion_matrix(
    y_true,
    y_pred,
    labels=list(range(len(classes)))
)

print("\nRows = Actual")
print("Columns = Predicted\n")

print("       ", end="")

for i in range(len(classes)):
    print(f"{i:5d}", end="")

print()

for i, row in enumerate(cm):

    print(
        f"{i:3d} : ",
        end=""
    )

    for value in row:
        print(
            f"{value:5d}",
            end=""
        )

    print()


# ============================================================
# CLASS DISTRIBUTION
# ============================================================

print("\n" + "=" * 75)
print("ACTUAL CLASS DISTRIBUTION")
print("=" * 75)

for i, cls in enumerate(classes):

    actual = int(
        np.sum(y_true == i)
    )

    predicted = int(
        np.sum(y_pred == i)
    )

    print(
        f"{i:2d} | "
        f"{cls:<35} | "
        f"Actual: {actual:>10,} | "
        f"Predicted: {predicted:>10,}"
    )


# ============================================================
# COMPLETE
# ============================================================

print("\n" + "=" * 75)
print("EVALUATION COMPLETE")
print("=" * 75)