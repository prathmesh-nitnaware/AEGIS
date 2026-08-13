import joblib
import numpy as np

MODEL_PATH = "trained_models/linux_ids/linux_xgboost_model.pkl"
ENCODER_PATH = "trained_models/linux_ids/linux_label_encoder.pkl"
INPUT_PATH = "stage2_python2_500.txt"

print("[1] Loading Linux model...")

model = joblib.load(MODEL_PATH)
encoder = joblib.load(ENCODER_PATH)

print(f"Model: {type(model).__name__}")
print(f"Expected features: {model.n_features_in_}")
print(f"Classes: {encoder.classes_}")

# --------------------------------------------------
# Read live syscall telemetry
# --------------------------------------------------

with open(INPUT_PATH, "r") as f:
    syscalls = [int(line.strip()) for line in f if line.strip()]

print(f"\nCaptured syscall values: {len(syscalls)}")

# --------------------------------------------------
# Validate exactly 500 features
# --------------------------------------------------

if len(syscalls) != 500:
    raise ValueError(
        f"Expected 500 syscall values, got {len(syscalls)}"
    )

X = np.array(syscalls, dtype=np.int64).reshape(1, -1)

print(f"Input shape: {X.shape}")

# --------------------------------------------------
# Run model
# --------------------------------------------------

probabilities = model.predict_proba(X)[0]

predicted_index = int(np.argmax(probabilities))
predicted_class = encoder.inverse_transform([predicted_index])[0]

# Find Normal dynamically
normal_indices = np.where(encoder.classes_ == "Normal")[0]

if len(normal_indices) == 0:
    raise ValueError("Normal class not found in label encoder")

normal_index = int(normal_indices[0])
normal_probability = float(probabilities[normal_index])

threat_score = 1.0 - normal_probability

# --------------------------------------------------
# Output
# --------------------------------------------------

print("\n========== LIVE LINUX MODEL RESULT ==========")

print(f"Predicted class : {predicted_class}")
print(f"P(Normal)       : {normal_probability:.6f}")
print(f"Threat score    : {threat_score:.6f}")

print("\nClass probabilities:")

for label, probability in zip(encoder.classes_, probabilities):
    print(f"{label:<20} {probability:.6f}")
