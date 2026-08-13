import argparse
import os
import sys

import joblib
import numpy as np


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

MODEL_PATH = os.path.join(
    PROJECT_ROOT,
    "trained_models",
    "linux_ids",
    "linux_xgboost_model.pkl",
)

ENCODER_PATH = os.path.join(
    PROJECT_ROOT,
    "trained_models",
    "linux_ids",
    "linux_label_encoder.pkl",
)


def load_model():
    print("[1] Loading Linux model...")

    model = joblib.load(MODEL_PATH)
    encoder = joblib.load(ENCODER_PATH)

    print(f"    Model: {type(model).__name__}")
    print(f"    Expected features: {model.n_features_in_}")
    print(f"    Classes: {list(encoder.classes_)}")

    return model, encoder


def prepare_sequence(sequence):
    """
    Reproduce the shape expected by the trained Linux model.
    """

    sequence = [int(x) for x in sequence]

    if len(sequence) > 500:
        sequence = sequence[:500]

    if len(sequence) < 500:
        sequence += [0] * (500 - len(sequence))

    return np.asarray(sequence, dtype=np.float32).reshape(1, 500)


def score_sequence(sequence):
    model, encoder = load_model()

    X = prepare_sequence(sequence)

    probabilities = model.predict_proba(X)[0]

    normal_index = list(encoder.classes_).index("Normal")

    normal_probability = float(probabilities[normal_index])

    threat_score = 1.0 - normal_probability

    predicted_index = int(np.argmax(probabilities))
    predicted_label = encoder.inverse_transform(
        [predicted_index]
    )[0]

    print()
    print("========== LINUX MODEL RESULT ==========")
    print(f"Predicted class : {predicted_label}")
    print(f"P(Normal)       : {normal_probability:.6f}")
    print(f"Threat score    : {threat_score:.6f}")
    print()

    print("Class probabilities:")

    for label, probability in zip(
        encoder.classes_,
        probabilities
    ):
        print(f"  {label:<20} {probability:.6f}")

    return threat_score


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--sequence",
        nargs="+",
        type=int,
        required=True,
        help="Syscall IDs"
    )

    args = parser.parse_args()

    score_sequence(args.sequence)


if __name__ == "__main__":
    main()