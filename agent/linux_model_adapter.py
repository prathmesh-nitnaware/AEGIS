import joblib
import numpy as np


class LinuxModelAdapter:

    WINDOW_SIZE = 500

    def __init__(
        self,
        model_path="trained_models/linux_ids/linux_xgboost_model.pkl",
        encoder_path="trained_models/linux_ids/linux_label_encoder.pkl",
    ):
        self.model = joblib.load(model_path)
        self.encoder = joblib.load(encoder_path)

        expected = getattr(self.model, "n_features_in_", None)

        if expected != self.WINDOW_SIZE:
            raise ValueError(
                f"Linux model expects {expected} features, "
                f"but AEGIS expects {self.WINDOW_SIZE}"
            )

        classes = list(self.encoder.classes_)

        if "Normal" not in classes:
            raise ValueError("Normal class not found")

        self.normal_index = classes.index("Normal")

    def predict(self, syscall_sequence):

        if len(syscall_sequence) != self.WINDOW_SIZE:
            raise ValueError(
                f"Expected {self.WINDOW_SIZE} syscall IDs, "
                f"got {len(syscall_sequence)}"
            )

        X = np.asarray(
            syscall_sequence,
            dtype=np.int64
        ).reshape(1, -1)

        probabilities = self.model.predict_proba(X)[0]

        predicted_index = int(np.argmax(probabilities))

        predicted_class = self.encoder.inverse_transform(
            [predicted_index]
        )[0]

        p_normal = float(
            probabilities[self.normal_index]
        )

        threat_score = 1.0 - p_normal

        class_probabilities = {
            str(label): float(probability)
            for label, probability in zip(
                self.encoder.classes_,
                probabilities
            )
        }

        return {
            "predicted_class": str(predicted_class),
            "p_normal": p_normal,
            "threat_score": threat_score,
            "probabilities": class_probabilities,
        }
