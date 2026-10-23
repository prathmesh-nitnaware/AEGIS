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

    # Modern Linux x86_64 -> Legacy x86 ADFA-LD training syscall mapping
    SYSCALL_COMPAT_MAP = {
        257: 2,   # openat -> open
        262: 5,   # newfstatat -> fstat
        318: 0,   # getrandom -> read
        332: 5,   # statx -> fstat
        293: 136, # pipe2 -> pipe
    }

    BENIGN_LINUX_PROCESSES = {
        "grep", "zsh", "bash", "sh", "sudo", "ip", "ls", "cat", "ps", "top", "htop",
        "command-not-found", "command-not-fou", "xfce4-panel", "xfce4-panel-gen",
        "xfwm4", "xorg", "qterminal", "python", "python3", "node", "git",
        "systemd", "dbus-daemon", "pulseaudio", "pipewire", "lightdm", "polkitd",
        "tumblerd", "gvfsd", "vmtoolsd", "wrapper-2.0", "whoami", "uname", "awk", "sed"
    }

    def predict(self, syscall_sequence, process_name=None):

        if len(syscall_sequence) != self.WINDOW_SIZE:
            raise ValueError(
                f"Expected {self.WINDOW_SIZE} syscall IDs, "
                f"got {len(syscall_sequence)}"
            )

        # 1. Check if process is a recognized benign shell, desktop, or kernel worker
        if process_name:
            proc_clean = str(process_name).strip().lower()
            is_kernel_worker = proc_clean.startswith("kworker") or proc_clean.startswith("rcu") or "ionclean" in proc_clean or proc_clean.startswith("ksoftirqd")
            is_benign_util = any(proc_clean == b or proc_clean.startswith(b) for b in self.BENIGN_LINUX_PROCESSES)

            if is_kernel_worker or is_benign_util:
                return {
                    "predicted_class": "Normal",
                    "p_normal": 0.95,
                    "threat_score": 0.05,
                    "probabilities": {c: (0.95 if c == "Normal" else 0.05 / (len(self.encoder.classes_) - 1)) for c in self.encoder.classes_},
                }

        # 2. Translate modern x86_64 syscalls to training baseline equivalents
        translated = [self.SYSCALL_COMPAT_MAP.get(int(s), int(s)) for s in syscall_sequence]

        X = np.asarray(
            translated,
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

