from agent.linux_model_adapter import LinuxModelAdapter


INPUT = "stage2/experiments/stage2_python3_500.txt"


def main():

    with open(INPUT, "r") as f:
        sequence = [
            int(line.strip())
            for line in f
            if line.strip()
        ]

    print(f"Loaded syscall values: {len(sequence)}")

    model = LinuxModelAdapter()

    result = model.predict(sequence)

    print("\n========== LINUX MODEL ==========")
    print(f"Predicted class : {result['predicted_class']}")
    print(f"P(Normal)       : {result['p_normal']:.6f}")
    print(f"Threat score    : {result['threat_score']:.6f}")

    print("\nClass probabilities:")

    for label, probability in result["probabilities"].items():
        print(f"{label:<20} {probability:.6f}")


if __name__ == "__main__":
    main()
