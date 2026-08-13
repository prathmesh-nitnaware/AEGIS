import os
import time

print(f"Test process PID: {os.getpid()}", flush=True)

input("Press Enter to start generating telemetry...")

TEST_FILE = "/tmp/aegis_test_file.txt"

for _ in range(200):
    with open(TEST_FILE, "w") as f:
        f.write("AEGIS normal telemetry test\n")

    with open(TEST_FILE, "r") as f:
        f.read()

    os.stat(TEST_FILE)

    time.sleep(0.1)

try:
    os.remove(TEST_FILE)
except FileNotFoundError:
    pass

time.sleep(20)

print("Test process finished.")