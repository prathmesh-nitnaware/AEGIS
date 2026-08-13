import os
import time

print(f"Test process PID: {os.getpid()}", flush=True)

input("Press Enter to start generating telemetry...")

for _ in range(200):
    os.getpid()
    os.getuid()
    time.sleep(0.1)

time.sleep(20)

print("Test process finished.")
