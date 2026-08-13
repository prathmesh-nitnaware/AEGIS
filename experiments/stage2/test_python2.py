import os
import subprocess
import time

print(f"Test process PID: {os.getpid()}", flush=True)

input("Press Enter to start generating telemetry...")

for _ in range(200):
    os.listdir("/tmp")
    os.stat("/etc/hostname")

    with open("/etc/hostname", "r") as f:
        f.read()

    subprocess.run(
        ["echo", "AEGIS"],
        stdout=subprocess.DEVNULL
    )

    time.sleep(0.1)

time.sleep(20)

print("Test process finished.")
