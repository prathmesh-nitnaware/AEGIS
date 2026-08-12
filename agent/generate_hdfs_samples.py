"""
agent/generate_hdfs_samples.py
================================
Continuously appends varied, realistic HDFS log lines (each with a unique
block ID) to test.log every few seconds -- so HDFSLogCollector in run_all.py
gets multiple different blocks to score, instead of just one.

Run this in a SEPARATE terminal, alongside run_all.py running in another:

    python generate_hdfs_samples.py

Watch run_all.py's terminal -- you should see a new [hdfs] score line
every ~12 seconds.
"""
import random
import time
from pathlib import Path

LOG_PATH = Path(__file__).resolve().parent / "test.log"

# A mix of normal and anomaly-flavoured template lines so scores actually vary
NORMAL_TEMPLATES = [
    "081110 {t} INFO dfs.DataNode: Receiving block {blk} src: /10.0.0.{ip}:50010",
    "081110 {t} INFO dfs.DataNode: PacketResponder for block {blk} terminating",
    "081110 {t} INFO dfs.FSNamesystem: BLOCK* NameSystem.allocateBlock: {blk}",
]

ANOMALY_TEMPLATES = [
    "081110 {t} ERROR dfs.DataNode: Exception writing block {blk}: java.io.IOException",
    "081110 {t} WARN dfs.DataNode: Slow BlockReceiver write packet for block {blk} took 15000ms",
    "081110 {t} ERROR dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: block {blk} on unknown datanode",
]

block_counter = 1608999600000000000

def make_block_id():
    global block_counter
    block_counter += random.randint(1, 999)
    return f"blk_-{block_counter}"

def make_time():
    return f"{random.randint(10,23)}{random.randint(0,5)}{random.randint(0,5)}{random.randint(0,5)}{random.randint(0,5)}"

print(f"[generator] Writing varied HDFS samples to: {LOG_PATH}")
print("[generator] Keep run_all.py running in another terminal to see them scored.")
print("[generator] Press Ctrl+C to stop.\n")

try:
    while True:
        blk = make_block_id()
        is_anomaly = random.random() < 0.3  # 30% anomaly-flavoured
        templates = ANOMALY_TEMPLATES if is_anomaly else NORMAL_TEMPLATES

        with open(LOG_PATH, "a", encoding="utf-8") as f:
            # Write 2-3 lines for this block, then a terminal line to flush it
            for _ in range(random.randint(2, 3)):
                line = random.choice(templates).format(t=make_time(), blk=blk, ip=random.randint(1, 254))
                f.write(line + "\n")
            f.write(f"081110 {make_time()} INFO dfs.DataNode: PacketResponder for block {blk} terminating\n")

        label = "ANOMALY-flavoured" if is_anomaly else "normal"
        print(f"[generator] Wrote block {blk} ({label})")
        time.sleep(12)
except KeyboardInterrupt:
    print("\n[generator] Stopped.")