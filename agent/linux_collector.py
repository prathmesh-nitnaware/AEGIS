import os
import subprocess
import sys
from collections import defaultdict, deque

from agent.linux_model_adapter import LinuxModelAdapter


WINDOW_SIZE = 500


class LinuxTelemetryCollector:

    def __init__(self):

        # Existing trained Linux model
        self.model = LinuxModelAdapter()

        # Separate syscall buffer for every PID
        self.buffers = defaultdict(
            lambda: deque(maxlen=WINDOW_SIZE)
        )

        # Basic process information
        self.process_names = {}

    def process_event(self, line):
        """
        Expected input:

        timestamp|pid|uid|syscall_id|process

        Example:

        5262240157246|21734|1000|257|python
        """

        line = line.strip()

        if not line:
            return

        parts = line.split("|")

        if len(parts) != 5:
            return

        timestamp, pid, uid, syscall_id, process = parts

        try:
            timestamp = int(timestamp)
            pid = int(pid)
            uid = int(uid)
            syscall_id = int(syscall_id)

        except ValueError:
            return

        # Store process name
        self.process_names[pid] = process

        # Get this PID's buffer
        buffer = self.buffers[pid]

        # Add syscall ID
        buffer.append(syscall_id)

        # When 500 syscalls are collected,
        # send exactly those 500 values to the model.
        if len(buffer) == WINDOW_SIZE:

            sequence = list(buffer)

            self.run_inference(
                timestamp=timestamp,
                pid=pid,
                uid=uid,
                process=process,
                sequence=sequence,
            )

            # Start next window
            buffer.clear()

    def run_inference(
        self,
        timestamp,
        pid,
        uid,
        process,
        sequence,
    ):
        """
        Run the existing Linux XGBoost model.
        """

        try:

            result = self.model.predict(sequence)

            print()
            print("========================================")
            print("AEGIS LINUX TELEMETRY")
            print("========================================")

            print(f"Timestamp       : {timestamp}")
            print(f"PID             : {pid}")
            print(f"UID             : {uid}")
            print(f"Process         : {process}")
            print(f"Window size     : {len(sequence)}")

            print()
            print("## Prediction")
            print()

            print(
                f"Predicted class : "
                f"{result['predicted_class']}"
            )

            print(
                f"P(Normal)       : "
                f"{result['p_normal']:.6f}"
            )

            print(
                f"Threat score    : "
                f"{result['threat_score']:.6f}"
            )

            print()
            print("Class probabilities")
            print("----------------------------------------")

            for label, probability in result[
                "probabilities"
            ].items():

                print(
                    f"{label:<20} "
                    f"{probability:.6f}"
                )

            print("========================================")
            print()

        except Exception as e:

            print(
                f"[AEGIS ERROR] Model inference failed: {e}",
                file=sys.stderr,
            )

    def start(self):
        """
        Start live Linux syscall telemetry.

        Excluded:
            bpftrace
            AEGIS collector itself

        Everything else remains eligible for monitoring.
        """

        # PID of this Python collector
        collector_pid = os.getpid()

        # bpftrace program
        #
        # pid != collector_pid
        #     -> don't capture AEGIS collector
        #
        # comm != "bpftrace"
        #     -> don't capture bpftrace itself
        #
        bpftrace_program = f'''
tracepoint:raw_syscalls:sys_enter
/ pid != {collector_pid} && comm != "bpftrace" /
{{
    printf("%llu|%d|%d|%d|%s\\n",
           nsecs,
           pid,
           uid,
           args->id,
           comm);
}}
'''

        print()
        print("========================================")
        print("AEGIS LINUX LIVE TELEMETRY COLLECTOR")
        print("========================================")

        print(f"Collector PID   : {collector_pid}")
        print(f"Window size     : {WINDOW_SIZE}")

        print()
        print("Excluded:")
        print("  [X] bpftrace")
        print(f"  [X] AEGIS collector PID {collector_pid}")

        print()
        print("Included:")
        print("  [✓] sudo")
        print("  [✓] bash")
        print("  [✓] python")
        print("  [✓] ssh")
        print("  [✓] child processes")
        print("  [✓] other Linux processes")

        print()
        print("Starting bpftrace...")
        print("Waiting for live syscall telemetry...")
        print()

        try:

            process = subprocess.Popen(
                [
                    "sudo",
                    "bpftrace",
                    "-e",
                    bpftrace_program,
                ],
                stdout=subprocess.PIPE,
                stderr=sys.stderr,
                text=True,
                bufsize=1,
            )

        except Exception as e:

            print(
                f"[AEGIS ERROR] Failed to start bpftrace: {e}",
                file=sys.stderr,
            )

            return

        try:

            for line in process.stdout:

                self.process_event(line)

        except KeyboardInterrupt:

            print()
            print("[AEGIS] Stopping collector...")

        finally:

            try:

                process.terminate()
                process.wait(timeout=3)

            except subprocess.TimeoutExpired:

                process.kill()

            except Exception:

                pass

            print("[AEGIS] Collector stopped.")


if __name__ == "__main__":

    collector = LinuxTelemetryCollector()

    collector.start()