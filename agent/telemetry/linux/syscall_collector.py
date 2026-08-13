import subprocess
import time
from typing import Iterator

from .syscall_event import SyscallEvent


BPFTRACE_PROGRAM = r"""
tracepoint:raw_syscalls:sys_enter
{
    printf("%llu|%d|%d|%d|%s\n",
           nsecs,
           pid,
           uid,
           args->id,
           comm);
}
"""


class LinuxSyscallCollector:
    """
    Stage 1 Linux syscall collector.

    Uses bpftrace to observe Linux raw syscall entry events.

    Output format:
        timestamp_ns | pid | uid | syscall_id | process_name

    This collector is intentionally limited to Stage 1 validation.
    """

    def __init__(self):
        self.process = None

    def start(self) -> Iterator[SyscallEvent]:
        self.process = subprocess.Popen(
            ["sudo", "bpftrace", "-e", BPFTRACE_PROGRAM],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        assert self.process.stdout is not None

        for line in self.process.stdout:
            line = line.strip()

            if not line:
                continue

            event = self._parse_line(line)

            if event is not None:
                yield event

    def _parse_line(self, line: str):
        parts = line.split("|", 4)

        if len(parts) != 5:
            return None

        try:
            timestamp_ns = int(parts[0])
            pid = int(parts[1])
            uid = int(parts[2])
            syscall_id = int(parts[3])
            process_name = parts[4]

            return SyscallEvent(
                timestamp=timestamp_ns / 1_000_000_000,
                pid=pid,
                uid=uid,
                syscall_id=syscall_id,
                process_name=process_name,
            )

        except ValueError:
            return None

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=5)
            self.process = None