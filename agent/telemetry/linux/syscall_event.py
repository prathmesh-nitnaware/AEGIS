from dataclasses import dataclass
from typing import Optional


@dataclass
class SyscallEvent:
    """
    One raw syscall observation captured from the Linux system.

    The syscall_id is the important field for the current
    Linux ML model.

    The remaining fields provide context for the EDR and
    future correlation/voting layers.
    """

    timestamp: float
    pid: int
    uid: Optional[int]
    syscall_id: int
    process_name: Optional[str] = None
    ppid: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "pid": self.pid,
            "uid": self.uid,
            "syscall_id": self.syscall_id,
            "process_name": self.process_name,
            "ppid": self.ppid,
        }