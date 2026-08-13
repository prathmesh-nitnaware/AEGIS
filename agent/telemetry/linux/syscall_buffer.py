from collections import defaultdict, deque
from typing import Dict, List


class SyscallSequenceBuffer:
    """
    Maintains syscall sequences independently for each process.

    This is a Stage 1 experimental design. It does NOT yet
    establish the final AEGIS production windowing strategy.
    """

    def __init__(self, max_length: int = 500):
        self.max_length = max_length
        self._buffers: Dict[int, deque] = defaultdict(
            lambda: deque(maxlen=max_length)
        )

    def add(self, pid: int, syscall_id: int) -> None:
        self._buffers[pid].append(int(syscall_id))

    def get_sequence(self, pid: int) -> List[int]:
        return list(self._buffers.get(pid, []))

    def get_padded_sequence(self, pid: int) -> List[int]:
        """
        Return exactly max_length integers.

        Short sequences are right-padded with 0.
        Long sequences are already limited by deque(maxlen=500).
        """
        sequence = self.get_sequence(pid)

        if len(sequence) < self.max_length:
            sequence = sequence + [0] * (
                self.max_length - len(sequence)
            )

        return sequence[:self.max_length]

    def clear(self, pid: int) -> None:
        self._buffers.pop(pid, None)

    def active_pids(self) -> List[int]:
        return list(self._buffers.keys())