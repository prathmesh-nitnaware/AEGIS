from pydantic import BaseModel


class TelemetryEvent(BaseModel):
    timestamp: int
    pid: int
    uid: int
    syscall_id: int
    process: str


class ModelResult(BaseModel):
    timestamp: int
    pid: int
    uid: int
    process: str
    window_size: int

    predicted_class: str
    p_normal: float
    threat_score: float

    probabilities: dict[str, float]
