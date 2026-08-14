def serialize_prediction(
    timestamp,
    pid,
    uid,
    process,
    syscall,
    window_size,
    predicted_class,
    normal_probability,
    threat_score,
    probabilities=None,
):

    return {
        "timestamp": int(timestamp),
        "pid": int(pid),
        "uid": int(uid),
        "process": str(process),
        "syscall": int(syscall),
        "window_size": int(window_size),
        "predicted_class": str(predicted_class),
        "normal_probability": float(normal_probability),
        "threat_score": float(threat_score),
        "probabilities": probabilities or {},
    }
