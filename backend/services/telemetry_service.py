from collections import deque
from typing import Any


MAX_EVENTS = 2000

events = deque(maxlen=MAX_EVENTS)
model_results = deque(maxlen=200)


def add_event(event: dict[str, Any]):
    events.append(event)


def add_model_result(result: dict[str, Any]):
    model_results.append(result)


def get_events():
    return list(events)


def get_model_results():
    return list(model_results)


def get_stats():
    processes = {
        event["pid"]
        for event in events
    }

    return {
        "events": len(events),
        "active_processes": len(processes),
        "model_results": len(model_results),
    }
