"""Aggregate recent file events and score suspicious patterns."""
from collections import deque
from threading import Lock
from time import monotonic
from detector import calculate_risk
from database import get_settings

class EventProcessor:
    def __init__(self, window_seconds=10):
        self.window_seconds = window_seconds
        self.events = deque()
        self.lock = Lock()

    def reset(self):
        with self.lock:
            self.events.clear()

    def process_event(self, event_type, path=None, settings_override=None):
        event_type = event_type.lower().strip()
        if event_type not in {"modified", "renamed", "deleted", "created"}:
            raise ValueError(f"Unsupported event type: {event_type}")

        settings = settings_override if settings_override is not None else get_settings()
        window = int(settings.get("event_window", self.window_seconds))
        now = monotonic()
        with self.lock:
            self.events.append((now, event_type))
            cutoff = now - window
            while self.events and self.events[0][0] < cutoff:
                self.events.popleft()
            counts = {
                "modifications": sum(1 for _, event in self.events if event == "modified"),
                "renames": sum(1 for _, event in self.events if event == "renamed"),
                "deletions": sum(1 for _, event in self.events if event == "deleted"),
            }
            detection = calculate_risk(
                modifications=counts["modifications"],
                renames=counts["renames"],
                deletions=counts["deletions"],
                modification_threshold=int(settings.get("modification_threshold", 20)),
                rename_threshold=int(settings.get("rename_threshold", 10)),
                deletion_threshold=int(settings.get("deletion_threshold", 10)),
            )
            return {
                "event_type": event_type,
                "path": path,
                "window_seconds": window,
                "activity": counts,
                **detection,
                "should_alert": detection["severity"] in ("Medium", "High"),
            }

event_processor = EventProcessor(window_seconds=10)
