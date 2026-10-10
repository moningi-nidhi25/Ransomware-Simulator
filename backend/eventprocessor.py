
from collections import deque
from threading import Lock
from time import monotonic

from detector import calculate_risk


class EventProcessor:
    """
    Processes file activity within a rolling time window
    and calculates ransomware risk using detector.py.
    """

    def __init__(self, window_seconds=10):
        self.window_seconds = window_seconds
        self.events = deque()
        self.lock = Lock()

    def process_event(self, event_type, path=None):
        """
        Supported event types:
        modified, renamed, deleted, created

        Returns activity counts and the detection result.
        """
        event_type = event_type.lower().strip()

        supported_events = {
            "modified",
            "renamed",
            "deleted",
            "created",
        }

        if event_type not in supported_events:
            raise ValueError(
                f"Unsupported event type: {event_type}"
            )

        current_time = monotonic()

        with self.lock:
            # Record the new event.
            self.events.append((current_time, event_type))

            # Remove events outside the rolling time window.
            cutoff = current_time - self.window_seconds

            while self.events and self.events[0][0] < cutoff:
                self.events.popleft()

            # Count activity in the current window.
            modifications = sum(
                1 for _, event in self.events
                if event == "modified"
            )

            renames = sum(
                1 for _, event in self.events
                if event == "renamed"
            )

            deletions = sum(
                1 for _, event in self.events
                if event == "deleted"
            )

            # Use the existing rule-based detection engine.
            detection = calculate_risk(
                modifications=modifications,
                renames=renames,
                deletions=deletions,
            )

            return {
                "event_type": event_type,
                "path": path,
                "window_seconds": self.window_seconds,
                "activity": {
                    "modifications": modifications,
                    "renames": renames,
                    "deletions": deletions,
                },
                "risk_score": detection["risk_score"],
                "severity": detection["severity"],
                "reasons": detection["reasons"],
                "should_alert": (
                    detection["severity"] in ("Medium", "High")
                ),
            }


# Shared processor instance for the file monitor.
event_processor = EventProcessor(window_seconds=10)
