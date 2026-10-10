
from eventprocessor import EventProcessor


def test_normal_activity():
    processor = EventProcessor(window_seconds=10)

    result = processor.process_event(
        "modified", "safe_test_folder/sample.txt"
    )

    assert result["event_type"] == "modified"
    assert result["activity"]["modifications"] == 1
    assert result["should_alert"] is False


def test_unsupported_event():
    processor = EventProcessor()

    try:
        processor.process_event("unknown")
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_rolling_window():
    processor = EventProcessor(window_seconds=10)

    processor.process_event("renamed", "sample.txt")
    result = processor.process_event("deleted", "sample.txt")

    assert result["activity"]["renames"] == 1
    assert result["activity"]["deletions"] == 1
