
# backend/monitor.py

from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class SafeFolderHandler(FileSystemEventHandler):
    """Forward file activity from the designated test folder."""

    def __init__(self, process_event):
        self.process_event = process_event

    def on_modified(self, event):
        if not event.is_directory:
            self.process_event("modified", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.process_event("created", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.process_event("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.process_event("renamed", event.dest_path)


def start_monitor(test_folder, process_event):
    """Start one observer for the explicitly designated test folder."""

    folder = Path(test_folder).resolve()

    if not folder.exists() or not folder.is_dir():
        raise ValueError(
            f"Test folder does not exist or is not a directory: {folder}"
        )

    observer = Observer()
    handler = SafeFolderHandler(process_event)

    observer.schedule(handler, str(folder), recursive=True)
    observer.start()

    return observer
