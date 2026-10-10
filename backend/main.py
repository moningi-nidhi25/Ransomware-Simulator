
from contextlib import asynccontextmanager
from eventprocessor import event_processor
from monitor import start_monitor
from datetime import datetime, timezone
from pathlib import Path
from detector import calculate_risk
import sqlite3
import random

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# The test folder is located at the project root.
TEST_FOLDER = Path(__file__).resolve().parent.parent / "safe_test_folder"


def handle_file_event(event_type, path):
    result = event_processor.process_event(event_type, path)

    print(
        f"[MONITOR] {event_type.upper()} | "
        f"File: {path} | "
        f"Risk: {result['risk_score']} | "
        f"Severity: {result['severity']}"
    )

    if result["reasons"]:
        print("Reasons:", ", ".join(result["reasons"]))


@asynccontextmanager
async def lifespan(app):
    observer = start_monitor(
        TEST_FOLDER,
        handle_file_event,
    )
    app.state.observer = observer

    try:
        yield
    finally:
        observer.stop()
        observer.join(timeout=5)


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = Path(__file__).with_name("alerts.db")


def connect_db():
    return sqlite3.connect(DB_PATH)


def setup_db():
    with connect_db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                scenario TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                files_affected INTEGER NOT NULL
            )
        """)


setup_db()


@app.get("/")
def home():
    return {"message": "RansomShield is running"}


@app.get("/api/alerts")
def get_alerts():
    with connect_db() as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT * FROM alerts ORDER BY id DESC"
        ).fetchall()
        return [dict(row) for row in rows]


@app.post("/api/simulate/{scenario}")
def simulate(scenario: str):
    if scenario not in ("normal", "suspicious"):
        return {"error": "Choose normal or suspicious"}

    # Synthetic events only; no real file operations.
    
    if scenario == "normal":
        modifications = random.randint(1, 3)
        renames = 0
        deletions = 0
    else:
        modifications = random.randint(25, 40)
        renames = random.randint(10, 15)
        deletions = random.randint(10, 15)

    detection = calculate_risk(
        modifications=modifications,
        renames=renames,
        deletions=deletions,
    )

    severity = detection["severity"]
    risk_score = detection["risk_score"]
    reasons = detection["reasons"]

    message = (
        ", ".join(reasons)
        if reasons
        else "No suspicious pattern detected"
    )
    timestamp = datetime.now(timezone.utc).isoformat()

    with connect_db() as con:
        con.execute(
            """INSERT INTO alerts
            (timestamp, scenario, severity, message, files_affected)
            VALUES (?, ?, ?, ?, ?)""",
            (timestamp, scenario, severity, message, count),
        )

    return {
        "timestamp": timestamp,
        "scenario": scenario,
        "severity": severity,
        "message": message,
        "files_affected": count,
    }
