
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import random

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="RansomShield API")

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
        count = random.randint(1, 3)
        severity = "Low"
        message = "Normal activity pattern"
    else:
        count = random.randint(25, 40)
        severity = "High"
        message = (
            "Rapid file-modification pattern detected. "
            "Potential ransomware-like behavior."
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
