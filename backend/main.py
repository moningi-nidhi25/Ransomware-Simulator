"""RansomShield Phase 3 API. Monitoring is opt-in and restricted to backend/test_data."""
import csv
import io
import os
import random
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, ConfigDict

from database import (
    init_db, insert_alert, insert_event, list_alerts, get_alert,
    update_alert_status, list_events, get_stats, get_settings, save_settings,
)
from detector import calculate_risk
from eventprocessor import event_processor
from monitor import start_monitor

SAFE_FOLDER = Path(__file__).resolve().parent / "test_data"
SAFE_FOLDER.mkdir(exist_ok=True)
observer = None

def handle_file_event(event_type, absolute_path):
    """Persist activity only when the event originates in the dedicated test_data folder."""
    try:
        path = Path(absolute_path).resolve()
        relative_path = path.relative_to(SAFE_FOLDER.resolve())
    except (ValueError, OSError):
        return

    result = event_processor.process_event(event_type, str(relative_path))
    insert_event(event_type, str(relative_path), result["risk_score"],
                 result["severity"], result["reasons"])
    if result["should_alert"]:
        insert_alert(
            scenario="file_monitor",
            severity=result["severity"],
            message=", ".join(result["reasons"]) or "Suspicious file activity detected",
            files_affected=1,
            risk_score=result["risk_score"],
            reasons=result["reasons"],
            source="file_monitor",
        )
    print(f"[MONITOR] {event_type.upper()} | {relative_path} | risk={result['risk_score']} | {result['severity']}")

@asynccontextmanager
async def lifespan(app):
    global observer
    init_db()
    # To opt in: set ENABLE_FILE_MONITOR=1. Only backend/test_data is watched.
    if os.getenv("ENABLE_FILE_MONITOR", "0") == "1":
        observer = start_monitor(SAFE_FOLDER, handle_file_event)
    try:
        yield
    finally:
        if observer is not None:
            observer.stop()
            observer.join(timeout=5)
            observer = None

app = FastAPI(title="RansomShield API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class StatusUpdate(BaseModel):
    status: str

class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_window: int = Field(ge=1, le=300, description="Sliding event window in seconds (1-300)")
    modification_threshold: int = Field(ge=1, le=10000, description="Modification threshold (1-10000)")
    rename_threshold: int = Field(ge=1, le=10000, description="Rename threshold (1-10000)")
    deletion_threshold: int = Field(ge=1, le=10000, description="Deletion threshold (1-10000)")

@app.get("/")
def home():
    return {"message": "RansomShield is running", "docs": "/docs"}

@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.get("/api/alerts")
def get_alerts(
    severity: str | None = None,
    source: str | None = None,
    status: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    limit: int = Query(100, ge=1, le=500),
):
    return list_alerts(severity, source, status, start_date, end_date, limit)

@app.get("/api/alerts/{alert_id}")
def alert_detail(alert_id: int):
    alert = get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@app.patch("/api/alerts/{alert_id}/status")
def set_alert_status(alert_id: int, body: StatusUpdate):
    if body.status not in {"open", "investigating", "resolved"}:
        raise HTTPException(status_code=400, detail="Status must be open, investigating, or resolved")
    if not update_alert_status(alert_id, body.status):
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"ok": True, "id": alert_id, "status": body.status}

@app.get("/api/events")
def get_events(event_type: str | None = None, limit: int = Query(200, ge=1, le=1000)):
    return list_events(event_type, limit)

@app.get("/api/stats")
def stats():
    return get_stats()

@app.get("/api/settings")
def settings():
    return get_settings()

@app.put("/api/settings")
def update_settings(body: SettingsUpdate):
    save_settings(body.model_dump())
    return get_settings()

@app.post("/api/simulate/{scenario}")
def simulate(
    scenario: str,
    modifications: int | None = None,
    renames: int | None = None,
    deletions: int | None = None,
):
    """Generate synthetic records only; no real files are read, changed, or deleted."""
    from datetime import datetime, timezone
    settings = get_settings()
    if scenario == "normal":
        counts = {
            "modifications": modifications if modifications is not None else 2,
            "renames": renames if renames is not None else 0,
            "deletions": deletions if deletions is not None else 0,
        }
    elif scenario == "suspicious":
        # A synthetic suspicious burst: 15 modifications, 12 renames, 12 deletions
        # (or custom counts if specified).
        # Under default thresholds (20, 10, 10), renames and deletions trigger High severity (risk score 70),
        # while modifications (15 < 20) are below threshold.
        # Lowering modification_threshold to 15 or below triggers "High modification rate"
        # and elevates risk score to 100 with all reasons triggered.
        counts = {
            "modifications": modifications if modifications is not None else 15,
            "renames": renames if renames is not None else 12,
            "deletions": deletions if deletions is not None else 12,
        }
    else:
        raise HTTPException(status_code=400, detail="Choose 'normal' or 'suspicious'")

    result = calculate_risk(
        **counts,
        modification_threshold=settings["modification_threshold"],
        rename_threshold=settings["rename_threshold"],
        deletion_threshold=settings["deletion_threshold"],
    )
    message = ", ".join(result["reasons"]) if result["reasons"] else "No suspicious pattern detected"
    alert_id = insert_alert(
        scenario, result["severity"], message,
        files_affected=sum(counts.values()),
        risk_score=result["risk_score"], reasons=result["reasons"],
        source="simulation",
    )
    return {
        "id": alert_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scenario": scenario,
        **result,
        "message": message,
        "files_affected": sum(counts.values()),
    }

@app.get("/api/reports/export")
def export_report():
    records = list_alerts(limit=500)
    output = io.StringIO()
    fields = ["id", "timestamp", "scenario", "severity", "risk_score", "message",
              "files_affected", "source", "status", "reasons"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for row in records:
        row["reasons"] = "; ".join(row.get("reasons") or [])
        writer.writerow({field: row.get(field, "") for field in fields})
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ransomshield-alerts.csv"},
    )
