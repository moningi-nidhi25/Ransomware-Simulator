"""SQLite persistence and backward-compatible migration for RansomShield."""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "alerts.db"
_active_db_path = DB_PATH
DEFAULT_SETTINGS = {
    "event_window": 10,
    "modification_threshold": 20,
    "rename_threshold": 10,
    "deletion_threshold": 10,
}

def set_db_path(path=None):
    global _active_db_path
    if path is None:
        _active_db_path = DB_PATH
    else:
        _active_db_path = Path(path).resolve()

def get_db_path():
    return _active_db_path

@contextmanager
def get_connection():
    conn = sqlite3.connect(get_db_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    """Create new tables and add Phase 3 columns without dropping old data."""
    with get_connection() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                scenario TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                files_affected INTEGER NOT NULL DEFAULT 0
            )
        """)
        columns = {row["name"] for row in con.execute("PRAGMA table_info(alerts)").fetchall()}
        migrations = {
            "risk_score": "INTEGER NOT NULL DEFAULT 0",
            "reasons": "TEXT NOT NULL DEFAULT '[]'",
            "source": "TEXT NOT NULL DEFAULT 'simulation'",
            "status": "TEXT NOT NULL DEFAULT 'open'",
        }
        for column, definition in migrations.items():
            if column not in columns:
                con.execute(f"ALTER TABLE alerts ADD COLUMN {column} {definition}")
        con.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'file_monitor',
                risk_score INTEGER NOT NULL DEFAULT 0,
                severity TEXT NOT NULL DEFAULT 'Low',
                reasons TEXT NOT NULL DEFAULT '[]'
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            )
        """)
        for key, value in DEFAULT_SETTINGS.items():
            con.execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (key, value))

def decode_row(row):
    if row is None:
        return None
    item = dict(row)
    if "reasons" in item:
        try:
            item["reasons"] = json.loads(item["reasons"] or "[]")
        except (TypeError, json.JSONDecodeError):
            item["reasons"] = []
    return item

def insert_alert(scenario, severity, message, files_affected=0, risk_score=0, reasons=None, source="simulation"):
    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).isoformat()
    with get_connection() as con:
        cur = con.execute("""
            INSERT INTO alerts
              (timestamp, scenario, severity, message, files_affected, risk_score, reasons, source, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open')
        """, (timestamp, scenario, severity, message, int(files_affected), int(risk_score),
              json.dumps(reasons or []), source))
        return cur.lastrowid

def insert_event(event_type, relative_path, risk_score=0, severity="Low", reasons=None, source="file_monitor"):
    with get_connection() as con:
        cur = con.execute("""
            INSERT INTO events (event_type, relative_path, risk_score, severity, reasons, source)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (event_type, str(relative_path), int(risk_score), severity, json.dumps(reasons or []), source))
        return cur.lastrowid

def list_alerts(severity=None, source=None, status=None, start_date=None, end_date=None, limit=100):
    sql = "SELECT * FROM alerts WHERE 1=1"
    params = []
    for column, value in (("severity", severity), ("source", source), ("status", status)):
        if value:
            sql += f" AND {column} = ?"
            params.append(value)
    if start_date:
        sql += " AND date(timestamp) >= date(?)"
        params.append(start_date)
    if end_date:
        sql += " AND date(timestamp) <= date(?)"
        params.append(end_date)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_connection() as con:
        rows = con.execute(sql, params).fetchall()
    return [decode_row(row) for row in rows]

def get_alert(alert_id):
    with get_connection() as con:
        row = con.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return decode_row(row)

def update_alert_status(alert_id, status):
    with get_connection() as con:
        cur = con.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        return cur.rowcount > 0

def list_events(event_type=None, limit=200):
    sql = "SELECT * FROM events"
    params = []
    if event_type:
        sql += " WHERE event_type = ?"
        params.append(event_type)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_connection() as con:
        rows = con.execute(sql, params).fetchall()
    return [decode_row(row) for row in rows]

def get_settings():
    # Defaults allow unit tests and tools to run before the API initializes SQLite.
    try:
        with get_connection() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value INTEGER NOT NULL
                )
            """)
            rows = con.execute("SELECT key, value FROM settings").fetchall()
        settings = DEFAULT_SETTINGS.copy()
        settings.update({row["key"]: int(row["value"]) for row in rows})
        return settings
    except (sqlite3.OperationalError, sqlite3.DatabaseError):
        return DEFAULT_SETTINGS.copy()

def save_settings(settings):
    with get_connection() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            )
        """)
        for key, value in settings.items():
            con.execute("""
                INSERT INTO settings(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """, (key, int(value)))
    return get_settings()

def get_stats():
    with get_connection() as con:
        total = con.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
        unresolved = con.execute("SELECT COUNT(*) AS n FROM alerts WHERE status != 'resolved'").fetchone()["n"]
        high = con.execute("SELECT COUNT(*) AS n FROM alerts WHERE severity = 'High'").fetchone()["n"]
        avg = con.execute("SELECT COALESCE(AVG(risk_score), 0) AS n FROM alerts").fetchone()["n"]
        latest = con.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 1").fetchone()
        activity = con.execute("""
            SELECT strftime('%H:%M', timestamp) AS time, COUNT(*) AS count
            FROM events
            WHERE timestamp >= datetime('now', '-1 day')
            GROUP BY strftime('%Y-%m-%d %H:%M', timestamp)
            ORDER BY MIN(timestamp) DESC LIMIT 24
        """).fetchall()
    return {
        "total_alerts": total,
        "open_alerts": unresolved,
        "high_alerts": high,
        "average_risk": round(float(avg), 1),
        "latest_alert": decode_row(latest),
        "activity": [{"time": row["time"], "count": row["count"]} for row in reversed(activity)],
    }
