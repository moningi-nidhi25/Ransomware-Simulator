"""Comprehensive tests for Phase 5: Configurable Detection Thresholds.

Tests cover:
1. Default settings initialization.
2. Saving and retrieving settings.
3. Persistence across backend restarts.
4. Validation and rejection of invalid settings (zero, negative, excessively large, extra keys, wrong types).
5. Dynamic detection behavior changes when thresholds are modified.
6. Synthetic simulation path using active saved configuration.
7. File-monitor event processor path using active saved configuration.
8. Full database isolation via temporary SQLite files to preserve project data.
"""
from pathlib import Path
import tempfile
import pytest
from fastapi.testclient import TestClient

from database import (
    DEFAULT_SETTINGS,
    get_db_path,
    get_settings,
    init_db,
    save_settings,
    set_db_path,
)
from detector import calculate_risk
from eventprocessor import event_processor
from main import app

@pytest.fixture(autouse=True)
def isolated_database():
    """Run every test in this module against a temporary SQLite database."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        temp_db_path = Path(tmp_dir) / "test_isolated_alerts.db"
        set_db_path(temp_db_path)
        init_db()
        event_processor.reset()
        try:
            yield temp_db_path
        finally:
            event_processor.reset()
            set_db_path(None)

@pytest.fixture
def client():
    return TestClient(app)

def test_default_settings_initialization():
    settings = get_settings()
    assert settings["event_window"] == 10
    assert settings["modification_threshold"] == 20
    assert settings["rename_threshold"] == 10
    assert settings["deletion_threshold"] == 10
    assert settings == DEFAULT_SETTINGS

def test_save_and_retrieve_settings():
    updated = {
        "event_window": 15,
        "modification_threshold": 30,
        "rename_threshold": 12,
        "deletion_threshold": 8,
    }
    save_settings(updated)
    current = get_settings()
    for key, val in updated.items():
        assert current[key] == val

def test_persistence_across_restarts(isolated_database):
    # Save custom settings
    custom = {
        "event_window": 25,
        "modification_threshold": 45,
        "rename_threshold": 18,
        "deletion_threshold": 14,
    }
    save_settings(custom)

    # Simulate restart by clearing and re-pointing to the same database file
    set_db_path(isolated_database)
    reloaded = get_settings()
    assert reloaded == custom

def test_api_get_settings(client):
    res = client.get("/api/settings")
    assert res.status_code == 200
    data = res.json()
    assert data["event_window"] == 10
    assert data["modification_threshold"] == 20

def test_api_put_valid_settings(client):
    new_settings = {
        "event_window": 30,
        "modification_threshold": 50,
        "rename_threshold": 20,
        "deletion_threshold": 15,
    }
    res = client.put("/api/settings", json=new_settings)
    assert res.status_code == 200
    data = res.json()
    assert data == new_settings
    assert get_settings() == new_settings

def test_api_reject_zero_values(client):
    invalid = {
        "event_window": 0,
        "modification_threshold": 20,
        "rename_threshold": 10,
        "deletion_threshold": 10,
    }
    res = client.put("/api/settings", json=invalid)
    assert res.status_code == 422

def test_api_reject_negative_values(client):
    invalid = {
        "event_window": 10,
        "modification_threshold": -5,
        "rename_threshold": 10,
        "deletion_threshold": 10,
    }
    res = client.put("/api/settings", json=invalid)
    assert res.status_code == 422

def test_api_reject_excessively_large_values(client):
    # event_window limit is 300
    res = client.put("/api/settings", json={
        "event_window": 500,
        "modification_threshold": 20,
        "rename_threshold": 10,
        "deletion_threshold": 10,
    })
    assert res.status_code == 422

    # threshold limit is 10000
    res2 = client.put("/api/settings", json={
        "event_window": 10,
        "modification_threshold": 20000,
        "rename_threshold": 10,
        "deletion_threshold": 10,
    })
    assert res2.status_code == 422

def test_api_reject_extra_fields(client):
    res = client.put("/api/settings", json={
        "event_window": 10,
        "modification_threshold": 20,
        "rename_threshold": 10,
        "deletion_threshold": 10,
        "unauthorized_field": "exploit",
    })
    assert res.status_code == 422

def test_api_reject_invalid_data_types(client):
    res = client.put("/api/settings", json={
        "event_window": "ten",
        "modification_threshold": 20,
        "rename_threshold": 10,
        "deletion_threshold": 10,
    })
    assert res.status_code == 422

def test_detection_behavior_changes_with_thresholds():
    # 15 modifications below default threshold (20)
    baseline = calculate_risk(modifications=15, modification_threshold=20)
    assert baseline["risk_score"] == 0
    assert baseline["severity"] == "Low"
    assert "High modification rate" not in baseline["reasons"]

    # 15 modifications above lower threshold (10)
    tuned = calculate_risk(modifications=15, modification_threshold=10)
    assert tuned["risk_score"] == 30
    assert tuned["severity"] == "High"
    assert "High modification rate" in tuned["reasons"]

def test_simulation_path_uses_saved_thresholds(client):
    # Under default thresholds (modification_threshold=20)
    res1 = client.post("/api/simulate/suspicious")
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["risk_score"] == 70
    assert "High modification rate" not in data1["reasons"]

    # Lower modification threshold to 10
    save_settings({
        "event_window": 10,
        "modification_threshold": 10,
        "rename_threshold": 10,
        "deletion_threshold": 10,
    })

    # Under lowered threshold, 15 modifications triggers "High modification rate"
    res2 = client.post("/api/simulate/suspicious")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["risk_score"] == 100
    assert "High modification rate" in data2["reasons"]

def test_file_monitor_path_uses_saved_thresholds():
    event_processor.reset()
    save_settings({
        "event_window": 10,
        "modification_threshold": 20,
        "rename_threshold": 10,
        "deletion_threshold": 10,
    })

    # Record 4 events: well below default threshold of 20
    for _ in range(4):
        res = event_processor.process_event("modified", "test_file.txt")
    assert res["should_alert"] is False
    assert res["severity"] == "Low"

    # Lower modification threshold to 4
    save_settings({
        "event_window": 10,
        "modification_threshold": 4,
        "rename_threshold": 10,
        "deletion_threshold": 10,
    })

    # Process next modification: now total modifications in window is 5 >= 4
    res_tuned = event_processor.process_event("modified", "test_file.txt")
    assert res_tuned["should_alert"] is True
    assert res_tuned["severity"] == "High"
    assert "High modification rate" in res_tuned["reasons"]
