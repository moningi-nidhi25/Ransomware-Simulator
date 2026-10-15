from database import init_db, insert_alert, get_alert, list_alerts, update_alert_status, get_settings, save_settings

def test_phase3_database_operations():
    init_db()
    alert_id = insert_alert(
        "test", "Low", "test alert", files_affected=1,
        risk_score=5, reasons=["test reason"], source="simulation"
    )
    alert = get_alert(alert_id)
    assert alert["id"] == alert_id
    assert alert["reasons"] == ["test reason"]
    assert update_alert_status(alert_id, "resolved") is True
    assert get_alert(alert_id)["status"] == "resolved"

def test_settings_round_trip():
    init_db()
    original = get_settings()
    changed = dict(original)
    changed["event_window"] = 11
    save_settings(changed)
    assert get_settings()["event_window"] == 11
    save_settings(original)
