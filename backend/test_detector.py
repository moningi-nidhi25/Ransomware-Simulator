
from detector import calculate_risk


def test_normal_activity():
    result = calculate_risk(modifications=2)
    assert result["severity"] == "Low"


def test_high_modification_rate():
    result = calculate_risk(modifications=25)
    assert result["severity"] == "High"


def test_multiple_signals():
    result = calculate_risk(
        modifications=25,
        renames=12,
        deletions=12,
    )
    assert result["risk_score"] == 100
    assert result["severity"] == "High"
