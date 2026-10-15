"""Rule-based risk scoring for ransomware-like file activity."""
def calculate_risk(
    modifications=0,
    renames=0,
    deletions=0,
    modification_threshold=20,
    rename_threshold=10,
    deletion_threshold=10,
):
    if modification_threshold is None:
        modification_threshold = 20
    if rename_threshold is None:
        rename_threshold = 10
    if deletion_threshold is None:
        deletion_threshold = 10

    score = 0
    reasons = []
    if modifications >= modification_threshold:
        score += 30
        reasons.append("High modification rate")
    if renames >= rename_threshold:
        score += 25
        reasons.append("Unusually high rename rate")
    if deletions >= deletion_threshold:
        score += 25
        reasons.append("Unusually high deletion rate")
    if len(reasons) >= 2:
        score += 20
        reasons.append("Multiple suspicious signals")
    score = min(score, 100)
    # Preserve the severity rules expected by the existing Phase 1/2 tests.
    if score >= 30:
        severity = "High"
    elif score >= 15:
        severity = "Medium"
    else:
        severity = "Low"
    return {"risk_score": score, "severity": severity, "reasons": reasons}
