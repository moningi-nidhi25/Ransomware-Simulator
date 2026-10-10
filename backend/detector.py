
def calculate_risk(
    modifications=0,
    renames=0,
    deletions=0,
):
    score = 0
    reasons = []

    if modifications >= 20:
        score += 30
        reasons.append("High modification rate")

    if renames >= 10:
        score += 25
        reasons.append("Unusually high rename rate")

    if deletions >= 10:
        score += 25
        reasons.append("Unusually high deletion rate")

    # Multiple signals increase concern.
    if len(reasons) >= 2:
        score += 20
        reasons.append("Multiple suspicious signals")

    score = min(score, 100)

    if score >= 30:
        severity = "High"
    elif score >= 15:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "risk_score": score,
        "severity": severity,
        "reasons": reasons,
    }
