"""
Zero Trust Risk Scoring Engine
Score range: 0–100

Factors (0–20 each):
- device_trust
- geo_trust
- role_sensitivity
- anomaly_score
- token_score
"""

def calculate_risk_score(event: dict) -> int:
    """Calculate overall risk score from event attributes."""

    device_trust = event.get("device_trust", 0)
    geo_trust = event.get("geo_trust", 0)
    role_sensitivity = event.get("role_sensitivity", 0)
    anomaly_score = event.get("anomaly_score", 0)
    token_score = event.get("token_score", 0)

    total = device_trust + geo_trust + role_sensitivity + anomaly_score + token_score

    # Clamp to [0, 100]
    if total < 0:
        total = 0
    if total > 100:
        total = 100

    return total


def risk_decision(score: int) -> str:
    """
    Map score to action:
    80+   -> BLOCK
    60-79 -> MFA
    <60   -> ALLOW
    """
    if score >= 80:
        return "BLOCK"
    elif score >= 60:
        return "MFA"
    else:
        return "ALLOW"


def explain_risk(event: dict) -> None:
    """Print a simple explanation of the risk score + decision (for logs/demo)."""

    score = calculate_risk_score(event)
    decision = risk_decision(score)

    print("\n[ZERO TRUST]")
    print(f"  Device trust:        {event.get('device_trust', 0)} / 20")
    print(f"  Geo trust:           {event.get('geo_trust', 0)} / 20")
    print(f"  Role sensitivity:    {event.get('role_sensitivity', 0)} / 20")
    print(f"  Anomaly score:       {event.get('anomaly_score', 0)} / 20")
    print(f"  Token score:         {event.get('token_score', 0)} / 20")
    print(f"  --> TOTAL RISK SCORE: {score} / 100")
    print(f"  --> DECISION: {decision}")
