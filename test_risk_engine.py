from risk.zero_trust_engine import explain_risk

# Simulate a HIGH-RISK admin action from bad geo and untrusted device
high_risk_event = {
    "device_trust": 18,        # Untrusted / unknown device
    "geo_trust": 15,           # Suspicious country / impossible travel
    "role_sensitivity": 20,    # Admin role
    "anomaly_score": 15,       # Behavior looks weird
    "token_score": 10          # Token reused / no MFA
}

# Simulate a LOW-RISK normal user action
low_risk_event = {
    "device_trust": 2,         # Known device
    "geo_trust": 2,            # Normal location
    "role_sensitivity": 5,     # Normal user
    "anomaly_score": 0,        # No anomaly
    "token_score": 0           # Secure token
}

print("=== HIGH RISK EVENT ===")
explain_risk(high_risk_event)

print("\n=== LOW RISK EVENT ===")
explain_risk(low_risk_event)
