from response.response_manager import auto_respond

high_risk_event = {
    "user": "evil_user",
    "sourceIPAddress": "203.0.113.55",
    "accessKeyId": "AKIASTOLEN12345",

    "device_trust": 20,
    "geo_trust": 20,
    "role_sensitivity": 20,
    "anomaly_score": 20,
    "token_score": 20
}

print("=== Testing Response Automation ===")
auto_respond(high_risk_event)
