import json

def parse_cloudtrail_event(event_json):
    """
    Takes raw CloudTrail JSON and normalizes it.
    Returns a clean event dictionary used by detection rules.
    """

    event = {
        "eventName": event_json.get("eventName"),
        "eventTime": event_json.get("eventTime"),
        "sourceIPAddress": event_json.get("sourceIPAddress"),
        "userAgent": event_json.get("userAgent"),
        "awsRegion": event_json.get("awsRegion"),

        # User Identity Fields
        "user": event_json.get("userIdentity", {}).get("userName"),
        "userType": event_json.get("userIdentity", {}).get("type"),
        "userArn": event_json.get("userIdentity", {}).get("arn"),

        # Additional info useful for detections
        "roleArn": event_json.get("requestParameters", {}).get("roleArn"),
        "accessKeyId": event_json.get("userIdentity", {}).get("accessKeyId"),
        "sessionContext": event_json.get("userIdentity", {}).get("sessionContext", {}),

        "device_trust": event_json.get("device_trust", 0),
        "geo_trust": event_json.get("geo_trust", 0),
        "role_sensitivity": event_json.get("role_sensitivity", 0),
        "anomaly_score": event_json.get("anomaly_score", 0),
        "token_score": event_json.get("token_score", 0),

        # Raw event saved for debugging later
        "raw": event_json
    }

    return event


def load_event_from_file(path):
    """Reads a JSON file and returns the normalized parsed event."""
    with open(path, "r") as f:
        data = json.load(f)
    return parse_cloudtrail_event(data)


if __name__ == "__main__":
    test_event = load_event_from_file("sample_logs/passrole_event.json")
    print("Normalized Event:\n")
    print(test_event)
