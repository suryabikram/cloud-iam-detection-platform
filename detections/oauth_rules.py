from detections.alert import alert

# 6. Malicious OAuth app requesting Directory.ReadWrite.All
def detect_malicious_oauth_permission(event):
    if event["eventName"] == "OAuthConsent" and "Directory.ReadWrite.All" in event.get("permissions", []):
        alert("Potential malicious OAuth app registered", event)


def run_oauth_detections(event):
    detect_malicious_oauth_permission(event)

