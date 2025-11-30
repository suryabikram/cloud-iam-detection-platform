from detections.alert import alert

# 1. Privilege Escalation - PassRole to Admin
def detect_passrole_admin(event):
    if event["eventName"] == "PassRole" and event.get("roleArn") and "Admin" in event["roleArn"]:
        alert("Possible privilege escalation via PassRole", event)


# 2. Unauthorized AssumeRole
def detect_unauthorized_assumerole(event):
    if event["eventName"] == "AssumeRole" and event.get("user") != "intended_user":
        alert("Unauthorized role assumption attempt", event)


def run_iam_detections(event):
    detect_passrole_admin(event)
    detect_unauthorized_assumerole(event)
