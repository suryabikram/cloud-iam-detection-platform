from detections.alert import alert
import time

# Memory for MFA fatigue
mfa_attempts = {}

# 7. MFA fatigue
def detect_mfa_fatigue(event):
    if event["eventName"] != "MFAChallenge":
        return
    
    user = event.get("user")
    now = time.time()

    if user not in mfa_attempts:
        mfa_attempts[user] = []

    mfa_attempts[user].append(now)

    # Keeps last 5 minutes only
    mfa_attempts[user] = [t for t in mfa_attempts[user] if now - t <= 300]

    if len(mfa_attempts[user]) > 5:
        alert("MFA fatigue attack suspected", event)


# 8. Impossible travel
def detect_impossible_travel(event):
    prev = event.get("prev_geo")
    curr = event.get("geo")

    if prev and curr and prev != curr:
        alert("Impossible travel detected", event)


# 9. Zero Trust device violation
approved_devices = {"laptop1", "laptop2"}

def detect_untrusted_device(event):
    device = event.get("device")
    if device not in approved_devices:
        alert("Untrusted device access", event)


def run_anomaly_detections(event):
    detect_mfa_fatigue(event)
    detect_impossible_travel(event)
    detect_untrusted_device(event)
