from detections.alert import alert

# We store a sequence of eventNames per user
user_event_history = {}

def record_event(user, event_name):
    """Save each event per user to track sequences."""
    if user not in user_event_history:
        user_event_history[user] = []
    user_event_history[user].append(event_name)

    # Optional: keep only last 20 events
    user_event_history[user] = user_event_history[user][-20:]


# ------- ATTACK CHAIN DETECTIONS ------- #

# CHAIN 1: Access key leak -> Privilege escalation
def detect_chain_1(user):
    sequence = ["NewIP", "ListRoles", "PassRole", "AssumeRole"]
    history = user_event_history.get(user, [])

    if all(step in history for step in sequence):
        alert(f"CHAIN 1 DETECTED: Access Key Leak -> Privilege Escalation (User: {user})")


# CHAIN 2: OAuth Consent Phishing
def detect_chain_2(user):
    sequence = ["NewOAuthApp", "HighPrivPermission", "AdminConsent", "StrangeAPICall"]
    history = user_event_history.get(user, [])

    if all(step in history for step in sequence):
        alert(f"CHAIN 2 DETECTED: OAuth Consent Phishing (User: {user})")


# CHAIN 3: MFA Fatigue -> Account Takeover
def detect_chain_3(user):
    sequence = ["MFAFatigue", "MFASuccess", "CreateAccessKey", "APIAbuse"]
    history = user_event_history.get(user, [])

    if all(step in history for step in sequence):
        alert(f"CHAIN 3 DETECTED: MFA Fatigue -> Account Takeover (User: {user})")


# CHAIN 4: Token Replay -> Resource Deletion
def detect_chain_4(user):
    sequence = ["TokenReplay", "DeleteTrail"]
    history = user_event_history.get(user, [])

    if all(step in history for step in sequence):
        alert(f"CHAIN 4 DETECTED: Token Replay -> Resource Deletion (User: {user})")


# ------- MAIN CORRELATION RUNNER ------- #

def run_correlation(event):

    user = event.get("user")
    if not user:
        return

    eventName = event.get("eventName")

    # Record every event
    record_event(user, eventName)

    # Evaluate all chains
    detect_chain_1(user)
    detect_chain_2(user)
    detect_chain_3(user)
    detect_chain_4(user)
