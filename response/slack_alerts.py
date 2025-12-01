
def send_slack_alert(message):
    """
    Simulated Slack alert.
    In real world: requests.post(WEBHOOK_URL, json={"text": message})
    """
    print(f"[SLACK] {message}")
