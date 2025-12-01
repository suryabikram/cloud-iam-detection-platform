from response.auto_disable_keys import disable_access_key
from response.auto_block_ip import block_ip
from response.slack_alerts import send_slack_alert
from risk.zero_trust_engine import calculate_risk_score, risk_decision


def auto_respond(event):
    """
    Takes an event, calculates risk, and triggers response actions.
    """

    score = calculate_risk_score(event)
    decision = risk_decision(score)

    user = event.get("user")
    ip = event.get("sourceIPAddress")
    access_key = event.get("accessKeyId")

    print(f"\n[RESPONSE ENGINE]")
    print(f"  Event user:       {user}")
    print(f"  Source IP:        {ip}")
    print(f"  Access Key ID:    {access_key}")
    print(f"  Risk decision:    {decision}")

    # ----- BLOCK ACTION -----
    if decision == "BLOCK":
        send_slack_alert(f"BLOCK: High-risk behavior detected for user {user}")

        if access_key:
            disable_access_key(access_key)

        if ip:
            block_ip(ip)

        print("[RESPONSE ENGINE] ->  Block action completed.\n")


    # ----- MFA CHALLENGE -----
    elif decision == "MFA":
        send_slack_alert(f"MFA challenge triggered for user {user}")
        print("[RESPONSE ENGINE] ->  MFA challenge simulated.\n")


    # ----- ALLOW -----
    else:
        print("[RESPONSE ENGINE] ->  No action required.\n")
