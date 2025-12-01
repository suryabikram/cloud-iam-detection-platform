
def disable_access_key(key_id):
    """
    Simulated AWS IAM access key disable.
    In real AWS: iam.update_access_key(...).
    """
    print(f"[RESPONSE] Simulating disable of access key: {key_id}")
