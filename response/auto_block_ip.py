
def block_ip(ip):
    """
    Simulated IP block.
    In real AWS: ec2.create_network_acl_entry(...).
    """
    print(f"[RESPONSE] Simulating network block for IP: {ip}")
