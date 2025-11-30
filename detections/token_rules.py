from detections.alert import alert

# Mock memory (later: store in file/db)
seen_ips = set()
inactive_keys = {"AKIAFAKEINACTIVE123"}

# 3. New IP address for access key
def detect_new_ip(event):
    ip = event.get("sourceIPAddress")
    if ip and ip not in seen_ips:
        seen_ips.add(ip)
        alert("Access key used from new IP address", event)


# 4. Access key used after being inactive
def detect_inactive_key_use(event):
    key = event.get("accessKeyId")
    if key in inactive_keys:
        alert("Stolen or inactive access key attempted", event)


# 5. Token replay (two different IPs using same token)
token_ip_map = {}

def detect_token_replay(event):
    token = event.get("sessionContext", {}).get("sessionIssuer", "NO_TOKEN")
    ip = event.get("sourceIPAddress")

    if token in token_ip_map and token_ip_map[token] != ip:
        alert("STS Token replay detected", event)

    token_ip_map[token] = ip


def run_token_detections(event):
    detect_new_ip(event)
    detect_inactive_key_use(event)
    detect_token_replay(event)

