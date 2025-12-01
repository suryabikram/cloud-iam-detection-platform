from detections.run_all import run_all_detections
from ingestion.cloudtrail_ingestor import parse_cloudtrail_event

# Fake attack chain 1 sequence
events = [
    {"eventName": "NewIP", "user": "attacker"},
    {"eventName": "ListRoles", "user": "attacker"},
    {"eventName": "PassRole", "user": "attacker"},
    {"eventName": "AssumeRole", "user": "attacker"}
]

for e in events:
    run_all_detections(e)
