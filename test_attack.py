import sys
import json
from ingestion.cloudtrail_ingestor import parse_cloudtrail_event
from detections.run_all import run_all_detections

# Usage: python test_attack.py <path_to_json>
if len(sys.argv) != 2:
    print("Usage: python test_attack.py <event.json>")
    sys.exit(1)

path = sys.argv[1]

with open(path, "r") as f:
    event_json = json.load(f)

event = parse_cloudtrail_event(event_json)

print("\n=== Running Attack Simulation ===")
print(f"Loaded event: {path}\n")

run_all_detections(event)
