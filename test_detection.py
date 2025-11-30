from ingestion.cloudtrail_ingestor import load_event_from_file
from detections.run_all import run_all_detections

event = load_event_from_file("sample_logs/passrole_event.json")

print("Running detections...")
run_all_detections(event)
