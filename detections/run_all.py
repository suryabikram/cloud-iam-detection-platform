from detections.iam_rules import run_iam_detections
from detections.token_rules import run_token_detections
from detections.oauth_rules import run_oauth_detections
from detections.anomaly_rules import run_anomaly_detections

def run_all_detections(event):
    run_iam_detections(event)
    run_token_detections(event)
    run_oauth_detections(event)
    run_anomaly_detections(event)
