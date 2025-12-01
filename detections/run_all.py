from detections.iam_rules import run_iam_detections
from detections.token_rules import run_token_detections
from detections.oauth_rules import run_oauth_detections
from detections.anomaly_rules import run_anomaly_detections
from correlation.correlation_engine import run_correlation
from risk.zero_trust_engine import explain_risk



def run_all_detections(event):
     # Running individual detection engines
    run_iam_detections(event)
    run_token_detections(event)
    run_oauth_detections(event)
    run_anomaly_detections(event)

     # Correlation across events
    run_correlation(event)

    # Zero Trust scoring overview (for this single event)
    explain_risk(event)
