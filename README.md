# cloud-iam-detection-platform

A complete security engineering project detecting:
- Privilege escalation
- Access key compromise
- OAuth abuse
- Token replay
- MFA fatigue
- Impossible travel
- Zero Trust violations

Includes:
- Ingestion engine
- Detection rules (23)
- Correlation engine
- Zero Trust scoring
- Response automation
- Splunk dashboard
- MITRE ATT&CK mapping
- Attack simulations

Architecture:
AWS CloudTrail → Ingestion → Detection Engine → Correlation → Zero Trust → Response → Splunk