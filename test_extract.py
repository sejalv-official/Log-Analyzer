from log_parser import extract_critical_logs
import json

log_text = """{"eventTime": "2026-07-23T14:00:00Z", "errorCode": "AccessDenied", "errorMessage": "Access Denied"}
2026-07-23T14:05:02.123Z ALB-01 10.0.1.46 502 GET /api/v1/checkout"""

results = extract_critical_logs(log_text)
print(json.dumps(results, indent=2))
