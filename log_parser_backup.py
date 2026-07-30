"""Rule-based AWS log parser used by the Streamlit application."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any


SECURITY_RULES = [
    ("Critical", "Credential Exposure", re.compile(
        r"(secret[_ -]?access[_ -]?key|access[_ -]?key|credential(s)? leaked|"
        r"root user|consolelogin.*failure)",
        re.IGNORECASE,
    )),
    ("High", "Access Denied", re.compile(
        r"(accessdenied|access denied|unauthorizedoperation|unauthorized|"
        r"authentication failed|invalidclienttokenid|signaturedoesnotmatch)",
        re.IGNORECASE,
    )),
    ("High", "IAM / Policy Change", re.compile(
        r"(putuserpolicy|putrolepolicy|attachuserpolicy|attachrolepolicy|"
        r"createaccesskey|deleteaccesskey|updateassumerolepolicy|"
        r"iam[:\s_-])",
        re.IGNORECASE,
    )),
    ("High", "Destructive API Call", re.compile(
        r"(terminateinstances|deletebucket|deleteobject|deletetrail|"
        r"stoplogging|disableguardduty|disablesecurityhub)",
        re.IGNORECASE,
    )),
    ("Medium", "Suspicious Network Activity", re.compile(
        r"(rejected connection|network acl deny|blocked ip|port scan|"
        r"brute force|malicious ip|threat detected)",
        re.IGNORECASE,
    )),
]

PERFORMANCE_RULES = [
    ("High", "HTTP 5xx", re.compile(
        r"(\b5\d{2}\b|bad gateway|service unavailable|gateway timeout)",
        re.IGNORECASE,
    )),
    ("High", "CPU", re.compile(
        r"(cpu.{0,35}(9[0-9]|100)\s*%|cpu utilization.{0,20}(critical|high)|"
        r"cpu throttl)",
        re.IGNORECASE,
    )),
    ("High", "Memory", re.compile(
        r"(memory.{0,35}(9[0-9]|100)\s*%|out of memory|oomkilled|"
        r"memory pressure|memory utilization.{0,20}(critical|high))",
        re.IGNORECASE,
    )),
    ("Medium", "Timeout", re.compile(
        r"(timed?\s*out|timeout|connection timeout|read timeout|"
        r"request timeout)",
        re.IGNORECASE,
    )),
    ("Medium", "Database", re.compile(
        r"(database connection|db connection|too many connections|"
        r"deadlock|slow query|rds|aurora).{0,80}(error|failed|timeout|high|critical)",
        re.IGNORECASE,
    )),
    ("Medium", "Container / Kubernetes", re.compile(
        r"(crashloopbackoff|imagepullbackoff|oomkilled|pod evicted|"
        r"failed scheduling|pending task|ecs task stopped)",
        re.IGNORECASE,
    )),
    ("Medium", "Application Error", re.compile(
        r"(\berror\b|\bexception\b|\bfatal\b|\bcritical\b)",
        re.IGNORECASE,
    )),
]


def _extract_timestamp(line: str) -> str:
    patterns = [
        r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b",
        r"\b\d{4}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2}\b",
    ]

    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            value = match.group(0).replace(" ", "T", 1)
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            try:
                return datetime.fromisoformat(value).isoformat()
            except ValueError:
                return match.group(0)

    return datetime.now(timezone.utc).isoformat()


def _normalise_line(item: Any) -> str:
    if isinstance(item, str):
        return item.strip()
    try:
        return json.dumps(item, ensure_ascii=False)
    except TypeError:
        return str(item)


def extract_critical_logs(
    log_text: str,
    source_context: str = "Unknown Source",
) -> dict[str, list]:
    """Return security, performance and structured incident data."""

    security: list[str] = []
    performance: list[str] = []
    structured_data: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    for raw_line in log_text.splitlines():
        line = _normalise_line(raw_line)
        if not line:
            continue

        matched = False

        for incident_type, rules in (
            ("Security", SECURITY_RULES),
            ("Performance", PERFORMANCE_RULES),
        ):
            for severity, category, pattern in rules:
                if not pattern.search(line):
                    continue

                dedupe_key = (incident_type, category, line)
                if dedupe_key in seen:
                    matched = True
                    break

                seen.add(dedupe_key)
                matched = True

                if incident_type == "Security":
                    security.append(line)
                else:
                    performance.append(line)

                structured_data.append(
                    {
                        "Timestamp": _extract_timestamp(line),
                        "Type": incident_type,
                        "Severity": severity,
                        "Category": category,
                        "Source": source_context,
                        "Message": line,
                    }
                )
                break

            if matched:
                break

    return {
        "security": security,
        "performance": performance,
        "structured_data": structured_data,
    }