"""Rule-based AWS log parser used by the Streamlit application."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any


# --- SECURITY RULE DEFINITIONS ---
SECURITY_RULE_DEFINITIONS = [
    (
        "Critical",
        "Credential Exposure",
        [
            r"secret[_ -]?access[_ -]?key",
            r"access[_ -]?key",
            r"credential(s)? leaked",
            r"root user",
            r"consolelogin.*failure",
        ],
    ),
    (
        "High",
        "Access Denied",
        [
            r"accessdenied",
            r"access denied",
            r"unauthorizedoperation",
            r"unauthorized",
            r"authentication failed",
            r"invalidclienttokenid",
            r"signaturedoesnotmatch",
        ],
    ),
    (
        "High",
        "IAM / Policy Change",
        [
            r"putuserpolicy",
            r"putrolepolicy",
            r"attachuserpolicy",
            r"attachrolepolicy",
            r"createaccesskey",
            r"deleteaccesskey",
            r"updateassumerolepolicy",
            r"iam[:\s_-]",
        ],
    ),
    (
        "High",
        "Destructive API Call",
        [
            r"terminateinstances",
            r"deletebucket",
            r"deleteobject",
            r"deletetrail",
            r"stoplogging",
            r"disableguardduty",
            r"disablesecurityhub",
        ],
    ),
    (
        "Medium",
        "Suspicious Network Activity",
        [
            r"rejected connection",
            r"network acl deny",
            r"blocked ip",
            r"port scan",
            r"brute force",
            r"malicious ip",
            r"threat detected",
        ],
    ),
]


# --- PERFORMANCE RULE DEFINITIONS ---
PERFORMANCE_RULE_DEFINITIONS = [
    (
        "High",
        "HTTP 5xx",
        [
            r"\b5\d{2}\b",
            r"bad gateway",
            r"service unavailable",
            r"gateway timeout",
        ],
    ),
    (
        "High",
        "CPU",
        [
            r"cpu.{0,35}(9[0-9]|100)\s*%",
            r"cpu utilization.{0,20}(critical|high)",
            r"cpu throttl",
        ],
    ),
    (
        "High",
        "Memory",
        [
            r"memory.{0,35}(9[0-9]|100)\s*%",
            r"out of memory",
            r"oomkilled",
            r"memory pressure",
            r"memory utilization.{0,20}(critical|high)",
        ],
    ),
    (
        "Medium",
        "Timeout",
        [
            r"timed?\s*out",
            r"timeout",
            r"connection timeout",
            r"read timeout",
            r"request timeout",
        ],
    ),
    (
        "Medium",
        "Database",
        [
            r"(database connection|db connection|too many connections|deadlock|slow query|rds|aurora).{0,80}(error|failed|timeout|high|critical)"
        ],
    ),
    (
        "Medium",
        "Container / Kubernetes",
        [
            r"crashloopbackoff",
            r"imagepullbackoff",
            r"oomkilled",
            r"pod evicted",
            r"failed scheduling",
            r"pending task",
            r"ecs task stopped",
        ],
    ),
    (
        "Medium",
        "Application Error",
        [
            r"\berror\b",
            r"\bexception\b",
            r"\bfatal\b",
            r"\bcritical\b",
        ],
    ),
]


# --- HELPER FUNCTION TO COMPILE PATTERNS ---
def _compile_rules(definitions: list[tuple[str, str, list[str]]]) -> list[tuple[str, str, re.Pattern]]:
    """Compile list of string patterns into unified regex objects."""
    compiled_rules = []
    for severity, category, patterns in definitions:
        joined_pattern = "(" + "|".join(patterns) + ")"
        compiled_rules.append((severity, category, re.compile(joined_pattern, re.IGNORECASE)))
    return compiled_rules


SECURITY_RULES = _compile_rules(SECURITY_RULE_DEFINITIONS)
PERFORMANCE_RULES = _compile_rules(PERFORMANCE_RULE_DEFINITIONS)


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