
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Iterable


DEFAULT_WINDOW_MINUTES = 15


def _parse_time(value):
    """
    Parse timestamps safely and normalize all datetimes to UTC.
    Prevents offset-naive / offset-aware subtraction errors.
    """
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(
            str(value).strip().replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except (TypeError, ValueError):
        return None


def _normalize_text(value):
    return str(value or "").lower()


def _extract_tokens(text):
    """
    Extract lightweight correlation tokens from incident evidence.

    We intentionally use explainable deterministic matching rather than
    asking the LLM to decide whether incidents belong together.
    """
    text = _normalize_text(text)

    patterns = {
        "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "instance": r"\bi-[0-9a-f]{8,17}\b",
        "eni": r"\beni-[0-9a-f]{8,17}\b",
        "sg": r"\bsg-[0-9a-f]{8,17}\b",
        "subnet": r"\bsubnet-[0-9a-f]{8,17}\b",
        "vpc": r"\bvpc-[0-9a-f]{8,17}\b",
        "arn": r"\barn:aws:[^\s\"',}]+",
        "request_path": r"\/[a-zA-Z0-9_\-./]+",
    }

    tokens = set()

    for prefix, pattern in patterns.items():
        for match in re.findall(pattern, text):
            tokens.add(f"{prefix}:{match}")

    service_keywords = [
        "iam",
        "s3",
        "cloudtrail",
        "cloudwatch",
        "ec2",
        "ecs",
        "eks",
        "lambda",
        "rds",
        "aurora",
        "alb",
        "elb",
        "load balancer",
        "dynamodb",
        "api gateway",
        "waf",
        "guardduty",
    ]

    for service in service_keywords:
        if service in text:
            tokens.add(f"service:{service}")

    error_keywords = [
        "accessdenied",
        "unauthorizedoperation",
        "credential exposure",
        "timeout",
        "connection timeout",
        "502",
        "503",
        "504",
        "5xx",
        "cpu",
        "memory",
        "throttle",
        "security group",
        "terminateinstances",
        "deleteobject",
        "deletebucket",
    ]

    for keyword in error_keywords:
        if keyword in text:
            tokens.add(f"signal:{keyword}")

    return tokens


def _incident_time(incident):
    return (
        _parse_time(incident.get("first_seen"))
        or _parse_time(incident.get("created_at"))
    )


def _correlation_score(left, right, window_minutes=DEFAULT_WINDOW_MINUTES):
    """
    Return a deterministic correlation score from 0-100.

    Scoring:
      +30 within configured time window
      +25 shared resource/service/signal tokens
      +20 different sources (cross-source evidence)
      +15 compatible incident types/categories
      +10 both high/critical severity
    """
    score = 0
    reasons = []

    left_time = _incident_time(left)
    right_time = _incident_time(right)

    if left_time and right_time:
        delta = abs(left_time - right_time)

        if delta <= timedelta(minutes=window_minutes):
            score += 30
            reasons.append(
                f"Events occurred within {window_minutes} minutes."
            )
        else:
            return 0, []

    left_text = " ".join(
        [
            str(left.get("source") or ""),
            str(left.get("category") or ""),
            str(left.get("message") or ""),
        ]
    )
    right_text = " ".join(
        [
            str(right.get("source") or ""),
            str(right.get("category") or ""),
            str(right.get("message") or ""),
        ]
    )

    left_tokens = _extract_tokens(left_text)
    right_tokens = _extract_tokens(right_text)

    shared_tokens = sorted(left_tokens.intersection(right_tokens))

    if shared_tokens:
        token_score = min(25, 10 + (5 * len(shared_tokens)))
        score += token_score
        reasons.append(
            "Shared evidence: "
            + ", ".join(shared_tokens[:6])
        )

    left_source = _normalize_text(left.get("source"))
    right_source = _normalize_text(right.get("source"))

    if left_source and right_source and left_source != right_source:
        score += 20
        reasons.append(
            "Evidence comes from different log sources."
        )

    left_type = _normalize_text(left.get("incident_type"))
    right_type = _normalize_text(right.get("incident_type"))
    left_category = _normalize_text(left.get("category"))
    right_category = _normalize_text(right.get("category"))

    compatible = False

    if left_type == right_type:
        compatible = True

    related_pairs = [
        ("iam", "access"),
        ("credential", "access"),
        ("timeout", "5"),
        ("database", "timeout"),
        ("cpu", "5"),
        ("memory", "5"),
        ("security group", "timeout"),
        ("security group", "5"),
    ]

    combined_left = f"{left_category} {left_text.lower()}"
    combined_right = f"{right_category} {right_text.lower()}"

    for a, b in related_pairs:
        if (
            (a in combined_left and b in combined_right)
            or (b in combined_left and a in combined_right)
        ):
            compatible = True
            break

    if compatible:
        score += 15
        reasons.append(
            "Incident categories/types are technically related."
        )

    severe = {"high", "critical"}
    if (
        _normalize_text(left.get("severity")) in severe
        and _normalize_text(right.get("severity")) in severe
    ):
        score += 10
        reasons.append(
            "Both incidents are high-severity signals."
        )

    return min(score, 100), reasons


def find_cross_source_correlations(
    incidents: Iterable[dict],
    window_minutes=DEFAULT_WINDOW_MINUTES,
    minimum_score=50,
):
    """
    Group related incidents without deleting or merging child incidents.

    Returns parent correlation candidates containing:
      - incident_ids
      - confidence
      - reasons
      - sources
      - first_seen
      - last_seen
    """
    incidents = list(incidents or [])

    if len(incidents) < 2:
        return []

    graph = {i: set() for i in range(len(incidents))}
    pair_metadata = {}

    for i in range(len(incidents)):
        for j in range(i + 1, len(incidents)):
            score, reasons = _correlation_score(
                incidents[i],
                incidents[j],
                window_minutes=window_minutes,
            )

            if score >= minimum_score:
                graph[i].add(j)
                graph[j].add(i)
                pair_metadata[(i, j)] = (score, reasons)

    visited = set()
    groups = []

    for start in range(len(incidents)):
        if start in visited or not graph[start]:
            continue

        stack = [start]
        component = []

        while stack:
            node = stack.pop()

            if node in visited:
                continue

            visited.add(node)
            component.append(node)

            for neighbor in graph[node]:
                if neighbor not in visited:
                    stack.append(neighbor)

        if len(component) < 2:
            continue

        group_incidents = [
            incidents[index]
            for index in sorted(component)
        ]

        pair_scores = []
        reasons = []

        for i in component:
            for j in component:
                if i >= j:
                    continue

                metadata = pair_metadata.get((min(i, j), max(i, j)))

                if metadata:
                    pair_scores.append(metadata[0])
                    reasons.extend(metadata[1])

        confidence = (
            round(sum(pair_scores) / len(pair_scores))
            if pair_scores
            else minimum_score
        )

        seen_times = [
            _incident_time(item)
            for item in group_incidents
        ]
        seen_times = [
            value
            for value in seen_times
            if value is not None
        ]

        sources = sorted(
            {
                str(item.get("source") or "Unknown Source")
                for item in group_incidents
            }
        )

        groups.append(
            {
                "incident_ids": [
                    item.get("incident_id")
                    for item in group_incidents
                    if item.get("incident_id")
                ],
                "confidence": confidence,
                "reasons": sorted(set(reasons)),
                "sources": sources,
                "first_seen": (
                    min(seen_times).isoformat()
                    if seen_times
                    else None
                ),
                "last_seen": (
                    max(seen_times).isoformat()
                    if seen_times
                    else None
                ),
            }
        )

    groups.sort(
        key=lambda item: (
            item["confidence"],
            item["last_seen"] or "",
        ),
        reverse=True,
    )

    return groups
