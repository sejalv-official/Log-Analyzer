"""AWS Telemetry fetcher module using Boto3."""

from __future__ import annotations

import gzip
import os
import time
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def _get_session(role_arn: str | None = None) -> boto3.Session:
    """Create a Boto3 session, assuming an IAM Role if provided."""
    base_session = boto3.Session()

    if not role_arn:
        return base_session

    try:
        sts_client = base_session.client("sts")
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AILogAnalyzerSession",
        )
        credentials = assumed_role["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
    except Exception:
        return base_session


def list_s3_buckets(role_arn: str | None = None) -> tuple[list[str], str | None]:
    """List S3 buckets available in the account."""
    try:
        session = _get_session(role_arn)
        s3 = session.client("s3")
        response = s3.list_buckets()
        buckets = [b["Name"] for b in response.get("Buckets", [])]
        return buckets, None
    except Exception as exc:
        return [], f"Failed to list S3 buckets: {exc}"


def fetch_latest_s3_log(
    bucket_name: str, role_arn: str | None = None
) -> tuple[str | None, str]:
    """Fetch content of the latest file in an S3 bucket."""
    try:
        session = _get_session(role_arn)
        s3 = session.client("s3")
        paginator = s3.get_paginator("list_objects_v2")

        latest_object = None
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get("Contents", []):
                if not latest_object or obj["LastModified"] > latest_object["LastModified"]:
                    latest_object = obj

        if not latest_object:
            return None, f"No log files found in S3 bucket '{bucket_name}'."

        key = latest_object["Key"]
        obj_res = s3.get_object(Bucket=bucket_name, Key=key)
        body = obj_res["Body"].read()

        if key.endswith(".gz"):
            body = gzip.decompress(body)

        content = body.decode("utf-8", errors="replace")
        return content, f"Successfully fetched `{key}` from S3 bucket '{bucket_name}'."
    except Exception as exc:
        return None, f"Error fetching from S3: {exc}"


def list_cloudwatch_log_groups(
    role_arn: str | None = None,
) -> tuple[list[str], str | None]:
    """List CloudWatch log groups."""
    try:
        session = _get_session(role_arn)
        logs = session.client("logs")
        response = logs.describe_log_groups()
        groups = [g["logGroupName"] for g in response.get("logGroups", [])]
        return groups, None
    except Exception as exc:
        return [], f"Failed to list Log Groups: {exc}"


def fetch_cloudwatch_logs(
    log_group_name: str, role_arn: str | None = None
) -> tuple[str | None, str]:
    """Fetch recent log events from a CloudWatch log group across streams without restrictive time limits."""
    try:
        session = _get_session(role_arn)
        logs = session.client("logs")

        # Look back 24 hours (24 hours * 3600 seconds * 1000 ms)
        start_time_ms = int((time.time() - (24 * 3600)) * 1000)

        # Approach 1: Filter events across all streams in the group for the past 24 hours
        response = logs.filter_log_events(
            logGroupName=log_group_name,
            startTime=start_time_ms,
            limit=100,
        )
        events = response.get("events", [])

        # Approach 2 (Fallback): Get latest stream directly if no events in 24 hours
        if not events:
            streams_res = logs.describe_log_streams(
                logGroupName=log_group_name,
                orderBy="LastEventTime",
                descending=True,
                limit=1,
            )
            streams = streams_res.get("logStreams", [])

            if streams:
                latest_stream = streams[0]["logStreamName"]
                stream_events_res = logs.get_log_events(
                    logGroupName=log_group_name,
                    logStreamName=latest_stream,
                    limit=100,
                    startFromHead=False,
                )
                events = stream_events_res.get("events", [])

        if not events:
            return (
                None,
                f"No CloudWatch log events found in '{log_group_name}'.",
            )

        log_lines = [e.get("message", "").strip() for e in events]
        return "\n".join(log_lines), f"Successfully fetched {len(events)} events from {log_group_name}."
    except Exception as exc:
        return None, f"Error fetching CloudWatch logs: {exc}"


def fetch_cloudtrail_events(
    role_arn: str | None = None,
) -> tuple[str | None, str]:
    """Fetch recent AWS CloudTrail events."""
    try:
        session = _get_session(role_arn)
        cloudtrail = session.client("cloudtrail")
        response = cloudtrail.lookup_events(MaxResults=50)
        events = response.get("Events", [])
        if not events:
            return None, "No CloudTrail events found in recent activity."

        log_lines = []
        for event in events:
            log_lines.append(
                f"{event.get('EventTime')} [{event.get('EventName')}] User: {event.get('Username')} - Resource: {event.get('Resources')}"
            )
        return "\n".join(log_lines), f"Successfully fetched {len(events)} CloudTrail management events."
    except Exception as exc:
        return None, f"Error fetching CloudTrail events: {exc}"