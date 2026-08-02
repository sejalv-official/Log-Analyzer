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


def get_aws_account_id(role_arn: str | None = None) -> tuple[str | None, str | None]:
    """Fetch the AWS Account ID associated with the active credentials or assumed role."""
    try:
        session = _get_session(role_arn)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity.get("Account")
        return account_id, None
    except Exception as exc:
        return None, f"Unable to fetch Account ID: {exc}"


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
    bucket_name: str, role_arn: str | None = None, max_files_per_folder: int = 3
) -> tuple[str | None, str]:
    """
    Fetch recent files across ALL subfolders (alb/, vpc-flow/, cloudtrail/, etc.)
    inside the bucket, ensuring balanced log analysis.
    """
    try:
        session = _get_session(role_arn)
        s3 = session.client("s3")
        paginator = s3.get_paginator("list_objects_v2")

        all_objects = []
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get("Contents", []):
                # Ignore folder placeholder keys
                if not obj["Key"].endswith("/"):
                    all_objects.append(obj)

        if not all_objects:
            return None, f"No log files found in S3 bucket '{bucket_name}'."

        # Group objects by top-level folder prefix (e.g., alb/, cloudtrail/, vpc-flow/)
        folder_groups: dict[str, list[dict]] = {}
        unfoldered_objects: list[dict] = []

        for obj in all_objects:
            key = obj["Key"]
            if "/" in key:
                prefix = key.split("/")[0] + "/"
                if prefix not in folder_groups:
                    folder_groups[prefix] = []
                folder_groups[prefix].append(obj)
            else:
                unfoldered_objects.append(obj)

        selected_objects = []

        # Grab the newest files from EACH top-level folder
        if folder_groups:
            for prefix, objs in folder_groups.items():
                objs.sort(key=lambda item: item["LastModified"], reverse=True)
                selected_objects.extend(objs[:max_files_per_folder])

        if unfoldered_objects:
            unfoldered_objects.sort(key=lambda item: item["LastModified"], reverse=True)
            selected_objects.extend(unfoldered_objects[:max_files_per_folder])

        # Fallback sorting if no distinct prefixes were matched
        if not selected_objects:
            all_objects.sort(key=lambda item: item["LastModified"], reverse=True)
            selected_objects = all_objects[:10]

        combined_logs = []
        fetched_keys = []

        for obj in selected_objects:
            key = obj["Key"]
            obj_res = s3.get_object(Bucket=bucket_name, Key=key)
            body = obj_res["Body"].read()

            if key.endswith(".gz"):
                body = gzip.decompress(body)

            content = body.decode("utf-8", errors="replace").strip()
            if content:
                # Prepend S3 Object URI header so log_parser tracks the exact file path
                combined_logs.append(f"# S3_OBJECT: s3://{bucket_name}/{key}\n{content}")
                fetched_keys.append(key)

        if not combined_logs:
            return None, f"The recent log files in '{bucket_name}' were empty."

        return (
            "\n".join(combined_logs),
            f"Successfully fetched {len(fetched_keys)} log file(s) across folders ({', '.join(folder_groups.keys())}) in S3 bucket '{bucket_name}'.",
        )
    except Exception as exc:
        return None, f"Error fetching from S3: {exc}"


def fetch_all_s3_buckets_logs(
    role_arn: str | None = None, max_files_per_bucket: int = 3
) -> tuple[str | None, str]:
    """Scan ALL S3 buckets in the account and fetch recent log files across all subfolders."""
    buckets, err = list_s3_buckets(role_arn)
    if err or not buckets:
        return None, err or "No S3 buckets found to scan."

    all_logs = []
    summary_msgs = []

    for bucket in buckets:
        content, msg = fetch_latest_s3_log(bucket, role_arn, max_files_per_folder=max_files_per_bucket)
        if content:
            all_logs.append(content)
            summary_msgs.append(f"• {bucket}: Loaded")

    if not all_logs:
        return None, f"Scanned {len(buckets)} bucket(s), but no log files were found."

    combined_text = "\n".join(all_logs)
    status_summary = f"Scanned {len(buckets)} bucket(s) successfully:\n" + "\n".join(summary_msgs)
    return combined_text, status_summary


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
    log_group_name: str, role_arn: str | None = None, max_events: int = 2000
) -> tuple[str | None, str]:
    """Fetch recent log events from a CloudWatch Log Group with fallback to latest stream."""
    try:
        session = _get_session(role_arn)
        logs = session.client("logs")

        # Look back 7 days
        start_time_ms = int((time.time() - (7 * 24 * 3600)) * 1000)

        log_lines = []
        next_token = None

        # 1. Try filtering across streams for the last 7 days
        while len(log_lines) < max_events:
            kwargs = {
                "logGroupName": log_group_name,
                "startTime": start_time_ms,
                "limit": 100,
            }
            if next_token:
                kwargs["nextToken"] = next_token

            response = logs.filter_log_events(**kwargs)
            events = response.get("events", [])

            for event in events:
                msg = event.get("message", "").strip()
                if msg:
                    log_lines.append(msg)

            next_token = response.get("nextToken")
            if not next_token or not events:
                break

        # 2. FALLBACK: If 0 events found in time window, fetch directly from the newest Log Stream
        if not log_lines:
            streams_res = logs.describe_log_streams(
                logGroupName=log_group_name,
                orderBy="LastEventTime",
                descending=True,
                limit=1,
            )
            streams = streams_res.get("logStreams", [])

            if streams:
                latest_stream_name = streams[0]["logStreamName"]
                stream_events_res = logs.get_log_events(
                    logGroupName=log_group_name,
                    logStreamName=latest_stream_name,
                    limit=200,
                    startFromHead=False,
                )
                events = stream_events_res.get("events", [])
                for event in events:
                    msg = event.get("message", "").strip()
                    if msg:
                        log_lines.append(msg)

        if not log_lines:
            return (
                None,
                f"No CloudWatch log events found in '{log_group_name}'. Ensure the log group contains active streams.",
            )

        return "\n".join(log_lines), f"Successfully fetched {len(log_lines)} events from '{log_group_name}'."
    except Exception as exc:
        return None, f"Error fetching CloudWatch logs: {exc}"


def fetch_cloudtrail_events(
    role_arn: str | None = None,
) -> tuple[str | None, str]:
    """Fetch recent AWS CloudTrail management events."""
    try:
        session = _get_session(role_arn)
        cloudtrail = session.client("cloudtrail")
        response = cloudtrail.lookup_events(MaxResults=50)
        events = response.get("Events", [])
        if not events:
            return None, "No CloudTrail management events found in recent activity."

        log_lines = []
        for event in events:
            log_lines.append(
                f"{event.get('EventTime')} [{event.get('EventName')}] User: {event.get('Username')} - Resource: {event.get('Resources')}"
            )
        return "\n".join(log_lines), f"Successfully fetched {len(events)} CloudTrail management events."
    except Exception as exc:
        return None, f"Error fetching CloudTrail events: {exc}"