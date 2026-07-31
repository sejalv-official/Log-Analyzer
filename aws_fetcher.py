from __future__ import annotations

import gzip
import json
import os
import time
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Any

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    PartialCredentialsError,
)


DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")


def _get_session(
    role_arn: str | None = None,
    region: str | None = None,
) -> boto3.Session:
    """
    Create a boto3 session.

    Credential order:
    1. Credentials entered in the Streamlit application and exported
       into environment variables.
    2. AWS CLI credentials/configuration.
    3. EC2/ECS IAM role credentials.
    4. Optional AssumeRole for cross-account access.
    """

    selected_region = (
        region
        or os.getenv("AWS_REGION")
        or os.getenv("AWS_DEFAULT_REGION")
        or DEFAULT_REGION
    )

    base_session = boto3.Session(region_name=selected_region)

    if not role_arn:
        return base_session

    sts_client = base_session.client(
        "sts",
        region_name=selected_region,
    )

    assumed_role = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName="AILogAnalyzerSession",
        DurationSeconds=3600,
    )

    credentials = assumed_role["Credentials"]

    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=selected_region,
    )


def _format_aws_error(
    operation: str,
    exception: Exception,
) -> str:
    """Convert boto3 exceptions into readable UI messages."""

    if isinstance(exception, NoCredentialsError):
        return (
            f"Error during {operation}: AWS credentials were not found. "
            "Configure credentials using the application, AWS CLI, "
            "environment variables, or an IAM role."
        )

    if isinstance(exception, PartialCredentialsError):
        return (
            f"Error during {operation}: AWS credentials are incomplete. "
            "Provide both the access key and secret access key. Temporary "
            "credentials also require a session token."
        )

    if isinstance(exception, ClientError):
        error = exception.response.get("Error", {})
        code = error.get("Code", "UnknownClientError")
        message = error.get("Message", str(exception))

        return f"Error during {operation}: {code} - {message}"

    return f"Error during {operation}: {exception}"


def list_s3_buckets(
    role_arn: str | None = None,
    region: str | None = None,
) -> tuple[list[str], str | None]:
    """
    Return accessible S3 bucket names.

    Returns:
        (bucket_names, error_message)
    """

    try:
        session = _get_session(
            role_arn=role_arn,
            region=region,
        )
        s3_client = session.client("s3")

        response = s3_client.list_buckets()

        buckets = sorted(
            bucket["Name"]
            for bucket in response.get("Buckets", [])
            if bucket.get("Name")
        )

        return buckets, None

    except (
        ClientError,
        BotoCoreError,
        NoCredentialsError,
        PartialCredentialsError,
    ) as exc:
        return [], _format_aws_error(
            "listing S3 buckets",
            exc,
        )

    except Exception as exc:
        return [], _format_aws_error(
            "listing S3 buckets",
            exc,
        )


def list_cloudwatch_log_groups(
    role_arn: str | None = None,
    region: str | None = None,
) -> tuple[list[str], str | None]:
    """
    Return accessible CloudWatch Log Group names.

    Returns:
        (log_group_names, error_message)
    """
    try:
        session = _get_session(
            role_arn=role_arn,
            region=region,
        )
        logs_client = session.client("logs")

        paginator = logs_client.get_paginator("describe_log_groups")
        log_groups = []

        for page in paginator.paginate():
            for group in page.get("logGroups", []):
                name = group.get("logGroupName")
                if name:
                    log_groups.append(name)

        return sorted(log_groups), None

    except (
        ClientError,
        BotoCoreError,
        NoCredentialsError,
        PartialCredentialsError,
    ) as exc:
        return [], _format_aws_error(
            "listing CloudWatch log groups",
            exc,
        )

    except Exception as exc:
        return [], _format_aws_error(
            "listing CloudWatch log groups",
            exc,
        )


def _decode_s3_object(
    object_body: bytes,
    object_key: str,
) -> str:
    """
    Decode plain text, JSON, .log, and gzip-compressed AWS log files.
    """

    if object_key.lower().endswith(".gz"):
        with gzip.GzipFile(
            fileobj=BytesIO(object_body)
        ) as gzip_file:
            return gzip_file.read().decode(
                "utf-8",
                errors="replace",
            )

    return object_body.decode(
        "utf-8",
        errors="replace",
    )


def fetch_latest_s3_log(
    bucket: str,
    role_arn: str | None = None,
    region: str | None = None,
    prefix: str = "",
    max_files: int = 5,
) -> tuple[str, str]:
    """
    Fetch recent log files from S3.

    This works for:
    - ALB access logs stored as .log.gz
    - CloudTrail logs stored as .json.gz
    - Plain .log, .txt, and .json objects

    Args:
        bucket: S3 bucket name.
        role_arn: Optional cross-account role.
        region: AWS Region.
        prefix: Optional S3 prefix.
        max_files: Number of latest files to retrieve.
    """

    try:
        if not bucket.strip():
            return "", "Error: S3 bucket name is required."

        session = _get_session(
            role_arn=role_arn,
            region=region,
        )
        s3_client = session.client("s3")

        paginator = s3_client.get_paginator(
            "list_objects_v2"
        )

        objects: list[dict[str, Any]] = []

        page_iterator = paginator.paginate(
            Bucket=bucket,
            Prefix=prefix,
            PaginationConfig={
                "PageSize": 1000,
            },
        )

        supported_extensions = (
            ".log",
            ".txt",
            ".json",
            ".gz",
            ".log.gz",
            ".json.gz",
        )

        for page in page_iterator:
            for item in page.get("Contents", []):
                key = item.get("Key", "")

                if (
                    key
                    and not key.endswith("/")
                    and key.lower().endswith(
                        supported_extensions
                    )
                ):
                    objects.append(item)

        if not objects:
            return (
                "",
                (
                    "No supported log files were found in "
                    f"s3://{bucket}/{prefix}"
                ),
            )

        objects.sort(
            key=lambda item: item["LastModified"],
            reverse=True,
        )

        selected_objects = objects[
            : max(1, min(max_files, 20))
        ]

        combined_logs: list[str] = []
        fetched_keys: list[str] = []

        for item in selected_objects:
            key = item["Key"]

            response = s3_client.get_object(
                Bucket=bucket,
                Key=key,
            )

            body = response["Body"].read()
            content = _decode_s3_object(
                body,
                key,
            )

            if content.strip():
                combined_logs.append(
                    f"# S3_OBJECT: s3://{bucket}/{key}\n"
                    f"{content}"
                )
                fetched_keys.append(key)

        if not combined_logs:
            return (
                "",
                "The selected S3 log files were empty.",
            )

        return (
            "\n\n".join(combined_logs),
            (
                f"Fetched {len(fetched_keys)} recent log "
                f"file(s) from S3 bucket {bucket}."
            ),
        )

    except (
        ClientError,
        BotoCoreError,
        NoCredentialsError,
        PartialCredentialsError,
    ) as exc:
        return "", _format_aws_error(
            "fetching S3 logs",
            exc,
        )

    except (OSError, EOFError) as exc:
        return (
            "",
            f"Error decompressing an S3 log file: {exc}",
        )

    except Exception as exc:
        return "", _format_aws_error(
            "fetching S3 logs",
            exc,
        )


def fetch_cloudwatch_logs(
    log_group: str,
    role_arn: str | None = None,
    region: str | None = None,
    minutes: int = 60,
    filter_pattern: str = "",
    max_events: int = 5000,
) -> tuple[str, str]:
    """
    Fetch recent events from a CloudWatch Logs log group.

    Args:
        log_group: CloudWatch log group name.
        role_arn: Optional cross-account IAM role ARN.
        region: AWS Region.
        minutes: Number of previous minutes to query.
        filter_pattern: Optional CloudWatch filter pattern.
        max_events: Maximum events returned to the application.
    """

    try:
        if not log_group.strip():
            return (
                "",
                "Error: CloudWatch Log Group Name is required.",
            )

        if minutes <= 0:
            return (
                "",
                "Error: CloudWatch time range must be greater than zero.",
            )

        session = _get_session(
            role_arn=role_arn,
            region=region,
        )
        logs_client = session.client("logs")

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(
            minutes=minutes
        )

        request: dict[str, Any] = {
            "logGroupName": log_group,
            "startTime": int(
                start_time.timestamp() * 1000
            ),
            "endTime": int(
                end_time.timestamp() * 1000
            ),
            "limit": min(max_events, 10_000),
        }

        if filter_pattern.strip():
            request["filterPattern"] = (
                filter_pattern.strip()
            )

        messages: list[str] = []
        next_token: str | None = None

        while len(messages) < max_events:
            if next_token:
                request["nextToken"] = next_token
            else:
                request.pop("nextToken", None)

            response = logs_client.filter_log_events(
                **request
            )

            for event in response.get("events", []):
                timestamp_ms = event.get("timestamp", 0)

                timestamp = datetime.fromtimestamp(
                    timestamp_ms / 1000,
                    tz=timezone.utc,
                ).isoformat()

                stream_name = event.get(
                    "logStreamName",
                    "unknown-stream",
                )
                message = str(
                    event.get("message", "")
                ).strip()

                if message:
                    messages.append(
                        f"{timestamp} "
                        f"[{stream_name}] "
                        f"{message}"
                    )

                if len(messages) >= max_events:
                    break

            new_token = response.get("nextToken")

            if (
                not new_token
                or new_token == next_token
                or len(messages) >= max_events
            ):
                break

            next_token = new_token

        if not messages:
            return (
                "",
                (
                    "No CloudWatch log events were found in "
                    f"{log_group} for the last {minutes} minutes."
                ),
            )

        return (
            "\n".join(messages),
            (
                f"Fetched {len(messages)} CloudWatch log "
                f"event(s) from {log_group}."
            ),
        )

    except (
        ClientError,
        BotoCoreError,
        NoCredentialsError,
        PartialCredentialsError,
    ) as exc:
        return "", _format_aws_error(
            "fetching CloudWatch logs",
            exc,
        )

    except Exception as exc:
        return "", _format_aws_error(
            "fetching CloudWatch logs",
            exc,
        )


def fetch_cloudtrail_events(
    role_arn: str | None = None,
    region: str | None = None,
    hours: int = 24,
    max_events: int = 500,
) -> tuple[str, str]:
    """
    Fetch recent CloudTrail management events.

    The returned events are converted into newline-separated JSON,
    allowing log_parser.py to detect AccessDenied,
    UnauthorizedOperation, destructive API calls, IAM changes, etc.
    """

    try:
        if hours <= 0:
            return (
                "",
                "Error: CloudTrail time range must be greater than zero.",
            )

        session = _get_session(
            role_arn=role_arn,
            region=region,
        )
        cloudtrail_client = session.client(
            "cloudtrail"
        )

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(
            hours=hours
        )

        events: list[str] = []
        next_token: str | None = None

        while len(events) < max_events:
            request: dict[str, Any] = {
                "StartTime": start_time,
                "EndTime": end_time,
                "MaxResults": 50,
            }

            if next_token:
                request["NextToken"] = next_token

            response = cloudtrail_client.lookup_events(
                **request
            )

            for event in response.get("Events", []):
                raw_event = event.get(
                    "CloudTrailEvent",
                    "{}",
                )

                try:
                    parsed_event = json.loads(raw_event)
                except (
                    json.JSONDecodeError,
                    TypeError,
                ):
                    parsed_event = {
                        "rawEvent": str(raw_event)
                    }

                normalized_event = {
                    "timestamp": (
                        event["EventTime"].isoformat()
                        if event.get("EventTime")
                        else ""
                    ),
                    "eventId": event.get("EventId"),
                    "eventName": event.get("EventName"),
                    "eventSource": event.get(
                        "EventSource"
                    ),
                    "username": event.get("Username"),
                    "sourceIPAddress": parsed_event.get(
                        "sourceIPAddress"
                    ),
                    "userAgent": parsed_event.get(
                        "userAgent"
                    ),
                    "errorCode": parsed_event.get(
                        "errorCode"
                    ),
                    "errorMessage": parsed_event.get(
                        "errorMessage"
                    ),
                    "awsRegion": parsed_event.get(
                        "awsRegion"
                    ),
                    "resources": event.get(
                        "Resources",
                        [],
                    ),
                    "requestParameters": parsed_event.get(
                        "requestParameters"
                    ),
                    "responseElements": parsed_event.get(
                        "responseElements"
                    ),
                    "userIdentity": parsed_event.get(
                        "userIdentity"
                    ),
                }

                events.append(
                    json.dumps(
                        normalized_event,
                        default=str,
                        ensure_ascii=False,
                    )
                )

                if len(events) >= max_events:
                    break

            next_token = response.get("NextToken")

            if (
                not next_token
                or len(events) >= max_events
            ):
                break

            # CloudTrail LookupEvents has a low request-rate limit.
            time.sleep(0.6)

        if not events:
            return (
                "",
                (
                    "No CloudTrail events were found for "
                    f"the last {hours} hour(s)."
                ),
            )

        return (
            "\n".join(events),
            (
                f"Fetched {len(events)} CloudTrail event(s) "
                f"for the last {hours} hour(s)."
            ),
        )

    except (
        ClientError,
        BotoCoreError,
        NoCredentialsError,
        PartialCredentialsError,
    ) as exc:
        return "", _format_aws_error(
            "fetching CloudTrail events",
            exc,
        )

    except Exception as exc:
        return "", _format_aws_error(
            "fetching CloudTrail events",
            exc,
        )