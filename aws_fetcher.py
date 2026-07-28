import boto3
from datetime import datetime, timedelta

# ==========================================
# 🆔 AWS ACCOUNT IDENTITY FETCHER
# ==========================================
def get_aws_account_info(region_name="us-east-1"):
    """
    Retrieves the active AWS Account ID and IAM User/Role ARN using STS.
    Returns (account_id, arn, error_message).
    """
    try:
        sts = boto3.client('sts', region_name=region_name)
        identity = sts.get_caller_identity()
        account_id = identity.get('Account', 'Unknown')
        arn = identity.get('Arn', 'Unknown')
        return account_id, arn, None
    except Exception as e:
        return None, None, str(e)


# ==========================================
# 🪣 AWS S3 LOG FETCHER
# ==========================================
def list_s3_buckets(region_name="us-east-1"):
    """
    Lists all available S3 buckets using active AWS credentials.
    Returns (buckets_list, error_message).
    """
    try:
        s3 = boto3.client('s3', region_name=region_name)
        response = s3.list_buckets()
        buckets = [b['Name'] for b in response.get('Buckets', [])]
        return buckets, None
    except Exception as e:
        return [], str(e)


def fetch_latest_s3_log(bucket_name, prefix="", region_name="us-east-1"):
    """
    Fetches the content of the most recently modified log file in an S3 bucket.
    Returns (file_content, status_message).
    """
    try:
        s3 = boto3.client('s3', region_name=region_name)
        
        kwargs = {'Bucket': bucket_name}
        if prefix.strip():
            kwargs['Prefix'] = prefix.strip()

        response = s3.list_objects_v2(**kwargs)
        contents = response.get('Contents', [])

        if not contents:
            return None, f"No files found in bucket '{bucket_name}' with prefix '{prefix}'."

        # Filter out folder markers and find the latest modified file
        files = [f for f in contents if not f['Key'].endswith('/')]
        if not files:
            return None, f"No valid log objects found in bucket '{bucket_name}'."

        latest_file = max(files, key=lambda x: x['LastModified'])
        file_key = latest_file['Key']

        # Fetch object contents
        obj = s3.get_object(Bucket=bucket_name, Key=file_key)
        file_content = obj['Body'].read().decode('utf-8')

        return file_content, f"Successfully fetched `{file_key}`"

    except Exception as e:
        return None, str(e)


# ==========================================
# 📈 AWS CLOUDWATCH LOGS FETCHER
# ==========================================
def fetch_cloudwatch_logs(log_group_name, log_stream_name=None, limit=200, region_name="us-east-1"):
    """
    Fetches the most recent log events from a CloudWatch Log Group.
    Returns (log_text, status_message).
    """
    try:
        client = boto3.client('logs', region_name=region_name)
        
        # If no specific stream is given, find the most recently active stream
        if not log_stream_name or not log_stream_name.strip():
            streams_resp = client.describe_log_streams(
                logGroupName=log_group_name,
                orderBy='LastEventTime',
                descending=True,
                limit=1
            )
            streams = streams_resp.get('logStreams', [])
            if not streams:
                return None, f"No active log streams found in group '{log_group_name}'."
            log_stream_name = streams[0]['logStreamName']

        # Fetch recent log events from the selected stream
        events_resp = client.get_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            limit=limit,
            startFromHead=False
        )
        
        events = events_resp.get('events', [])
        if not events:
            return None, f"No log events found in stream '{log_stream_name}'."

        # Combine log messages into a single text block
        log_text = "\n".join([e['message'] for e in events])
        return log_text, f"Successfully fetched {len(events)} events from stream `{log_stream_name}`"

    except Exception as e:
        return None, str(e)


# ==========================================
# 🛡️ AWS CLOUDTRAIL API EVENT FETCHER
# ==========================================
def fetch_cloudtrail_events(minutes_back=60, region_name="us-east-1"):
    """
    Fetches recent CloudTrail API events for security and operational auditing.
    Returns (log_text, status_message).
    """
    try:
        client = boto3.client('cloudtrail', region_name=region_name)
        start_time = datetime.utcnow() - timedelta(minutes=minutes_back)

        # Lookup recent events
        response = client.lookup_events(
            StartTime=start_time,
            MaxResults=50
        )
        
        events = response.get('Events', [])
        if not events:
            return None, "No CloudTrail events found in the specified time window."

        # Format CloudTrail events into structured readable log text
        trail_lines = []
        for ev in events:
            event_name = ev.get('EventName', 'UnknownEvent')
            user_name = ev.get('Username', 'UnknownUser')
            event_time = ev.get('EventTime', '')
            resource_name = ev.get('Resources', [{}])[0].get('ResourceName', 'N/A') if ev.get('Resources') else 'N/A'
            
            line = f"[{event_time}] Event: {event_name} | User: {user_name} | Resource: {resource_name}"
            trail_lines.append(line)

        log_text = "\n".join(trail_lines)
        return log_text, f"Successfully retrieved {len(events)} CloudTrail API events."

    except Exception as e:
        return None, str(e)