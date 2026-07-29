import os
import boto3
from botocore.exceptions import NoCredentialsError, ClientError

def create_aws_client(service_name, region_name="us-east-1", role_arn=None):
    """
    Creates an AWS client for the specified service.
    First attempts to use memory credentials (or default boto3 chain like SSO/Profiles).
    If role_arn is provided, it assumes the role to generate temporary credentials.
    """
    try:
        access_key = os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        session_token = os.getenv("AWS_SESSION_TOKEN") # Optional

        # Strictly check that memory variables exist
        if not access_key or not secret_key:
            raise NoCredentialsError()

        # Base session using strictly memory variables
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region_name
        )
        
        # If no role provided, return standard client
        if not role_arn:
            return session.client(service_name)
            
        # Assume Role if provided
        sts_client = session.client("sts")
        assumed_role_object = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AILogAnalyzerSession"
        )
        credentials = assumed_role_object['Credentials']
        
        # Create new session with assumed credentials
        assumed_session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region_name
        )
        return assumed_session.client(service_name)
        
    except ClientError as e:
        raise Exception(f"AWS Error: {e.response['Error']['Message']}")
    except NoCredentialsError:
        raise Exception("⛔ Security Error: Missing memory credentials. Please export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in your active terminal.")

# --- S3 Functions ---

def list_s3_buckets(region_name="us-east-1", role_arn=None):
    try:
        s3 = create_aws_client("s3", region_name, role_arn)
        response = s3.list_buckets()
        return [bucket['Name'] for bucket in response.get('Buckets', [])], None
    except Exception as e:
        return [], str(e)

def fetch_latest_s3_log(bucket_name, prefix="", region_name="us-east-1", role_arn=None):
    try:
        s3 = create_aws_client("s3", region_name, role_arn)
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        
        if 'Contents' not in response or len(response['Contents']) == 0:
            return "", "No log files found in the specified S3 bucket or prefix."
        
        sorted_objects = sorted(response['Contents'], key=lambda x: x['LastModified'], reverse=True)
        latest_file_key = sorted_objects[0]['Key']
        obj = s3.get_object(Bucket=bucket_name, Key=latest_file_key)
        return obj['Body'].read().decode('utf-8', errors='ignore'), f"Fetched latest log: {latest_file_key}"
        
    except Exception as e:
        return "", f"Error: {str(e)}"

# --- CloudWatch Functions ---

def fetch_cloudwatch_logs(log_group_name, limit=100, region_name="us-east-1", role_arn=None):
    try:
        logs_client = create_aws_client("logs", region_name, role_arn)
        # Using filter_log_events to just grab the latest streams from a log group
        # Real-world usage might need specific time filters, but we fetch the latest N events here
        response = logs_client.filter_log_events(
            logGroupName=log_group_name,
            limit=limit,
            interleaved=True
        )
        events = response.get('events', [])
        if not events:
            return "", f"No recent logs found in CloudWatch Log Group: {log_group_name}"
            
        log_text = "\n".join([e.get('message', '') for e in events])
        return log_text, f"Fetched {len(events)} logs from CloudWatch: {log_group_name}"
        
    except Exception as e:
        return "", f"Error: {str(e)}"

# --- CloudTrail Functions ---

def fetch_cloudtrail_events(limit=50, region_name="us-east-1", role_arn=None):
    try:
        trail_client = create_aws_client("cloudtrail", region_name, role_arn)
        response = trail_client.lookup_events(
            MaxResults=limit
        )
        events = response.get('Events', [])
        if not events:
            return "", "No recent events found in CloudTrail."
            
        log_lines = []
        for event in events:
            # We construct a readable string or dump JSON
            name = event.get('EventName', 'Unknown')
            user = event.get('Username', 'Unknown')
            time = str(event.get('EventTime', 'Unknown'))
            log_lines.append(f"{time} | User: {user} | API: {name} | CloudTrailEvent")
            
        return "\n".join(log_lines), f"Fetched {len(events)} CloudTrail events."
        
    except Exception as e:
        return "", f"Error: {str(e)}"
