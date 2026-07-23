import os
import boto3
from botocore.exceptions import NoCredentialsError, ClientError

def create_memory_only_s3_client(region_name="us-east-1"):
    """
    Creates an S3 client strictly using environment variables in memory.
    Fails immediately if no environment variables are present instead of 
    falling back to hidden local files (~/.aws/credentials).
    """
    access_key = os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    session_token = os.getenv("AWS_SESSION_TOKEN") # Optional for temporary STS keys

    # Strictly check that memory variables exist
    if not access_key or not secret_key:
        raise NoCredentialsError()

    # Pass memory variables directly into an isolated Session
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region_name
    )
    
    return session.client("s3")


def list_s3_buckets(region_name="us-east-1"):
    """
    Lists available S3 buckets using ONLY memory credentials.
    """
    try:
        s3 = create_memory_only_s3_client(region_name=region_name)
        response = s3.list_buckets()
        buckets = [bucket['Name'] for bucket in response.get('Buckets', [])]
        return buckets, None
    except NoCredentialsError:
        return [], "⛔ Security Error: Missing memory credentials. Please export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in your active terminal."
    except Exception as e:
        return [], str(e)


def fetch_latest_s3_log(bucket_name, prefix="", region_name="us-east-1"):
    """
    Fetches the newest log file uploaded to S3 using ONLY memory credentials.
    """
    try:
        s3 = create_memory_only_s3_client(region_name=region_name)
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        
        if 'Contents' not in response or len(response['Contents']) == 0:
            return "", "No log files found in the specified S3 bucket or prefix."
        
        # Sort files by last modified date (newest first)
        sorted_objects = sorted(
            response['Contents'], 
            key=lambda x: x['LastModified'], 
            reverse=True
        )
        
        latest_file_key = sorted_objects[0]['Key']
        obj = s3.get_object(Bucket=bucket_name, Key=latest_file_key)
        file_content = obj['Body'].read().decode('utf-8', errors='ignore')
        
        return file_content, f"Fetched latest log: {latest_file_key}"
        
    except NoCredentialsError:
        return "", "⛔ Security Error: Missing memory credentials. Please export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in your active terminal."
    except ClientError as e:
        return "", f"AWS Error: {e.response['Error']['Message']}"
    except Exception as e:
        return "", f"Error: {str(e)}"