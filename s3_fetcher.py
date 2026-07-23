import boto3
from botocore.exceptions import NoCredentialsError, ClientError

def list_s3_buckets(region_name="us-east-1"):
    """
    Lists available S3 buckets using credentials in environment variables or session.
    """
    try:
        s3 = boto3.client('s3', region_name=region_name)
        response = s3.list_buckets()
        buckets = [bucket['Name'] for bucket in response.get('Buckets', [])]
        return buckets, None
    except Exception as e:
        return [], str(e)

def fetch_latest_s3_log(bucket_name, prefix="", region_name="us-east-1"):
    """
    Finds and fetches the newest log file uploaded to the specified S3 bucket.
    """
    try:
        s3 = boto3.client('s3', region_name=region_name)
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
        return "", "AWS credentials missing. Ensure environment variables are set."
    except ClientError as e:
        return "", f"AWS Error: {e.response['Error']['Message']}"
    except Exception as e:
        return "", f"Error: {str(e)}"