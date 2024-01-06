'''
S3 Sentinel
-----------
S3 Bucket Security Scanner

This script scans all S3 buckets in an AWS account and outputs the results in a JSON file.
The JSON file is named after the AWS account ID.

Usage:
    python s3_bucket_scanner.py <AWS_ACCESS_KEY_ID> <AWS_SECRET_ACCESS_KEY> [<AWS_SESSION_TOKEN>]
'''
# pylint: disable=C0301

import json
import sys
import boto3
from botocore.exceptions import ClientError

# Maximum number of objects to scan per bucket.
#   -1 = No limit, but may take longer.
MAX_OBJECTS = 400

def create_s3_client(aws_access_key, aws_secret_key, aws_session_token):
    """
    Create an authenticated S3 client using the provided AWS credentials.

    Parameters:
        aws_access_key_id (str): AWS Access Key ID
        aws_secret_access_key (str): AWS Secret Access Key
        aws_session_token (str): AWS Session Token, optional

    Returns:
        boto3.client: Authenticated S3 client
    """
    return boto3.client(
        's3',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        aws_session_token=aws_session_token
    )

def is_bucket_public(bucket_acl):
    """
    Check if the S3 bucket is publicly accessible based on its ACL.

    Parameters:
        s3_client (boto3.client): Authenticated S3 client
        bucket_name (str): Name of the S3 bucket

    Returns:
        bool: True if the bucket is public, False otherwise
    """
    try:
        for grant in bucket_acl['Grants']:
            grantee = grant['Grantee']
            # Check if grantee is public
            if grantee['Type'] == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                return True  # Bucket is public if any grant is to AllUsers
        return False  # Bucket is not public
    except ClientError as e:
        return False  # In case of error, assume bucket is not public for safety

def is_policy_public(bucket_policy):
    """
    Determine if the S3 bucket policy allows public access.

    Parameters:
        bucket_policy (str): The JSON string of the bucket policy

    Returns:
        bool: True if the bucket policy allows public access, False otherwise
    """
    policy_statements = json.loads(bucket_policy).get('Statement', [])
    return any(
        statement.get('Effect') == 'Allow' and statement.get('Principal') == '*'
        for statement in policy_statements
    )

def get_bucket_acl(s3_client, bucket_name):
    """
    Retrieve the access control list (ACL) of an S3 bucket.

    Parameters:
        s3_client (boto3.client): Authenticated S3 client
        bucket_name (str): Name of the S3 bucket

    Returns:
        dict: ACL configuration of the bucket or None if an error occurs
    """
    try:
        return s3_client.get_bucket_acl(Bucket=bucket_name)
    except ClientError as e:
        print(f"Error getting policy for bucket {bucket_name}: {e}")
        return None

def get_bucket_policy(s3_client, bucket_name):
    """
    Retrieve the policy of an S3 bucket.

    Parameters:
        s3_client (boto3.client): Authenticated S3 client
        bucket_name (str): Name of the S3 bucket

    Returns:
        str: Policy of the bucket as a JSON string, or None if an error occurs or no policy is set
    """
    try:
        return s3_client.get_bucket_policy(Bucket=bucket_name)['Policy']
    except s3_client.exceptions.from_code('NoSuchBucketPolicy'):
        # The bucket doesn't have a policy, no err needed, just return None.
        return None
    except ClientError as e:
        print(f"Error getting policy for bucket {bucket_name}: {e}")
        return None

def list_bucket_objects(s3_client, bucket_name, threshold):
    """
    List objects in the specified S3 bucket up to the given threshold and
    determine their public accessibility.

    This function paginates through the objects in the bucket, checking the ACL
    for each object to see if it is publicly accessible. The process stops if
    the number of objects exceeds the specified threshold.

    Parameters:
        s3_client (boto3.client): Authenticated S3 client
        bucket_name (str): Name of the S3 bucket to scan
        threshold (int): Maximum number of objects to scan in the bucket

    Returns:
        tuple:
            - list of public object keys (list)
            - boolean indicating if the threshold was exceeded (bool)
    """
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        object_count = 0
        public_objects = []
        total_objects = sum(1 for _ in paginator.paginate(Bucket=bucket_name).search('Contents'))

        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' not in page:
                continue
            for obj in page['Contents']:
                object_count += 1
                if object_count > threshold > -1: # We can use -1 to not set a limit.
                    return total_objects, public_objects, True
                object_acl = s3_client.get_object_acl(Bucket=bucket_name, Key=obj['Key'])
                if is_bucket_public(object_acl):
                    public_objects.append(obj['Key'])
        return total_objects, public_objects, False
    except ClientError as e:
        print(f"Error listing objects in bucket {bucket_name}: {e}")
        return 'Unknown', [], False

def scan_buckets(s3_client, object_threshold):
    """
    Scan all buckets and save results in a JSON file named buckets.json.

    Parameters:
        s3_client (boto3.client): Authenticated S3 client
    """
    results = {}
    try:
        buckets = s3_client.list_buckets()['Buckets']
        print(f"[!] There are {len(buckets)} buckets in this account.")
        for index, bucket in enumerate(buckets):
            bucket_name = bucket['Name']
            acl = get_bucket_acl(s3_client, bucket_name)
            policy = get_bucket_policy(s3_client, bucket_name)

            is_public_acl = is_bucket_public(acl) if acl else False
            is_public_policy = is_policy_public(policy) if policy else False
            total_objects, public_objects, exceeded_threshold = list_bucket_objects(s3_client,
                                                                                    bucket_name,
                                                                                    object_threshold)

            bucket_info = {
                'total_objects': total_objects,
                'max_objects_scanned': MAX_OBJECTS,
                'total_public_objects': len(public_objects),
                'public_objects': public_objects,
                'public_via_acl': is_public_acl,
                'public_via_policy': is_public_policy
            }
            results[bucket_name] = bucket_info

            print(
                f"[{index + 1} / {len(buckets)}] Bucket: {bucket_name}\n"
                f"\t- Public via ACL: {is_public_acl}\n"
                f"\t- Public via Policy: {is_public_policy}\n"
                f"\t- Exceeded Object Threshold: {exceeded_threshold} ({total_objects}/{MAX_OBJECTS})\n"
                f"\t- Public Objects: {len(public_objects)}")
            for obj in public_objects:
                print(f"\t\t- {obj}")
                
        with open("buckets.json", "w") as file:
            json.dump(results, file, indent=4)
    except ClientError as e:
        print(f"Error scanning buckets: {e}")

def main():
    """
    Main function to execute the script logic.
    """
    if len(sys.argv) < 3:
        print("Usage: python s3_sentinel.py <AWS_ACCESS_KEY_ID> <AWS_SECRET_ACCESS_KEY> [<AWS_SESSION_TOKEN>]")
        sys.exit(1)
    try:
        s3_client = create_s3_client(sys.argv[1],
                                     sys.argv[2],
                                     sys.argv[3] if len(sys.argv) > 3 else None)
    except ClientError as e:
        print(f"Failed to authenticate with provided AWS Credentials: {e}")
        sys.exit(1)
    scan_buckets(s3_client, MAX_OBJECTS)

if __name__ == '__main__':
    main()
