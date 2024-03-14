"""
S3 Sentinel
-----------
S3 Bucket Security Scanner

This script scans all S3 buckets in an AWS account and outputs the results in a JSON file.
The JSON file is named `buckets.json`.

Usage:
    python s3_bucket_scanner.py [-p <AWS_PROFILE> ] [-a <AWS_ACCESS_KEY_ID> -s <AWS_SECRET_ACCESS_KEY> [-t <AWS_SESSION_TOKEN>]] [-m <MAX_OBJECTS>]
"""

# Ignoring Line too Long / Local Variable Count
# pylint: disable=C0301,R0914

import json
import sys
import boto3
import argparse
import logging
from botocore.exceptions import ClientError, NoCredentialsError


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


def get_bucket_status(s3_client, bucket_name):
    """
    Determine the public access status of the bucket based on policy, ACL, and public access block.

    This function assesses the bucket's policy, ACL, and public access block configuration
    to determine the overall public access status. It provides a descriptive status indicating
    whether the bucket and its objects are publicly accessible or not.

    Parameters:
        s3_client (boto3.client): An authenticated S3 client.
        bucket_name (str): The name of the S3 bucket to check.

    Returns:
        str: A descriptive status of the bucket's public access. Possible returns include
             "Objects can be public", "Bucket and objects not public", or "Unknown" (an error has occurred).
    """
    try:
        policy = s3_client.get_bucket_policy(Bucket=bucket_name).get("Policy")
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)[
            "PublicAccessBlockConfiguration"
        ]

        policy_public = is_policy_public(policy)
        acl_public = is_acl_public(acl)
        block_public_access = any(public_access_block.values())

        if block_public_access:
            return "Bucket and objects not public"
        if policy_public or acl_public:
            return "Objects can be public"
        return "Bucket and objects not public"
    except:
        return "Unknown"


def is_acl_public(bucket_acl):
    """
    Check if the ACL indicates the bucket or objects are publicly accessible.

    This function iterates over the ACL grants. If any grant allows access to 'AllUsers',
    it considers the ACL as publicly accessible.

    Parameters:
        bucket_acl (dict): The Access Control List configuration of the bucket.

    Returns:
        bool: True if the ACL allows public access or errors, False otherwise.
    """
    try:
        for grant in bucket_acl.get("Grants"):
            grantee = grant.get("Grantee")
            # Check if grantee is public
            if grantee.get("Type") == "Group" and "AllUsers" in grantee.get("URI", ""):
                return True  # ACL is public if any grant is to AllUsers
        return False  # ACL is not public
    except:
        return True  # In case of error, assume ACL is public for safety


def is_policy_public(bucket_policy):
    """
    Parse the bucket policy to determine if it allows public access.

    This function checks each statement in the policy. If it finds any statements that
    allow 's3:GetObject' to the public ('Principal': '*'), it considers the policy as allowing public access.

    Parameters:
        bucket_policy (str): A JSON string of the bucket policy.

    Returns:
        bool: True if the policy allows public access, False otherwise.
    """
    try:
        policy_dict = json.loads(bucket_policy)
        for statement in policy_dict.get("Statement", []):
            if statement.get("Effect") == "Allow" and "s3:GetObject" in statement.get(
                "Action", []
            ):
                principal = statement.get("Principal", {})
                if principal == "*" or "AWS" in principal:
                    return True
    except json.JSONDecodeError:
        pass
    return False


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
    except Exception as e:
        logger.error(f"Error getting policy for bucket {bucket_name}: {e}")
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
        return s3_client.get_bucket_policy(Bucket=bucket_name).get("Policy")
    except s3_client.exceptions.from_code("NoSuchBucketPolicy"):
        # The bucket doesn't have a policy, no err needed, just return None.
        return None
    except Exception as e:
        logger.error(f"Error getting policy for bucket {bucket_name}: {e}")
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
    tuple: A tuple containing three elements:
        - total_objects (int): The total number of objects scanned in the bucket.
        - public_objects (list): A list of keys (str) representing objects that are publicly accessible.
        - bool: A boolean value indicating whether the object scan exceeded the specified threshold.
    """
    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        object_count = 0
        public_objects = []
        total_objects = sum(
            1 for _ in paginator.paginate(Bucket=bucket_name).search("Contents")
        )

        for page in paginator.paginate(Bucket=bucket_name):
            if "Contents" not in page:
                continue
            for obj in page["Contents"]:
                object_count += 1
                if object_count > threshold > -1:  # We can use -1 to not set a limit.
                    return total_objects, public_objects, True
                object_acl = s3_client.get_object_acl(
                    Bucket=bucket_name, Key=obj.get("Key")
                )
                if is_acl_public(object_acl):
                    public_objects.append(obj.get("Key"))
        return total_objects, public_objects, False
    except Exception as e:
        logger.error(f"Error listing objects in bucket {bucket_name}: {e}")
        return "Unknown", [], False


def scan_buckets(s3_client, max_objects):
    """
    Scan all buckets in the AWS account and assess their public access status.

    This function iterates through all the S3 buckets in the AWS account linked to the provided S3 client.
    It evaluates each bucket's public access status based on its policy, ACL, and public access block settings.
    Additionally, it scans the objects within each bucket to check their public accessibility,
    up to the specified threshold.

    Parameters:
        s3_client (boto3.session.client): An authenticated S3 client used to access bucket details.
        max_objects (int): The maximum number of objects to scan in each bucket for public accessibility.
                                If set to -1, there is no limit on the number of objects scanned.

    Outputs:
        buckets.json: A JSON file where each key is a bucket name and the value is its public access status and
              other relevant security information. If object scanning is performed, details of object-level
              public access are included.
    """
    results = {}
    try:
        buckets = s3_client.list_buckets().get("Buckets")
        logger.info(f"There is {len(buckets)} bucket(s) in this account.")
        for index, bucket in enumerate(buckets):
            bucket_name = bucket.get("Name")
            acl = get_bucket_acl(s3_client, bucket_name)
            policy = get_bucket_policy(s3_client, bucket_name)
            try:
                public_access_block = s3_client.get_public_access_block(
                    Bucket=bucket_name
                )
                access_block_set = public_access_block.get("BlockPublicAcls", False)
            except Exception:
                access_block_set = "Unknown"
            bucket_status = get_bucket_status(s3_client, bucket_name)
            versioning_enabled = (
                s3_client.get_bucket_versioning(Bucket=bucket_name).get("Status")
                or "Never Enabled"
            )
            is_public_acl = is_acl_public(acl) if acl else False
            is_public_policy = is_policy_public(policy) if policy else False
            total_objects, public_objects, exceeded_threshold = list_bucket_objects(
                s3_client, bucket_name, max_objects
            )
            results[bucket_name] = {
                "bucket_status": bucket_status,
                "total_objects": total_objects,
                "max_objects_scanned": max_objects,
                "total_public_objects": len(public_objects),
                "public_objects": public_objects,
                "public_via_acl": is_public_acl,
                "public_via_policy": is_public_policy,
                "versioning": versioning_enabled,
                "access_block": access_block_set,
            }
            logger.info(
                f"[{index + 1} / {len(buckets)}] Bucket: {bucket_name}\n"
                f"\t- Bucket Status: {bucket_status}\n"
                f"\t- Public via ACL: {is_public_acl}\n"
                f"\t- Public via Policy: {is_public_policy}\n"
                f"\t- Access Block Set: {access_block_set}\n"
                f"\t- Versioning: {versioning_enabled}\n"
                f"\t- Exceeded Object Threshold: {exceeded_threshold} ({total_objects}/{max_objects})\n"
                f"\t- Public Objects: {len(public_objects)}"
            )
            for obj in public_objects:
                logger.info(f"\t\t- {obj}")

        with open("buckets.json", "w", encoding="UTF-8") as file:
            json.dump(results, file, indent=4)
    except Exception as e:
        logger.error(f"Error scanning buckets: {e}")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p",
        "--profile",
        type=str,
        help="The AWS profile name to use",
        required=False,
        default="default",
    )
    parser.add_argument(
        "-a",
        "--access-key-id",
        type=str,
        help="The AWS Access Key ID to use",
        required=False,
    )
    parser.add_argument(
        "-s",
        "--secret-access-key",
        type=str,
        help="The AWS Secret Access Key to use",
        required=False,
    )
    parser.add_argument(
        "-t",
        "--session-token",
        type=str,
        help="The AWS Session Token to use",
        required=False,
    )
    parser.add_argument(
        "-m",
        "--max-objects",
        type=int,
        help="Maximum number of objects to scan per bucket. Enter -1 for infinite",
        required=False,
        default=400,
    )
    parser.add_argument(
        "-r",
        "--region",
        type=str,
        help="AWS Region to use",
        required=False,
        default="eu-west-2",
    )
    args = parser.parse_args()
    return args


def authenticate(args):
    if args.access_key_id:
        session = boto3.Session(
            aws_access_key_id=args.access_key_id,
            aws_secret_access_key=args.secret_access_key,
            aws_session_token=args.session_token,
            region_name=args.region,
        )
    elif args.profile:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    return session.client("s3")


def main():
    try:
        args = parse_args()
        s3_client = authenticate(args)
        scan_buckets(s3_client, args.max_objects)
    except Exception as e:
        logger.error(e)
    finally:
        logger.info('Please see file "buckets.json" to view the details of the scan')


if __name__ == "__main__":
    main()
