import boto3
from datetime import datetime, timezone


# ============================================================
# CONFIGURATION
# ============================================================

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP"
}

STALE_ACCESS_KEY_DAYS = 90


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def create_finding(severity, service, resource, issue, remediation):
    return {
        "severity": severity,
        "service": service,
        "resource": resource,
        "issue": issue,
        "remediation": remediation
    }


# ============================================================
# CHECK 1 - SECURITY GROUP EXPOSURE
# ============================================================

def check_security_groups():
    print("Checking Security Groups...")

    findings = []

    try:
        ec2 = boto3.client("ec2")

        paginator = ec2.get_paginator("describe_security_groups")

        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):

                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "N/A")

                for permission in sg.get("IpPermissions", []):

                    from_port = permission.get("FromPort")
                    to_port = permission.get("ToPort")

                    if from_port is None or to_port is None:
                        continue

                    # IPv4 checks
                    for ip_range in permission.get("IpRanges", []):

                        cidr = ip_range.get("CidrIp")

                        if cidr != "0.0.0.0/0":
                            continue

                        for port, service in SENSITIVE_PORTS.items():

                            if from_port <= port <= to_port:
                                findings.append(
                                    create_finding(
                                        "CRITICAL",
                                        "EC2",
                                        f"{sg_id} ({sg_name})",
                                        f"{service} port {port} is exposed to 0.0.0.0/0",
                                        "Restrict inbound access to trusted IP ranges or private connectivity."
                                    )
                                )

                    # IPv6 checks
                    for ipv6_range in permission.get("Ipv6Ranges", []):

                        cidr = ipv6_range.get("CidrIpv6")

                        if cidr != "::/0":
                            continue

                        for port, service in SENSITIVE_PORTS.items():

                            if from_port <= port <= to_port:
                                findings.append(
                                    create_finding(
                                        "CRITICAL",
                                        "EC2",
                                        f"{sg_id} ({sg_name})",
                                        f"{service} port {port} is exposed to ::/0",
                                        "Restrict IPv6 inbound access to trusted networks."
                                    )
                                )

    except Exception as error:
        findings.append(
            create_finding(
                "ERROR",
                "EC2",
                "Security Groups",
                str(error),
                "Verify AWS credentials and EC2 read permissions."
            )
        )

    return findings


# ============================================================
# CHECK 2 - PUBLIC RDS
# ============================================================

def check_public_rds():
    print("Checking RDS instances...")

    findings = []

    try:
        rds = boto3.client("rds")

        paginator = rds.get_paginator("describe_db_instances")

        for page in paginator.paginate():
            for db in page.get("DBInstances", []):

                if db.get("PubliclyAccessible", False):

                    findings.append(
                        create_finding(
                            "HIGH",
                            "RDS",
                            db["DBInstanceIdentifier"],
                            "Database is configured as publicly accessible.",
                            "Place the database in private subnets and disable public accessibility unless explicitly required."
                        )
                    )

    except Exception as error:
        findings.append(
            create_finding(
                "ERROR",
                "RDS",
                "RDS Assessment",
                str(error),
                "Verify RDS read permissions."
            )
        )

    return findings


# ============================================================
# CHECK 3 - S3 PUBLIC ACCESS BLOCK
# ============================================================

def check_s3_public_access():
    print("Checking S3 buckets...")

    findings = []

    try:
        s3 = boto3.client("s3")

        response = s3.list_buckets()

        for bucket in response.get("Buckets", []):

            bucket_name = bucket["Name"]

            try:
                response = s3.get_public_access_block(
                    Bucket=bucket_name
                )

                config = response[
                    "PublicAccessBlockConfiguration"
                ]

                risky_settings = []

                if not config.get("BlockPublicAcls", False):
                    risky_settings.append(
                        "BlockPublicAcls=False"
                    )

                if not config.get("IgnorePublicAcls", False):
                    risky_settings.append(
                        "IgnorePublicAcls=False"
                    )

                if not config.get("BlockPublicPolicy", False):
                    risky_settings.append(
                        "BlockPublicPolicy=False"
                    )

                if not config.get(
                    "RestrictPublicBuckets",
                    False
                ):
                    risky_settings.append(
                        "RestrictPublicBuckets=False"
                    )

                if risky_settings:

                    findings.append(
                        create_finding(
                            "REVIEW",
                            "S3",
                            bucket_name,
                            ", ".join(risky_settings),
                            "Confirm whether public access is intentionally required. Prefer private S3 access through CloudFront OAC where possible."
                        )
                    )

            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:

                findings.append(
                    create_finding(
                        "REVIEW",
                        "S3",
                        bucket_name,
                        "No Public Access Block configuration found.",
                        "Review the bucket policy and enable S3 Public Access Block unless public access is intentionally required."
                    )
                )

            except Exception as error:

                findings.append(
                    create_finding(
                        "ERROR",
                        "S3",
                        bucket_name,
                        str(error),
                        "Verify permission to inspect this bucket."
                    )
                )

    except Exception as error:

        findings.append(
            create_finding(
                "ERROR",
                "S3",
                "S3 Assessment",
                str(error),
                "Verify S3 read permissions."
            )
        )

    return findings


# ============================================================
# CHECK 4 - IAM USERS WITHOUT MFA
# ============================================================

def check_iam_mfa():
    print("Checking IAM MFA...")

    findings = []

    try:
        iam = boto3.client("iam")

        paginator = iam.get_paginator("list_users")

        for page in paginator.paginate():

            for user in page.get("Users", []):

                username = user["UserName"]

                mfa_devices = iam.list_mfa_devices(
                    UserName=username
                )

                if not mfa_devices.get("MFADevices"):

                    findings.append(
                        create_finding(
                            "HIGH",
                            "IAM",
                            username,
                            "IAM user does not have MFA configured.",
                            "Enable MFA or migrate human access to centralized identity/SSO."
                        )
                    )

    except Exception as error:

        findings.append(
            create_finding(
                "ERROR",
                "IAM",
                "MFA Assessment",
                str(error),
                "Verify IAM read permissions."
            )
        )

    return findings


# ============================================================
# CHECK 5 - STALE IAM ACCESS KEYS
# ============================================================

def check_stale_access_keys():
    print("Checking IAM access keys...")

    findings = []

    try:
        iam = boto3.client("iam")

        paginator = iam.get_paginator("list_users")

        now = datetime.now(timezone.utc)

        for page in paginator.paginate():

            for user in page.get("Users", []):

                username = user["UserName"]

                keys = iam.list_access_keys(
                    UserName=username
                )

                for key in keys.get(
                    "AccessKeyMetadata",
                    []
                ):

                    create_date = key["CreateDate"]

                    age = (
                        now - create_date
                    ).days

                    if (
                        key.get("Status") == "Active"
                        and age > STALE_ACCESS_KEY_DAYS
                    ):

                        findings.append(
                            create_finding(
                                "MEDIUM",
                                "IAM",
                                username,
                                f"Active access key is {age} days old.",
                                "Review whether the key is still required. Prefer temporary credentials and rotate or remove unnecessary long-lived keys."
                            )
                        )

    except Exception as error:

        findings.append(
            create_finding(
                "ERROR",
                "IAM",
                "Access Key Assessment",
                str(error),
                "Verify IAM read permissions."
            )
        )

    return findings


# ============================================================
# CHECK 6 - UNENCRYPTED EBS VOLUMES
# ============================================================

def check_ebs_encryption():
    print("Checking EBS encryption...")

    findings = []

    try:
        ec2 = boto3.client("ec2")

        paginator = ec2.get_paginator(
            "describe_volumes"
        )

        for page in paginator.paginate():

            for volume in page.get("Volumes", []):

                volume_id = volume["VolumeId"]

                if not volume.get(
                    "Encrypted",
                    False
                ):

                    findings.append(
                        create_finding(
                            "HIGH",
                            "EBS",
                            volume_id,
                            "EBS volume is not encrypted.",
                            "Migrate data to an encrypted EBS volume using AWS KMS."
                        )
                    )

    except Exception as error:

        findings.append(
            create_finding(
                "ERROR",
                "EBS",
                "EBS Assessment",
                str(error),
                "Verify EC2 volume read permissions."
            )
        )

    return findings


# ============================================================
# CHECK 7 - CLOUDTRAIL LOGGING
# ============================================================

def check_cloudtrail():
    print("Checking CloudTrail...")

    findings = []

    try:
        cloudtrail = boto3.client(
            "cloudtrail"
        )

        response = cloudtrail.describe_trails(
            includeShadowTrails=False
        )

        trails = response.get(
            "trailList",
            []
        )

        if not trails:

            findings.append(
                create_finding(
                    "HIGH",
                    "CloudTrail",
                    "AWS Account",
                    "No CloudTrail trail was detected.",
                    "Configure CloudTrail to record AWS API activity."
                )
            )

            return findings

        active_trail_found = False

        for trail in trails:

            trail_name = trail[
                "Name"
            ]

            try:

                status = (
                    cloudtrail.get_trail_status(
                        Name=trail_name
                    )
                )

                if status.get(
                    "IsLogging",
                    False
                ):
                    active_trail_found = True

                else:

                    findings.append(
                        create_finding(
                            "HIGH",
                            "CloudTrail",
                            trail_name,
                            "CloudTrail exists but logging is disabled.",
                            "Enable CloudTrail logging."
                        )
                    )

            except Exception as error:

                findings.append(
                    create_finding(
                        "ERROR",
                        "CloudTrail",
                        trail_name,
                        str(error),
                        "Verify CloudTrail read permissions."
                    )
                )

        if active_trail_found:
            pass

    except Exception as error:

        findings.append(
            create_finding(
                "ERROR",
                "CloudTrail",
                "CloudTrail Assessment",
                str(error),
                "Verify CloudTrail read permissions."
            )
        )

    return findings


# ============================================================
# REPORTING
# ============================================================

def print_section(
    title,
    findings,
    pass_message
):

    print("\n" + title)
    print("-" * 70)

    if not findings:

        print(
            f"[PASS] {pass_message}"
        )

        return

    for finding in findings:

        print(
            f"\n[{finding['severity']}] "
            f"{finding['service']} | "
            f"{finding['resource']}"
        )

        print(
            f"Issue: {finding['issue']}"
        )

        print(
            f"Remediation: "
            f"{finding['remediation']}"
        )


def print_report(results):

    print(
        "\n" + "=" * 70
    )

    print(
        "AWS SECURITY POSTURE SCANNER"
    )

    print(
        "=" * 70
    )

    print_section(
        "SECURITY GROUP CHECKS",
        results["security_groups"],
        "No public SSH/RDP exposure detected."
    )

    print_section(
        "RDS CHECKS",
        results["rds"],
        "No publicly accessible RDS instances detected."
    )

    print_section(
        "S3 CHECKS",
        results["s3"],
        "Public Access Block posture passed for all evaluated buckets."
    )

    print_section(
        "IAM MFA CHECKS",
        results["iam_mfa"],
        "All IAM users have MFA configured."
    )

    print_section(
        "IAM ACCESS KEY CHECKS",
        results["access_keys"],
        f"No active access keys older than {STALE_ACCESS_KEY_DAYS} days detected."
    )

    print_section(
        "EBS ENCRYPTION CHECKS",
        results["ebs"],
        "All EBS volumes are encrypted."
    )

    print_section(
        "CLOUDTRAIL CHECKS",
        results["cloudtrail"],
        "Active CloudTrail logging detected."
    )

    all_findings = []

    for result in results.values():
        all_findings.extend(result)

    security_findings = [
        finding
        for finding in all_findings
        if finding["severity"] != "ERROR"
    ]

    errors = [
        finding
        for finding in all_findings
        if finding["severity"] == "ERROR"
    ]

    print(
        "\n" + "=" * 70
    )

    print(
        "SCAN SUMMARY"
    )

    print(
        "=" * 70
    )

    print(
        f"Security findings: "
        f"{len(security_findings)}"
    )

    print(
        f"Assessment errors: "
        f"{len(errors)}"
    )

    print(
        "=" * 70
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print(
        "\nStarting AWS Security Posture Scan...\n"
    )

    results = {
        "security_groups":
            check_security_groups(),

        "rds":
            check_public_rds(),

        "s3":
            check_s3_public_access(),

        "iam_mfa":
            check_iam_mfa(),

        "access_keys":
            check_stale_access_keys(),

        "ebs":
            check_ebs_encryption(),

        "cloudtrail":
            check_cloudtrail()
    }

    print_report(results)