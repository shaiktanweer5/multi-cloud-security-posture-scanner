import boto3
import json
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
# HELPER
# ============================================================

def create_finding(
    finding_id,
    severity,
    service,
    category,
    resource,
    issue,
    risk,
    remediation,
    status="OPEN"
):
    return {
        "id": finding_id,
        "severity": severity,
        "service": service,
        "category": category,
        "resource": resource,
        "issue": issue,
        "risk": risk,
        "remediation": remediation,
        "status": status
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

                    for ip_range in permission.get("IpRanges", []):

                        cidr = ip_range.get("CidrIp")

                        if cidr != "0.0.0.0/0":
                            continue

                        for port, service in SENSITIVE_PORTS.items():

                            if from_port <= port <= to_port:
                                findings.append(
                                    create_finding(
                                        "AWS-EC2-SG-001",
                                        "CRITICAL",
                                        "EC2",
                                        "Network Exposure",
                                        f"{sg_id} ({sg_name})",
                                        f"{service} port {port} is exposed to 0.0.0.0/0.",
                                        "Public exposure of management ports increases the risk of brute-force attempts and unauthorized access.",
                                        "Restrict inbound access to trusted IP ranges, VPN connectivity, bastion hosts, or private access."
                                    )
                                )

                    for ipv6_range in permission.get("Ipv6Ranges", []):

                        cidr = ipv6_range.get("CidrIpv6")

                        if cidr != "::/0":
                            continue

                        for port, service in SENSITIVE_PORTS.items():

                            if from_port <= port <= to_port:
                                findings.append(
                                    create_finding(
                                        "AWS-EC2-SG-002",
                                        "CRITICAL",
                                        "EC2",
                                        "Network Exposure",
                                        f"{sg_id} ({sg_name})",
                                        f"{service} port {port} is exposed to ::/0.",
                                        "Public IPv6 exposure of management ports increases the attack surface.",
                                        "Restrict IPv6 inbound access to trusted networks."
                                    )
                                )

    except Exception as error:
        findings.append(
            create_finding(
                "AWS-EC2-ERROR",
                "ERROR",
                "EC2",
                "Assessment Error",
                "Security Groups",
                str(error),
                "The scanner could not complete the Security Group assessment.",
                "Verify AWS credentials and EC2 read permissions.",
                "ERROR"
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
                            "AWS-RDS-001",
                            "HIGH",
                            "RDS",
                            "Public Exposure",
                            db["DBInstanceIdentifier"],
                            "Database is configured as publicly accessible.",
                            "A publicly accessible database may increase the risk of unauthorized access if network or authentication controls are weak.",
                            "Place the database in private subnets and disable public accessibility unless explicitly required."
                        )
                    )

    except Exception as error:
        findings.append(
            create_finding(
                "AWS-RDS-ERROR",
                "ERROR",
                "RDS",
                "Assessment Error",
                "RDS Assessment",
                str(error),
                "The scanner could not complete the RDS assessment.",
                "Verify RDS read permissions.",
                "ERROR"
            )
        )

    return findings


# ============================================================
# CHECK 3 - S3 PUBLIC ACCESS
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

                config = response["PublicAccessBlockConfiguration"]

                risky_settings = []

                if not config.get("BlockPublicAcls", False):
                    risky_settings.append("BlockPublicAcls=False")

                if not config.get("IgnorePublicAcls", False):
                    risky_settings.append("IgnorePublicAcls=False")

                if not config.get("BlockPublicPolicy", False):
                    risky_settings.append("BlockPublicPolicy=False")

                if not config.get("RestrictPublicBuckets", False):
                    risky_settings.append("RestrictPublicBuckets=False")

                if risky_settings:

                    findings.append(
                        create_finding(
                            "AWS-S3-PAB-001",
                            "REVIEW",
                            "S3",
                            "Public Access Configuration",
                            bucket_name,
                            ", ".join(risky_settings),
                            "These settings may permit public access depending on the bucket policy and intended architecture.",
                            "Confirm whether public access is intentionally required. Prefer private S3 access through CloudFront OAC where possible.",
                            "REVIEW_REQUIRED"
                        )
                    )

            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:

                findings.append(
                    create_finding(
                        "AWS-S3-PAB-002",
                        "REVIEW",
                        "S3",
                        "Public Access Configuration",
                        bucket_name,
                        "No Public Access Block configuration found.",
                        "The bucket may allow unintended public access depending on ACL and bucket policy configuration.",
                        "Review the bucket policy and enable Public Access Block unless public access is intentionally required.",
                        "REVIEW_REQUIRED"
                    )
                )

            except Exception as error:

                findings.append(
                    create_finding(
                        "AWS-S3-ERROR",
                        "ERROR",
                        "S3",
                        "Assessment Error",
                        bucket_name,
                        str(error),
                        "The scanner could not inspect this bucket.",
                        "Verify permission to inspect this S3 bucket.",
                        "ERROR"
                    )
                )

    except Exception as error:

        findings.append(
            create_finding(
                "AWS-S3-ERROR",
                "ERROR",
                "S3",
                "Assessment Error",
                "S3 Assessment",
                str(error),
                "The scanner could not complete the S3 assessment.",
                "Verify S3 read permissions.",
                "ERROR"
            )
        )

    return findings


# ============================================================
# CHECK 4 - IAM MFA
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
                            "AWS-IAM-MFA-001",
                            "HIGH",
                            "IAM",
                            "Identity Security",
                            username,
                            "IAM user does not have MFA configured.",
                            "A compromised password may allow account access without a second authentication factor.",
                            "Enable MFA or migrate human access to centralized identity federation or AWS IAM Identity Center."
                        )
                    )

    except Exception as error:

        findings.append(
            create_finding(
                "AWS-IAM-MFA-ERROR",
                "ERROR",
                "IAM",
                "Assessment Error",
                "MFA Assessment",
                str(error),
                "The scanner could not complete the IAM MFA assessment.",
                "Verify IAM read permissions.",
                "ERROR"
            )
        )

    return findings


# ============================================================
# CHECK 5 - STALE ACCESS KEYS
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

                for key in keys.get("AccessKeyMetadata", []):

                    create_date = key["CreateDate"]
                    age = (now - create_date).days

                    if (
                        key.get("Status") == "Active"
                        and age > STALE_ACCESS_KEY_DAYS
                    ):

                        findings.append(
                            create_finding(
                                "AWS-IAM-KEY-001",
                                "MEDIUM",
                                "IAM",
                                "Credential Hygiene",
                                username,
                                f"Active access key is {age} days old.",
                                "Long-lived credentials increase exposure if they are leaked, copied, or forgotten.",
                                "Review whether the key is still required. Rotate or remove unnecessary keys and prefer temporary credentials."
                            )
                        )

    except Exception as error:

        findings.append(
            create_finding(
                "AWS-IAM-KEY-ERROR",
                "ERROR",
                "IAM",
                "Assessment Error",
                "Access Key Assessment",
                str(error),
                "The scanner could not complete the IAM access key assessment.",
                "Verify IAM read permissions.",
                "ERROR"
            )
        )

    return findings


# ============================================================
# CHECK 6 - EBS ENCRYPTION
# ============================================================

def check_ebs_encryption():
    print("Checking EBS encryption...")

    findings = []

    try:
        ec2 = boto3.client("ec2")
        paginator = ec2.get_paginator("describe_volumes")

        for page in paginator.paginate():

            for volume in page.get("Volumes", []):

                volume_id = volume["VolumeId"]

                if not volume.get("Encrypted", False):

                    findings.append(
                        create_finding(
                            "AWS-EBS-001",
                            "HIGH",
                            "EBS",
                            "Data Protection",
                            volume_id,
                            "EBS volume is not encrypted.",
                            "Unencrypted storage may expose data if snapshots or underlying storage are improperly accessed.",
                            "Migrate data to an encrypted EBS volume using AWS KMS."
                        )
                    )

    except Exception as error:

        findings.append(
            create_finding(
                "AWS-EBS-ERROR",
                "ERROR",
                "EBS",
                "Assessment Error",
                "EBS Assessment",
                str(error),
                "The scanner could not complete the EBS encryption assessment.",
                "Verify EC2 volume read permissions.",
                "ERROR"
            )
        )

    return findings


# ============================================================
# CHECK 7 - CLOUDTRAIL
# ============================================================

def check_cloudtrail():
    print("Checking CloudTrail...")

    findings = []

    try:
        cloudtrail = boto3.client("cloudtrail")

        response = cloudtrail.describe_trails(
            includeShadowTrails=False
        )

        trails = response.get("trailList", [])

        if not trails:

            findings.append(
                create_finding(
                    "AWS-CT-001",
                    "HIGH",
                    "CloudTrail",
                    "Logging and Monitoring",
                    "AWS Account",
                    "No CloudTrail trail was detected.",
                    "Without CloudTrail, security teams may lack sufficient audit data for investigations and incident response.",
                    "Configure CloudTrail to record AWS API activity."
                )
            )

            return findings

        for trail in trails:

            trail_name = trail["Name"]

            try:
                status = cloudtrail.get_trail_status(
                    Name=trail_name
                )

                if not status.get("IsLogging", False):

                    findings.append(
                        create_finding(
                            "AWS-CT-002",
                            "HIGH",
                            "CloudTrail",
                            "Logging and Monitoring",
                            trail_name,
                            "CloudTrail exists but logging is disabled.",
                            "Disabled audit logging reduces visibility into AWS API activity and security events.",
                            "Enable CloudTrail logging."
                        )
                    )

            except Exception as error:

                findings.append(
                    create_finding(
                        "AWS-CT-ERROR",
                        "ERROR",
                        "CloudTrail",
                        "Assessment Error",
                        trail_name,
                        str(error),
                        "The scanner could not inspect this CloudTrail.",
                        "Verify CloudTrail read permissions.",
                        "ERROR"
                    )
                )

    except Exception as error:

        findings.append(
            create_finding(
                "AWS-CT-ERROR",
                "ERROR",
                "CloudTrail",
                "Assessment Error",
                "CloudTrail Assessment",
                str(error),
                "The scanner could not complete the CloudTrail assessment.",
                "Verify CloudTrail read permissions.",
                "ERROR"
            )
        )

    return findings


# ============================================================
# TERMINAL REPORT
# ============================================================

def print_section(title, findings, pass_message):

    print("\n" + title)
    print("-" * 70)

    if not findings:
        print(f"[PASS] {pass_message}")
        return

    for finding in findings:

        print(
            f"\n[{finding['severity']}] {finding['id']}"
        )

        print(f"Service: {finding['service']}")
        print(f"Category: {finding['category']}")
        print(f"Resource: {finding['resource']}")

        print(f"\nIssue:")
        print(finding["issue"])

        print(f"\nRisk:")
        print(finding["risk"])

        print(f"\nRemediation:")
        print(finding["remediation"])

        print(f"\nStatus: {finding['status']}")


def print_report(results):

    print("\n" + "=" * 70)
    print("AWS SECURITY POSTURE SCANNER")
    print("=" * 70)

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
        item for item in all_findings
        if item["severity"] != "ERROR"
    ]

    errors = [
        item for item in all_findings
        if item["severity"] == "ERROR"
    ]

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "REVIEW": 0
    }

    for finding in security_findings:

        severity = finding["severity"]

        if severity in severity_counts:
            severity_counts[severity] += 1

    print("\n" + "=" * 70)
    print("SCAN SUMMARY")
    print("=" * 70)

    print(f"Critical: {severity_counts['CRITICAL']}")
    print(f"High:     {severity_counts['HIGH']}")
    print(f"Medium:   {severity_counts['MEDIUM']}")
    print(f"Review:   {severity_counts['REVIEW']}")

    print(f"\nTotal security findings: {len(security_findings)}")
    print(f"Assessment errors: {len(errors)}")

    print("=" * 70)


# ============================================================
# JSON REPORT
# ============================================================

def export_json_report(results):

    sts = boto3.client("sts")
    identity = sts.get_caller_identity()

    all_findings = []

    for result in results.values():
        all_findings.extend(result)

    security_findings = [
        item for item in all_findings
        if item["severity"] != "ERROR"
    ]

    errors = [
        item for item in all_findings
        if item["severity"] == "ERROR"
    ]

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "REVIEW": 0
    }

    for finding in security_findings:

        severity = finding["severity"]

        if severity in severity_counts:
            severity_counts[severity] += 1

    report = {
        "scanner": {
            "name": "Multi-Cloud Security Posture Scanner",
            "version": "1.1.0",
            "cloud": "AWS",
            "scan_timestamp_utc": datetime.now(
                timezone.utc
            ).isoformat()
        },
        "assessment": {
            "account_id": identity.get("Account"),
            "principal_arn": identity.get("Arn")
        },
        "summary": {
            "total_security_findings": len(
                security_findings
            ),
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "review": severity_counts["REVIEW"],
            "assessment_errors": len(errors)
        },
        "findings": security_findings,
        "errors": errors
    }

    with open(
        "report.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            default=str
        )

    print("\nJSON report generated: report.json")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("\nStarting AWS Security Posture Scan...\n")

    results = {
        "security_groups": check_security_groups(),
        "rds": check_public_rds(),
        "s3": check_s3_public_access(),
        "iam_mfa": check_iam_mfa(),
        "access_keys": check_stale_access_keys(),
        "ebs": check_ebs_encryption(),
        "cloudtrail": check_cloudtrail()
    }

    print_report(results)
    export_json_report(results)