import boto3

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP"
}


def check_security_groups():
    print("\nChecking Security Groups...\n")

    ec2 = boto3.client("ec2")
    response = ec2.describe_security_groups()

    findings = []

    for sg in response.get("SecurityGroups", []):
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
                        findings.append({
                            "severity": "CRITICAL",
                            "security_group": sg_id,
                            "name": sg_name,
                            "port": port,
                            "service": service,
                            "cidr": cidr
                        })

    return findings


def check_public_rds():
    print("\nChecking RDS instances...\n")

    rds = boto3.client("rds")
    response = rds.describe_db_instances()

    findings = []

    for db in response.get("DBInstances", []):
        if db.get("PubliclyAccessible", False):
            findings.append({
                "severity": "HIGH",
                "db_instance": db["DBInstanceIdentifier"],
                "engine": db.get("Engine", "N/A"),
                "endpoint": db.get("Endpoint", {}).get("Address", "N/A")
            })

    return findings


def check_s3_public_access():
    print("\nChecking S3 buckets...\n")

    s3 = boto3.client("s3")
    response = s3.list_buckets()

    findings = []

    for bucket in response.get("Buckets", []):
        bucket_name = bucket["Name"]

        try:
            response = s3.get_public_access_block(Bucket=bucket_name)
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
                findings.append({
                    "severity": "HIGH",
                    "bucket": bucket_name,
                    "issue": ", ".join(risky_settings)
                })

        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            findings.append({
                "severity": "HIGH",
                "bucket": bucket_name,
                "issue": "No Public Access Block configuration found"
            })

        except Exception as error:
            findings.append({
                "severity": "INFO",
                "bucket": bucket_name,
                "issue": f"Could not evaluate bucket: {error}"
            })

    return findings


def print_report(
    security_group_findings,
    rds_findings,
    s3_findings
):
    print("\n" + "=" * 60)
    print("AWS SECURITY POSTURE SCANNER")
    print("=" * 60)

    total_findings = 0

    print("\nSECURITY GROUP CHECKS")
    print("-" * 60)

    if not security_group_findings:
        print("[PASS] No SSH/RDP exposure to 0.0.0.0/0 detected.")
    else:
        for finding in security_group_findings:
            total_findings += 1

            print(
                f"[{finding['severity']}] "
                f"{finding['security_group']} "
                f"({finding['name']}) allows "
                f"{finding['service']} on port "
                f"{finding['port']} from "
                f"{finding['cidr']}"
            )

    print("\nRDS CHECKS")
    print("-" * 60)

    if not rds_findings:
        print("[PASS] No publicly accessible RDS instances detected.")
    else:
        for finding in rds_findings:
            total_findings += 1

            print(
                f"[{finding['severity']}] "
                f"RDS instance "
                f"{finding['db_instance']} "
                f"({finding['engine']}) "
                f"is publicly accessible "
                f"at {finding['endpoint']}"
            )

    print("\nS3 CHECKS")
    print("-" * 60)

    if not s3_findings:
        print("[PASS] S3 Public Access Block is enabled for all buckets.")
    else:
        for finding in s3_findings:
            total_findings += 1

            print(
                f"[{finding['severity']}] "
                f"S3 bucket "
                f"{finding['bucket']} - "
                f"{finding['issue']}"
            )

    print("\n" + "=" * 60)
    print(f"TOTAL FINDINGS: {total_findings}")
    print("=" * 60)


if __name__ == "__main__":
    security_group_findings = check_security_groups()
    rds_findings = check_public_rds()
    s3_findings = check_s3_public_access()

    print_report(
        security_group_findings,
        rds_findings,
        s3_findings
    )