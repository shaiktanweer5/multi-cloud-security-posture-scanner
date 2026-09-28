# Multi-Cloud Security Posture Scanner

A lightweight Python-based cloud security posture scanner designed to identify common cloud misconfigurations and present them as clear, CSPM-style security findings.

The project is being built to demonstrate practical cloud security concepts such as:

- Cloud resource discovery
- Security posture assessment
- Misconfiguration detection
- Risk classification
- Remediation guidance
- Exception handling
- Attack-path thinking
- Multi-cloud security automation

> This is an independent learning and portfolio project. It is not affiliated with Wiz, Prisma Cloud, AWS Security Hub, or any other commercial CNAPP/CSPM platform.

---

## Current AWS Security Checks

The scanner currently evaluates seven security controls.

---

### 1. Security Group Exposure

Detects Security Groups that expose sensitive management ports to the public internet.

Current checks:

- SSH — Port 22
- RDP — Port 3389
- IPv4 exposure — `0.0.0.0/0`
- IPv6 exposure — `::/0`

### Example finding

```text
[CRITICAL] EC2 | sg-0123456789
Issue: SSH port 22 is exposed to 0.0.0.0/0
Remediation: Restrict inbound access to trusted IP ranges or private connectivity.
```

---

### 2. Publicly Accessible RDS Instances

Detects Amazon RDS database instances configured as publicly accessible.

### Example finding

```text
[HIGH] RDS | production-db
Issue: Database is configured as publicly accessible.
Remediation: Place the database in private subnets and disable public accessibility unless explicitly required.
```

---

### 3. S3 Public Access Posture

Evaluates S3 Public Access Block settings for each bucket.

The scanner checks:

- `BlockPublicAcls`
- `IgnorePublicAcls`
- `BlockPublicPolicy`
- `RestrictPublicBuckets`

### Example finding

```text
[REVIEW] S3 | example-bucket
Issue: BlockPublicPolicy=False
Remediation: Confirm whether public access is intentionally required.
```

A disabled Public Access Block setting does not always mean a security incident.

Some architectures may intentionally require public access, such as static website hosting.

For this reason, the scanner marks these findings as:

```text
REVIEW
```

instead of automatically treating every case as a high-severity issue.

---

### 4. IAM Users Without MFA

Detects IAM users that do not have an MFA device configured.

### Example finding

```text
[HIGH] IAM | example-user
Issue: IAM user does not have MFA configured.
Remediation: Enable MFA or migrate human access to centralized identity/SSO.
```

---

### 5. Stale IAM Access Keys

Detects active IAM access keys older than 90 days.

### Example finding

```text
[MEDIUM] IAM | example-user
Issue: Active access key is 132 days old.
Remediation: Review whether the key is still required and rotate or remove unnecessary long-lived credentials.
```

The objective is to reduce reliance on long-lived credentials and encourage temporary credentials wherever possible.

---

### 6. EBS Encryption

Detects Amazon EBS volumes that are not encrypted.

### Example finding

```text
[HIGH] EBS | vol-0123456789abcdef
Issue: EBS volume is not encrypted.
Remediation: Migrate data to an encrypted EBS volume using AWS KMS.
```

---

### 7. CloudTrail Logging

Checks whether CloudTrail logging is configured and active.

### Example finding

```text
[HIGH] CloudTrail | AWS Account
Issue: No CloudTrail trail was detected.
Remediation: Configure CloudTrail to record AWS API activity.
```

CloudTrail is important for:

- Security investigations
- Audit logging
- Incident response
- API activity tracking
- Governance

---

## Example Scanner Output

```text
======================================================================
AWS SECURITY POSTURE SCANNER
======================================================================

SECURITY GROUP CHECKS
----------------------------------------------------------------------
[PASS] No public SSH/RDP exposure detected.

RDS CHECKS
----------------------------------------------------------------------
[PASS] No publicly accessible RDS instances detected.

S3 CHECKS
----------------------------------------------------------------------

[REVIEW] S3 | example-bucket
Issue: BlockPublicPolicy=False
Remediation: Confirm whether public access is intentionally required.

IAM MFA CHECKS
----------------------------------------------------------------------

[HIGH] IAM | example-user
Issue: IAM user does not have MFA configured.
Remediation: Enable MFA or migrate human access to centralized identity/SSO.

IAM ACCESS KEY CHECKS
----------------------------------------------------------------------
[PASS] No active access keys older than 90 days detected.

EBS ENCRYPTION CHECKS
----------------------------------------------------------------------
[PASS] All EBS volumes are encrypted.

CLOUDTRAIL CHECKS
----------------------------------------------------------------------

[HIGH] CloudTrail | AWS Account
Issue: No CloudTrail trail was detected.
Remediation: Configure CloudTrail to record AWS API activity.

======================================================================
SCAN SUMMARY
======================================================================
Security findings: 3
Assessment errors: 0
======================================================================
```

---

## How the Scanner Works

The scanner uses AWS APIs through the Python `boto3` SDK.

Basic workflow:

```text
AWS Account
    |
    v
Resource Discovery
    |
    v
Security Checks
    |
    v
Findings
    |
    v
Severity + Context
    |
    v
Remediation Guidance
```

The project is intentionally designed to move beyond simply printing configuration data.

Each finding aims to answer:

- What resource is affected?
- What is the security issue?
- How severe is it?
- Is context required?
- What should be done next?

---

## CSPM / CNAPP Concepts

The project demonstrates simplified versions of concepts used in modern CSPM and CNAPP platforms.

Current concepts include:

- Resource discovery
- Configuration assessment
- Identity posture
- Encryption posture
- Logging posture
- Internet exposure
- Security findings
- Severity classification
- Remediation guidance
- Context-aware review

Future versions will also focus on correlation between findings.

Example:

```text
Internet Exposure
      |
      v
Public Compute Resource
      |
      v
Overprivileged IAM Role
      |
      v
Sensitive Data
```

Instead of treating each issue independently, the project will attempt to understand how multiple risks may combine into a larger attack path.

---

## Relationship to Wiz and CNAPP Platforms

This project is not a replacement for Wiz or any enterprise CNAPP platform.

The purpose is to demonstrate an understanding of the security concepts behind CSPM and CNAPP tooling.

Modern cloud security platforms may correlate information such as:

- Internet exposure
- Vulnerabilities
- IAM permissions
- Sensitive data
- Misconfigurations
- Workload context
- Attack paths

This project gradually implements simplified versions of these ideas for educational and portfolio purposes.

---

## Requirements

- Python 3
- AWS CLI
- boto3
- Valid AWS authentication
- Read permissions for the AWS services being evaluated

Install boto3:

```powershell
python -m pip install boto3
```

If AWS login credentials require CRT support:

```powershell
python -m pip install "botocore[crt]"
```

Authenticate:

```powershell
aws login
```

Verify identity:

```powershell
aws sts get-caller-identity
```

---

## Run the Scanner

From the project folder:

```powershell
python .\scanner.py
```

---

## Current AWS Permissions

The scanner requires read access to services such as:

- EC2
- RDS
- S3
- IAM
- CloudTrail

For production-quality usage, the preferred model is a dedicated least-privilege read-only assessment role rather than broad administrative permissions.

---

## Security Guidelines

Do not store or commit:

- AWS access keys
- Secret access keys
- Session tokens
- Passwords
- Customer information
- Employer information
- Production credentials
- Confidential architecture
- Proprietary configurations

The scanner should only be used against accounts and environments you are authorized to assess.

---

## Current Project Status

### AWS

Implemented:

- Security Group exposure checks
- Public RDS checks
- S3 Public Access Block posture
- IAM MFA checks
- IAM stale access key checks
- EBS encryption checks
- CloudTrail logging checks

### Reporting

Current:

- Terminal output
- Severity
- Resource
- Issue
- Remediation
- Scan summary

---

## Roadmap

### AWS Improvements

Planned:

- Overly permissive IAM policies
- Public EC2 exposure
- Root account security checks
- S3 bucket policy evaluation
- Default VPC detection
- KMS posture
- Security Hub posture
- Additional logging checks

### Reporting

Planned:

- JSON report
- CSV report
- HTML report
- Risk summary
- Finding IDs
- Timestamps
- Region/account metadata

### Context and Prioritization

Planned:

- Risk scoring
- Security exceptions
- Context-aware findings
- False-positive handling
- Asset criticality
- Exposure analysis

### Attack-Path Correlation

Planned:

```text
Internet
   |
   v
Public Workload
   |
   v
Privileged IAM Role
   |
   v
Sensitive Data
```

The goal is to demonstrate how individual findings can combine into a larger security risk.

### Multi-Cloud Support

Planned:

- Microsoft Azure
- Google Cloud Platform

The long-term objective is to use a common finding model across AWS, Azure, and GCP.

---

## Project Goal

The goal of this project is to understand cloud security posture management at a deeper technical level.

Instead of only consuming findings from a security platform, the project explores how security checks can be implemented using cloud APIs.

Key questions include:

- Is a resource internet exposed?
- Does a user have strong authentication?
- Are long-lived credentials being used?
- Is sensitive infrastructure encrypted?
- Is security logging enabled?
- What is the potential blast radius?
- Is the finding actually exploitable?
- What should be remediated first?

This project focuses on practical cloud security engineering, CSPM concepts, automation, and attack-path thinking.

---

## Author

**Tanweer Ahmed**

Cloud Security Engineer focused on:

- AWS
- Microsoft Azure
- Google Cloud
- Wiz
- CNAPP / CSPM
- IAM
- Terraform
- DevSecOps
- Kubernetes Security
- Vulnerability Management
- Security Automation

Portfolio: https://tanweerahmed.in

GitHub: https://github.com/shaiktanweer5