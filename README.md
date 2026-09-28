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

## Current AWS Checks

The scanner currently evaluates:

### 1. Security Group Exposure

Detects Security Groups that expose sensitive management ports to the public internet.

Current checks:

- SSH — Port 22
- RDP — Port 3389
- Source — `0.0.0.0/0`

Example finding:

```text
[CRITICAL] sg-0123456789 allows SSH on port 22 from 0.0.0.0/0