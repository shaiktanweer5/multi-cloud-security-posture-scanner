import json
import subprocess
import sys
from pathlib import Path

import streamlit as st


REPORT_FILE = Path("report.json")


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Multi-Cloud Security Posture Scanner",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ Multi-Cloud Security Posture Scanner")

st.write(
    "Assess cloud security posture, identify misconfigurations, "
    "understand risk, and review remediation guidance."
)

st.info(
    "Current version: AWS Security Assessment | "
    "Azure and Google Cloud support planned."
)


# ============================================================
# RUN SCAN
# ============================================================

if st.button(
    "Run AWS Security Scan",
    type="primary"
):

    with st.spinner(
        "Scanning AWS environment..."
    ):

        result = subprocess.run(
            [sys.executable, "scanner.py"],
            capture_output=True,
            text=True
        )

    if result.returncode != 0:

        st.error(
            "The security scan failed."
        )

        st.code(
            result.stderr,
            language="text"
        )

    elif not REPORT_FILE.exists():

        st.error(
            "The scan completed but report.json was not generated."
        )

    else:

        st.session_state["scan_completed"] = True


# ============================================================
# DISPLAY REPORT
# ============================================================

if (
    st.session_state.get("scan_completed")
    and REPORT_FILE.exists()
):

    with open(
        REPORT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        report = json.load(file)

    st.success(
        "AWS security scan completed successfully."
    )


    # ========================================================
    # ASSESSMENT DETAILS
    # ========================================================

    assessment = report.get(
        "assessment",
        {}
    )

    scanner_info = report.get(
        "scanner",
        {}
    )

    st.subheader(
        "Assessment Overview"
    )

    col1, col2, col3 = st.columns(3)

    col1.write(
        "**Cloud Provider**"
    )

    col1.write(
        scanner_info.get(
            "cloud",
            "AWS"
        )
    )

    col2.write(
        "**AWS Account**"
    )

    col2.write(
        assessment.get(
            "account_id",
            "N/A"
        )
    )

    col3.write(
        "**Scan Time (UTC)**"
    )

    col3.write(
        scanner_info.get(
            "scan_timestamp_utc",
            "N/A"
        )
    )


    # ========================================================
    # SEVERITY SUMMARY
    # ========================================================

    summary = report.get(
        "summary",
        {}
    )

    st.subheader(
        "Security Posture Summary"
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Critical",
        summary.get(
            "critical",
            0
        )
    )

    col2.metric(
        "High",
        summary.get(
            "high",
            0
        )
    )

    col3.metric(
        "Medium",
        summary.get(
            "medium",
            0
        )
    )

    col4.metric(
        "Review",
        summary.get(
            "review",
            0
        )
    )


    # ========================================================
    # FINDINGS TABLE
    # ========================================================

    findings = report.get(
        "findings",
        []
    )

    st.subheader(
        "Findings Overview"
    )

    if not findings:

        st.success(
            "No security findings detected."
        )

    else:

        table_data = []

        for finding in findings:

            table_data.append(
                {
                    "Finding ID":
                        finding.get(
                            "id",
                            "N/A"
                        ),

                    "Severity":
                        finding.get(
                            "severity",
                            "N/A"
                        ),

                    "Service":
                        finding.get(
                            "service",
                            "N/A"
                        ),

                    "Category":
                        finding.get(
                            "category",
                            "N/A"
                        ),

                    "Resource":
                        finding.get(
                            "resource",
                            "N/A"
                        ),

                    "Status":
                        finding.get(
                            "status",
                            "N/A"
                        )
                }
            )

        st.dataframe(
            table_data,
            width="stretch",
            hide_index=True
        )


        # ====================================================
        # DETAILED FINDINGS
        # ====================================================

        st.subheader(
            "Finding Details"
        )

        for finding in findings:

            severity = finding.get(
                "severity",
                "UNKNOWN"
            )

            finding_id = finding.get(
                "id",
                "N/A"
            )

            resource = finding.get(
                "resource",
                "N/A"
            )

            title = (
                f"[{severity}] "
                f"{finding_id} | "
                f"{resource}"
            )

            with st.expander(
                title
            ):

                col1, col2 = st.columns(2)

                col1.write(
                    "**Service:**"
                )

                col1.write(
                    finding.get(
                        "service",
                        "N/A"
                    )
                )

                col2.write(
                    "**Category:**"
                )

                col2.write(
                    finding.get(
                        "category",
                        "N/A"
                    )
                )

                st.markdown(
                    "### Issue"
                )

                st.write(
                    finding.get(
                        "issue",
                        "N/A"
                    )
                )

                st.markdown(
                    "### Risk"
                )

                st.write(
                    finding.get(
                        "risk",
                        "N/A"
                    )
                )

                st.markdown(
                    "### Remediation"
                )

                st.write(
                    finding.get(
                        "remediation",
                        "N/A"
                    )
                )

                st.markdown(
                    "### Status"
                )

                st.write(
                    finding.get(
                        "status",
                        "N/A"
                    )
                )


    # ========================================================
    # DOWNLOAD REPORT
    # ========================================================

    st.subheader(
        "Export Report"
    )

    st.download_button(
        label="Download JSON Security Report",
        data=json.dumps(
            report,
            indent=4
        ),
        file_name=(
            "security-posture-report.json"
        ),
        mime="application/json"
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Multi-Cloud Security Posture Scanner | "
    "Use only against cloud environments "
    "you are authorized to assess."
)