import json
import subprocess
import streamlit as st
from pathlib import Path


REPORT_FILE = Path("report.json")


st.set_page_config(
    page_title="Multi-Cloud Security Posture Scanner",
    page_icon="🛡️",
    layout="wide"
)


st.title("🛡️ Multi-Cloud Security Posture Scanner")

st.write(
    "Run a cloud security posture assessment and review "
    "misconfigurations, risks, and remediation guidance."
)


if st.button("Run AWS Security Scan", type="primary"):

    with st.spinner("Running AWS security assessment..."):

        result = subprocess.run(
            ["python", "scanner.py"],
            capture_output=True,
            text=True
        )

    if result.returncode != 0:

        st.error("The scanner failed.")

        st.code(
            result.stderr,
            language="text"
        )

    elif not REPORT_FILE.exists():

        st.error(
            "The scan completed, but report.json was not created."
        )

    else:

        st.success("AWS security scan completed successfully.")

        with open(
            REPORT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            report = json.load(file)

        summary = report.get(
            "summary",
            {}
        )

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Critical",
            summary.get("critical", 0)
        )

        col2.metric(
            "High",
            summary.get("high", 0)
        )

        col3.metric(
            "Medium",
            summary.get("medium", 0)
        )

        col4.metric(
            "Review",
            summary.get("review", 0)
        )

        st.subheader("Security Findings")

        findings = report.get(
            "findings",
            []
        )

        if not findings:

            st.success(
                "No security findings detected."
            )

        else:

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
                    f"{finding_id} — "
                    f"{resource}"
                )

                with st.expander(title):

                    st.write(
                        "**Service:**",
                        finding.get(
                            "service",
                            "N/A"
                        )
                    )

                    st.write(
                        "**Category:**",
                        finding.get(
                            "category",
                            "N/A"
                        )
                    )

                    st.write(
                        "**Issue:**"
                    )

                    st.write(
                        finding.get(
                            "issue",
                            "N/A"
                        )
                    )

                    st.write(
                        "**Risk:**"
                    )

                    st.write(
                        finding.get(
                            "risk",
                            "N/A"
                        )
                    )

                    st.write(
                        "**Remediation:**"
                    )

                    st.write(
                        finding.get(
                            "remediation",
                            "N/A"
                        )
                    )

                    st.write(
                        "**Status:**",
                        finding.get(
                            "status",
                            "N/A"
                        )
                    )

        st.subheader("Assessment Details")

        assessment = report.get(
            "assessment",
            {}
        )

        st.write(
            "**AWS Account:**",
            assessment.get(
                "account_id",
                "N/A"
            )
        )

        st.write(
            "**Principal:**",
            assessment.get(
                "principal_arn",
                "N/A"
            )
        )

        st.download_button(
            label="Download JSON Report",
            data=json.dumps(
                report,
                indent=4
            ),
            file_name="security-posture-report.json",
            mime="application/json"
        )


st.divider()

st.caption(
    "Use only against cloud environments "
    "you are authorized to assess."
)