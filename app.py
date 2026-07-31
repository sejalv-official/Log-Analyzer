import hashlib
import os
import time

import altair as alt
import pandas as pd
import streamlit as st

from ai_engine import (
    chat_with_logs,
    generate_log_query,
    generate_proactive_defenses,
    generate_remediation_playbook,
)
from aws_fetcher import (
    fetch_cloudtrail_events,
    fetch_cloudwatch_logs,
    fetch_latest_s3_log,
    list_cloudwatch_log_groups,
    list_s3_buckets,
)
from ini_parser import parse_aws_extension_ini
from log_parser import extract_critical_logs
from metrics_engine import calculate_metrics, generate_timeseries_dataframe


# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AI Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --- SESSION STATE INITIALIZATION ---
DEFAULT_RESULTS = {
    "security": [],
    "performance": [],
    "structured_data": [],
}

STATE_DEFAULTS = {
    "log_hash": "",
    "log_text": "",
    "messages": [],
    "results": DEFAULT_RESULTS.copy(),
    "role_arn": "",
    "source_context": "Unknown Source",
    "proactive_report": "",
    "sec_report": "",
    "perf_report": "",
    "auto_poll": False,
    "poll_interval": 10,
    "selected_bucket": "",
    "selected_log_group": "",
    "active_source": "S3 Bucket",
}

for key, value in STATE_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


def clear_analysis_state():
    """Clear all loaded logs and analysis results from state."""
    st.session_state.log_text = ""
    st.session_state.log_hash = ""
    st.session_state.results = DEFAULT_RESULTS.copy()
    st.session_state.sec_report = ""
    st.session_state.perf_report = ""
    st.session_state.proactive_report = ""
    st.session_state.messages = []


def render_playbook_section(
    incident_type: str,
    logs: list[str],
    report_state_key: str,
    btn_label: str,
    report_filename: str,
    alert_message: str,
    alert_type: str = "error",
):
    """Reusable UI component for rendering incident playbooks and snippets."""
    if not logs:
        st.success(f"✅ No {incident_type.lower()} risks detected.")
        return

    if alert_type == "error":
        st.error(alert_message)
    else:
        st.warning(alert_message)

    with st.expander(f"👁️ View Isolated {incident_type} Snippets", expanded=True):
        for item in logs:
            st.code(str(item), language="log")

    if st.button(
        btn_label,
        type="primary",
        use_container_width=True,
        key=f"{incident_type.lower()}_btn",
    ):
        with st.spinner(
            f"🤖 Llama 3.2 is generating an {incident_type} remediation plan..."
        ):
            st.session_state[report_state_key] = generate_remediation_playbook(
                logs, incident_type.lower()
            )

    report = st.session_state.get(report_state_key, "")
    if report:
        st.success(f"✨ {incident_type} Analysis Complete!")
        st.markdown(report)

        st.download_button(
            f"📥 Download {incident_type} Report",
            data=report,
            file_name=report_filename,
            mime="text/markdown",
            use_container_width=True,
            key=f"dl_{incident_type.lower()}_report",
        )


def build_incident_report(results: dict, source_context: str) -> str:
    """Build a portable Markdown incident report from current analysis results."""
    security_logs = results.get("security", [])
    performance_logs = results.get("performance", [])
    structured_data = results.get("structured_data", [])

    lines = [
        "# AI-Powered AWS Log Analyzer - Incident Report",
        "",
        f"**Source:** {source_context}",
        f"**Total incidents:** {len(security_logs) + len(performance_logs)}",
        f"**Security incidents:** {len(security_logs)}",
        f"**Performance incidents:** {len(performance_logs)}",
        "",
        "## Executive Summary",
        "",
        (
            "The analyzer identified incidents that require review. "
            "Security findings should be validated against CloudTrail and IAM activity, "
            "while performance findings should be correlated with CloudWatch metrics "
            "and application telemetry."
            if security_logs or performance_logs
            else "No critical security or performance incidents were detected."
        ),
        "",
        "## Security Findings",
        "",
    ]

    if security_logs:
        for index, item in enumerate(security_logs, start=1):
            lines.append(f"{index}. `{str(item)}`")
    else:
        lines.append("No security findings detected.")

    lines.extend(["", "## Performance Findings", ""])

    if performance_logs:
        for index, item in enumerate(performance_logs, start=1):
            lines.append(f"{index}. `{str(item)}`")
    else:
        lines.append("No performance findings detected.")

    lines.extend(["", "## Structured Incident Details", ""])

    if structured_data:
        for index, item in enumerate(structured_data, start=1):
            lines.append(f"### Incident {index}")
            for key, value in item.items():
                lines.append(f"- **{key}:** {value}")
            lines.append("")
    else:
        lines.append("No structured incident records are available.")

    lines.extend(
        [
            "",
            "## Recommended Next Actions",
            "",
            "1. Validate the affected identity, resource and timestamp in AWS CloudTrail.",
            "2. Review IAM permissions and apply least privilege.",
            "3. Correlate performance incidents with CloudWatch metrics and application logs.",
            "4. Confirm whether the activity was expected or unauthorized.",
            "5. Record remediation actions and assign an incident owner.",
        ]
    )

    return "\n".join(lines)


# --- CUSTOM STYLING ---
st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E88E5;
        margin-bottom: 0;
    }

    .sub-header {
        font-size: 1rem;
        color: #666;
        margin-bottom: 20px;
    }

    .stCodeBlock {
        border-radius: 8px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# --- SIDEBAR ---
with st.sidebar:
    st.image(
        "https://img.icons8.com/color/96/000000/cloud-lighting.png",
        width=60,
    )
    st.title("Settings & Status")

    st.markdown("### ⚙️ Engine Config")
    st.info(
        "**Model:** `llama3.2:1b` (Local)\n\n"
        "**Mode:** Privacy-Preserving"
    )

    st.markdown("---")
    st.markdown("### 🔄 Auto-Polling Suite")
    st.session_state.auto_poll = st.toggle(
        "Enable Live Auto-Polling",
        value=st.session_state.auto_poll,
        help="Continuously polls active AWS log stream and refreshes AI analysis.",
    )

    if st.session_state.auto_poll:
        st.session_state.poll_interval = st.slider(
            "Polling Interval (seconds)",
            min_value=5,
            max_value=60,
            value=st.session_state.poll_interval,
            step=5,
        )
        st.caption(
            f"⚡ Active: Polling AWS every **{st.session_state.poll_interval}s**"
        )

    st.markdown("---")
    st.markdown("### 📌 Supported Log Formats")
    st.caption(
        "• AWS Application Load Balancer (ALB)\n"
        "• AWS CloudWatch Logs\n"
        "• AWS CloudTrail Events\n"
        "• Custom Application Logs"
    )

    st.markdown("---")
    st.caption("Developed for Automated L1 Incident Triage.")


# --- MAIN HEADER ---
st.markdown(
    '<div class="main-header">🛡️ AI-Powered Log Analyzer</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="sub-header">'
    "Automated Root Cause Analysis & Remediation for AWS Infrastructure Logs"
    "</div>",
    unsafe_allow_html=True,
)


# --- TOP-LEVEL TABS ---
main_tab1, main_tab2, main_tab3, main_tab4, main_tab5 = st.tabs(
    [
        "📊 Log Analysis & Ingestion",
        "📈 Incident Dashboard",
        "🛡️ Proactive Defense & Compliance",
        "🔍 AI Query Builder",
        "💬 AI Chat Assistant",
    ]
)


# ============================================================
# TAB 1: LOG ANALYSIS & INGESTION
# ============================================================
with main_tab1:
    st.markdown("### 📥 Select Input Method")

    paste_tab, upload_tab, aws_tab = st.tabs(
        [
            "📋 Paste Raw Text",
            "📁 Upload Log File",
            "☁️ Pull from AWS",
        ]
    )

    with paste_tab:
        pasted_logs = st.text_area(
            "Paste log lines directly from CloudWatch or terminal:",
            height=180,
            placeholder=(
                "e.g., 2026-07-21 14:32:05 ALB 502 Bad Gateway "
                "/api/v1/checkout AccessDenied..."
            ),
        )

        if pasted_logs and pasted_logs != st.session_state.log_text:
            clear_analysis_state()
            st.session_state.log_text = pasted_logs
            st.session_state.source_context = "Pasted Text"

    with upload_tab:
        uploaded_files = st.file_uploader(
            "Upload log files (.log, .txt, .json)",
            type=["log", "txt", "json"],
            accept_multiple_files=True,
        )

        if uploaded_files:
            decoded_files = []

            for uploaded_file in uploaded_files:
                try:
                    decoded_files.append(
                        uploaded_file.read().decode(
                            "utf-8",
                            errors="replace",
                        )
                    )
                except Exception as exc:
                    st.error(
                        f"Unable to read {uploaded_file.name}: {exc}"
                    )

            if decoded_files:
                new_uploaded_text = "\n".join(decoded_files)
                if new_uploaded_text != st.session_state.log_text:
                    clear_analysis_state()
                    st.session_state.log_text = new_uploaded_text
                    st.session_state.source_context = (
                        "Uploaded Files: "
                        + ", ".join(file.name for file in uploaded_files)
                    )
                    st.success(
                        f"📄 Successfully loaded {len(decoded_files)} file(s)."
                    )

    with aws_tab:
        st.markdown("#### ☁️ Fetch AWS Telemetry")

        with st.expander(
            "🔑 AWS Auth (POD SSO) - Cross-Account Access",
            expanded=True,
        ):
            st.warning(
                "⚠️ **Note:** Cross-account authentication is currently "
                "a work in progress and may not work in every environment."
            )
            st.caption(
                "Enter AWS credentials for this session, or leave them blank "
                "to use credentials already configured with AWS CLI/SSO."
            )

            st.markdown("##### Base AWS Credentials")
            cred_col1, cred_col2 = st.columns(2)

            with cred_col1:
                aws_access_key = st.text_input(
                    "AWS Access Key ID",
                    type="password",
                    placeholder="AKIA...",
                    help="Used only by the running Streamlit process.",
                )
                aws_session_token = st.text_input(
                    "AWS Session Token (optional)",
                    type="password",
                    help="Required for temporary STS/SSO credentials.",
                )

            with cred_col2:
                aws_secret_key = st.text_input(
                    "AWS Secret Access Key",
                    type="password",
                    help="Used only by the running Streamlit process.",
                )
                aws_region = st.text_input(
                    "AWS Region",
                    value=os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
                )

            if aws_access_key and aws_secret_key:
                os.environ["AWS_ACCESS_KEY_ID"] = aws_access_key.strip()
                os.environ["AWS_SECRET_ACCESS_KEY"] = aws_secret_key.strip()

                if aws_session_token.strip():
                    os.environ["AWS_SESSION_TOKEN"] = aws_session_token.strip()
                else:
                    os.environ.pop("AWS_SESSION_TOKEN", None)

                if aws_region.strip():
                    os.environ["AWS_DEFAULT_REGION"] = aws_region.strip()
                    os.environ["AWS_REGION"] = aws_region.strip()

                st.success("AWS credentials loaded for this app session.")
            elif aws_access_key or aws_secret_key:
                st.warning(
                    "Enter both the Access Key ID and Secret Access Key."
                )

            ini_config = st.text_area(
                "AWS Extension Config (INI)",
                placeholder=(
                    "[profile my-client]\n"
                    "role_arn = arn:aws:iam::123456789012:role/L1-Admin"
                ),
                help=(
                    "Paste AWS Extend Switch Roles INI configuration "
                    "to populate a client profile dropdown."
                ),
                height=100,
            )

            role_arn_input = ""

            if ini_config.strip():
                profiles = parse_aws_extension_ini(ini_config)

                if profiles:
                    selected_profile = st.selectbox(
                        "Select Client Profile",
                        options=[
                            "Manual ARN Input",
                            *profiles.keys(),
                        ],
                    )

                    if selected_profile != "Manual ARN Input":
                        role_arn_input = profiles[selected_profile]
                        st.success(
                            f"Loaded ARN for {selected_profile}"
                        )

            if not role_arn_input:
                role_arn_input = st.text_input(
                    "Assume Role ARN (Manual)",
                    value=st.session_state.role_arn or "",
                    placeholder=(
                        "arn:aws:iam::123456789012:role/L1-Admin"
                    ),
                )

            st.session_state.role_arn = (
                role_arn_input.strip()
                if role_arn_input and role_arn_input.strip()
                else None
            )

            if st.button("🗑️ Clear Session Credentials", type="secondary"):
                os.environ.pop("AWS_ACCESS_KEY_ID", None)
                os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
                os.environ.pop("AWS_SESSION_TOKEN", None)
                st.session_state.role_arn = ""
                clear_analysis_state()
                st.success("Credentials cleared from app session!")
                st.rerun()

        # Dynamic Source Switcher
        aws_source = st.radio(
            "Select Source",
            [
                "S3 Bucket",
                "CloudWatch Logs",
                "CloudTrail Events",
            ],
            horizontal=True,
        )

        # Clear state when switching between S3 / CloudWatch / CloudTrail
        if aws_source != st.session_state.active_source:
            st.session_state.active_source = aws_source
            clear_analysis_state()
            st.rerun()

        if aws_source == "S3 Bucket":
            buckets, error = list_s3_buckets(
                role_arn=st.session_state.role_arn
            )

            if error:
                st.error(error)
                bucket = st.text_input("S3 Bucket Name manually")
            else:
                bucket = (
                    st.selectbox("Select S3 Bucket", buckets)
                    if buckets
                    else st.text_input("S3 Bucket Name manually")
                )

            st.session_state.selected_bucket = bucket

            if st.button(
                "Fetch Latest S3 Log",
                type="primary",
                key="fetch_s3",
            ):
                if not bucket:
                    st.error("Please provide a bucket name.")
                else:
                    with st.spinner(
                        f"Fetching from S3 bucket {bucket}..."
                    ):
                        content, message = fetch_latest_s3_log(
                            bucket,
                            role_arn=st.session_state.role_arn,
                        )

                    if "Error" in message:
                        st.error(message)
                    else:
                        clear_analysis_state()
                        st.success(message)
                        st.session_state.log_text = content or ""
                        st.session_state.source_context = (
                            f"S3 Bucket: {bucket}"
                        )

        elif aws_source == "CloudWatch Logs":
            log_groups, error = list_cloudwatch_log_groups(
                role_arn=st.session_state.role_arn
            )

            if error:
                st.caption(f"⚠️ Notice: {error}")
                log_group = st.text_input(
                    "CloudWatch Log Group Name",
                    placeholder="/aws/lambda/my-function",
                )
            else:
                log_group = (
                    st.selectbox(
                        "Select CloudWatch Log Group",
                        options=log_groups,
                    )
                    if log_groups
                    else st.text_input(
                        "CloudWatch Log Group Name manually",
                        placeholder="/aws/lambda/my-function",
                    )
                )

            st.session_state.selected_log_group = log_group

            if st.button(
                "Fetch CloudWatch Logs",
                type="primary",
                key="fetch_cloudwatch",
            ):
                if not log_group:
                    st.error("Please select or provide a Log Group Name.")
                else:
                    with st.spinner(
                        f"Fetching logs from {log_group}..."
                    ):
                        content, message = fetch_cloudwatch_logs(
                            log_group,
                            role_arn=st.session_state.role_arn,
                        )

                    if "Error" in message:
                        st.error(message)
                    else:
                        clear_analysis_state()
                        st.success(message)
                        st.session_state.log_text = content or ""
                        st.session_state.source_context = (
                            f"CloudWatch: {log_group}"
                        )

        elif aws_source == "CloudTrail Events":
            if st.button(
                "Fetch Recent CloudTrail Events",
                type="primary",
                key="fetch_cloudtrail",
            ):
                with st.spinner("Fetching CloudTrail events..."):
                    content, message = fetch_cloudtrail_events(
                        role_arn=st.session_state.role_arn
                    )

                if "Error" in message:
                    st.error(message)
                else:
                    clear_analysis_state()
                    st.success(message)
                    st.session_state.log_text = content or ""
                    st.session_state.source_context = "CloudTrail"

    st.markdown("---")

    log_text = st.session_state.get("log_text", "")

    if log_text.strip():
        source_context = st.session_state.get(
            "source_context",
            "Pasted/Uploaded Data",
        )
        hash_input = f"{source_context}\n{log_text}"
        current_hash = hashlib.md5(
            hash_input.encode("utf-8")
        ).hexdigest()

        if current_hash != st.session_state.log_hash:
            st.session_state.log_hash = current_hash
            st.session_state.messages = []
            st.session_state.sec_report = ""
            st.session_state.perf_report = ""

            with st.spinner(
                "🤖 AI is scanning the logs for anomalies..."
            ):
                st.session_state.results = extract_critical_logs(
                    log_text,
                    source_context,
                )

        results = st.session_state.results
        security_logs = results.get("security", [])
        performance_logs = results.get("performance", [])
        structured_data = results.get("structured_data", [])

        security_count = len(security_logs)
        performance_count = len(performance_logs)
        total_flagged = security_count + performance_count

        metric1, metric2, metric3 = st.columns(3)

        metric1.metric(
            "Total Lines Scanned",
            len(log_text.splitlines()),
        )
        metric2.metric(
            "Security Risks",
            security_count,
        )
        metric3.metric(
            "Performance Issues",
            performance_count,
        )

        st.markdown("### 🔍 Analysis Overview")

        if total_flagged == 0:
            st.success(
                "✅ **Clean Scan!** No critical error signatures detected."
            )
        else:
            st.warning(
                f"⚠️ **Found {total_flagged} critical log entries "
                "requiring attention.**"
            )

            if structured_data:
                timeseries_df = generate_timeseries_dataframe(
                    structured_data
                )

                if not timeseries_df.empty:
                    st.markdown(
                        "#### 📈 Visual Telemetry (Anomaly Timeline)"
                    )

                    timeline_chart = (
                        alt.Chart(timeseries_df)
                        .mark_area(
                            opacity=0.6,
                            interpolate="monotone",
                        )
                        .encode(
                            x=alt.X(
                                "Timestamp:T",
                                title="Time (Min)",
                            ),
                            y=alt.Y(
                                "Count:Q",
                                title="Incident Count",
                            ),
                            color=alt.Color(
                                "Type:N",
                                scale=alt.Scale(
                                    domain=[
                                        "Security",
                                        "Performance",
                                    ],
                                    range=[
                                        "#ff4b4b",
                                        "#ffa421",
                                    ],
                                ),
                            ),
                            tooltip=[
                                "Timestamp:T",
                                "Type:N",
                                "Count:Q",
                            ],
                        )
                        .properties(height=250)
                        .interactive()
                    )

                    st.altair_chart(
                        timeline_chart,
                        use_container_width=True,
                    )

            st.markdown("---")
            st.markdown("### 🛠️ Feature Output Workspaces")

            # Dedicated Output Feature Tabs
            out_tab1, out_tab2, out_tab3, out_tab4 = st.tabs(
                [
                    "🛡️ SecOps Playbook",
                    "⚡ SRE Performance Playbook",
                    "👁️ Isolated Log Snippets",
                    "📋 Extracted Incident Data",
                ]
            )

            # Refactored Clean Tab Rendering using Helper Component
            with out_tab1:
                render_playbook_section(
                    incident_type="Security",
                    logs=security_logs,
                    report_state_key="sec_report",
                    btn_label="🚀 Generate SecOps Playbook",
                    report_filename="secops_playbook.md",
                    alert_message="🚨 **High Severity:** Security risks detected.",
                    alert_type="error",
                )

            with out_tab2:
                render_playbook_section(
                    incident_type="Performance",
                    logs=performance_logs,
                    report_state_key="perf_report",
                    btn_label="🚀 Generate SRE Playbook",
                    report_filename="sre_playbook.md",
                    alert_message="⚠️ **Medium/High Severity:** Performance bottlenecks detected.",
                    alert_type="warning",
                )

            with out_tab3:
                st.markdown("#### Isolated Anomaly Snippets")
                snippet_col1, snippet_col2 = st.columns(2)

                with snippet_col1:
                    st.markdown("##### 🛡️ Security Snippets")
                    if security_logs:
                        for item in security_logs:
                            st.code(str(item), language="log")
                    else:
                        st.caption("No security log snippets found.")

                with snippet_col2:
                    st.markdown("##### ⚡ Performance Snippets")
                    if performance_logs:
                        for item in performance_logs:
                            st.code(str(item), language="log")
                    else:
                        st.caption("No performance log snippets found.")

            with out_tab4:
                st.markdown("#### Extracted Structured Context")
                if structured_data:
                    context_df = pd.DataFrame(structured_data)

                    if "Source" in context_df.columns:
                        ordered_columns = [
                            "Source",
                            *[
                                column
                                for column in context_df.columns
                                if column != "Source"
                            ],
                        ]
                        context_df = context_df[ordered_columns]

                    st.dataframe(
                        context_df,
                        use_container_width=True,
                        hide_index=True,
                    )
                else:
                    st.info("No structured metadata extracted.")
    else:
        st.info(
            "👈 **Get Started:** Paste, upload, or fetch logs "
            "to trigger analysis."
        )


# ============================================================
# TAB 2: INCIDENT DASHBOARD
# ============================================================
with main_tab2:
    st.markdown("### 📈 Incident Intelligence Dashboard")
    st.caption(
        "Executive overview of incidents detected during "
        "the current analysis session."
    )

    results = st.session_state.get(
        "results",
        DEFAULT_RESULTS,
    )
    security_logs = results.get("security", [])
    performance_logs = results.get("performance", [])
    structured_data = results.get("structured_data", [])
    all_incidents = [
        *security_logs,
        *performance_logs,
    ]

    if not all_incidents:
        st.info(
            "No incidents are available yet. Analyze logs in "
            "the Log Analysis & Ingestion tab first."
        )
    else:
        dashboard = calculate_metrics(all_incidents)
        severity_counts = dashboard.get("severity", {})

        total_incidents = len(all_incidents)
        critical_count = severity_counts.get("Critical", 0)
        high_count = severity_counts.get("High", 0)
        medium_count = severity_counts.get("Medium", 0)
        low_count = severity_counts.get("Low", 0)
        error_count = severity_counts.get("Error", 0)
        unknown_count = severity_counts.get("Unknown", 0)

        kpi1, kpi2, kpi3, kpi4 = st.columns(4)
        kpi1.metric("Total Incidents", total_incidents)
        kpi2.metric("Security", len(security_logs))
        kpi3.metric("Performance", len(performance_logs))
        kpi4.metric(
            "Critical / High",
            critical_count + high_count,
        )

        st.markdown("---")

        chart_column1, chart_column2 = st.columns(2)

        with chart_column1:
            st.markdown("#### Severity Distribution")
            severity_df = dashboard.get("severity_df")

            if (
                severity_df is not None
                and not severity_df.empty
            ):
                severity_chart = (
                    alt.Chart(severity_df)
                    .mark_arc(innerRadius=55)
                    .encode(
                        theta=alt.Theta(
                            "Count:Q",
                            title="Count",
                        ),
                        color=alt.Color(
                            "Severity:N",
                            title="Severity",
                        ),
                        tooltip=[
                            "Severity:N",
                            "Count:Q",
                        ],
                    )
                    .properties(height=320)
                )

                st.altair_chart(
                    severity_chart,
                    use_container_width=True,
                )
            else:
                st.info("Severity data is unavailable.")

        with chart_column2:
            st.markdown("#### Incident Categories")
            error_df = dashboard.get("error_df")

            if error_df is not None and not error_df.empty:
                category_chart = (
                    alt.Chart(error_df)
                    .mark_bar()
                    .encode(
                        x=alt.X(
                            "Count:Q",
                            title="Incident Count",
                        ),
                        y=alt.Y(
                            "Error:N",
                            sort="-x",
                            title="Category",
                        ),
                        tooltip=[
                            "Error:N",
                            "Count:Q",
                        ],
                    )
                    .properties(height=320)
                )

                st.altair_chart(
                    category_chart,
                    use_container_width=True,
                )
            else:
                st.info("Category data is unavailable.")

        st.markdown("---")
        st.markdown("#### Severity Summary")

        severity_summary = pd.DataFrame(
            [
                {
                    "Severity": "Critical",
                    "Count": critical_count,
                },
                {
                    "Severity": "High",
                    "Count": high_count,
                },
                {
                    "Severity": "Medium",
                    "Count": medium_count,
                },
                {
                    "Severity": "Low",
                    "Count": low_count,
                },
                {
                    "Severity": "Error",
                    "Count": error_count,
                },
                {
                    "Severity": "Unknown",
                    "Count": unknown_count,
                },
            ]
        )
        severity_summary = severity_summary[
            severity_summary["Count"] > 0
        ]

        if not severity_summary.empty:
            st.dataframe(
                severity_summary,
                use_container_width=True,
                hide_index=True,
            )

        st.markdown("#### Incidents Over Time")
        timeseries_df = generate_timeseries_dataframe(
            structured_data
        )

        if not timeseries_df.empty:
            dashboard_timeline = (
                alt.Chart(timeseries_df)
                .mark_area(
                    opacity=0.6,
                    interpolate="monotone",
                )
                .encode(
                    x=alt.X(
                        "Timestamp:T",
                        title="Time",
                    ),
                    y=alt.Y(
                        "Count:Q",
                        title="Incident Count",
                    ),
                    color=alt.Color(
                        "Type:N",
                        title="Incident Type",
                    ),
                    tooltip=[
                        "Timestamp:T",
                        "Type:N",
                        "Count:Q",
                    ],
                )
                .properties(height=300)
                .interactive()
            )

            st.altair_chart(
                dashboard_timeline,
                use_container_width=True,
            )
        else:
            st.info(
                "Timestamp data is unavailable for these incidents."
            )

        st.markdown("---")
        st.markdown("#### Latest Detected Incidents")

        incident_rows = [
            {
                "Type": "Security",
                "Source": st.session_state.source_context,
                "Incident": str(item),
            }
            for item in security_logs
        ]
        incident_rows.extend(
            {
                "Type": "Performance",
                "Source": st.session_state.source_context,
                "Incident": str(item),
            }
            for item in performance_logs
        )

        st.dataframe(
            pd.DataFrame(incident_rows).head(20),
            use_container_width=True,
            hide_index=True,
        )

        st.markdown("---")
        st.markdown("#### Export Incident Evidence")

        report_markdown = build_incident_report(
            results,
            st.session_state.get("source_context", "Unknown Source"),
        )
        incidents_df = pd.DataFrame(incident_rows)

        export_col1, export_col2 = st.columns(2)

        with export_col1:
            st.download_button(
                "📥 Download Incident Report",
                data=report_markdown,
                file_name="ai_log_analyzer_incident_report.md",
                mime="text/markdown",
                use_container_width=True,
            )

        with export_col2:
            st.download_button(
                "📥 Download Incident CSV",
                data=incidents_df.to_csv(index=False),
                file_name="ai_log_analyzer_incidents.csv",
                mime="text/csv",
                use_container_width=True,
            )


# ============================================================
# TAB 3: PROACTIVE DEFENSE & COMPLIANCE
# ============================================================
with main_tab3:
    st.info(
        "🛡️ Map detected issues to compliance frameworks and "
        "generate preventive Terraform or CLI recommendations."
    )

    framework_column, context_column = st.columns(2)

    with framework_column:
        compliance_framework = st.selectbox(
            "Compliance Framework",
            [
                "SOC 2",
                "HIPAA",
                "PCI-DSS",
                "CIS AWS Foundations Benchmark",
            ],
        )

    with context_column:
        log_context = st.selectbox(
            "Log Context to Audit",
            [
                "S3",
                "CloudWatch",
                "CloudTrail",
                "Application Logs",
            ],
        )

    results = st.session_state.results
    
    st.markdown("#### 🎯 Select Logs for Evaluation")
    st.caption("Choose which detected anomalies to include in the compliance audit. The AI will only analyze what you select.")
    
    include_security = st.checkbox(
        f"Include Security Logs ({len(results.get('security', []))} found)", 
        value=bool(results.get("security"))
    )
    include_performance = st.checkbox(
        f"Include Performance Logs ({len(results.get('performance', []))} found)", 
        value=bool(results.get("performance"))
    )

    logs_to_evaluate = []
    if include_security:
        logs_to_evaluate.extend(results.get("security", []))
    if include_performance:
        logs_to_evaluate.extend(results.get("performance", []))
        
    total_flagged = len(logs_to_evaluate)

    if total_flagged:
        with st.expander(f"👁️ View Exact Logs Being Sent to AI ({total_flagged} lines)", expanded=False):
            st.info("No black box here! This is the exact raw data the AI will see to generate your compliance report.")
            for log in logs_to_evaluate:
                st.code(str(log), language="log")

        if st.button(
            "🚀 Generate Compliance Audit Report",
            type="primary",
            use_container_width=True,
            key="proact_btn",
        ):
            with st.spinner(
                f"🤖 Llama 3.2 is auditing logs against "
                f"{compliance_framework}..."
            ):
                raw_context = "\n".join(str(item) for item in logs_to_evaluate)
                st.session_state.proactive_report = (
                    generate_proactive_defenses(
                        results.get("structured_data", []),
                        raw_context,
                        compliance_framework,
                        log_context,
                    )
                )

        if st.session_state.proactive_report:
            st.success(
                "✨ Proactive Defense Analysis Complete!"
            )
            st.markdown(
                st.session_state.proactive_report
            )
            st.download_button(
                label="📥 Download Audit Report",
                data=st.session_state.proactive_report,
                file_name=(
                    "compliance_audit_"
                    f"{compliance_framework.lower().replace(' ', '_')}.md"
                ),
                mime="text/markdown",
                use_container_width=True,
            )
    else:
        st.warning(
            "⚠️ No security or performance issues are available. "
            "Analyze logs first."
        )


# ============================================================
# TAB 4: AI QUERY BUILDER
# ============================================================
with main_tab4:
    st.info(
        "🔍 Translate plain English into queries for Athena, "
        "CloudWatch Logs Insights, Splunk, or Datadog."
    )

    if not st.session_state.results.get(
        "structured_data",
        [],
    ):
        st.warning(
            "⚠️ No logs are currently loaded. "
            "A generic query will be generated."
        )

    query_platform = st.selectbox(
        "Select Target Platform",
        [
            "AWS Athena",
            "CloudWatch Logs Insights",
            "Splunk SPL",
            "Datadog",
        ],
    )
    query_prompt = st.text_area(
        "Describe what you want to search for:",
        placeholder=(
            "e.g., Find all 502 errors grouped by source IP "
            "from the last 24 hours"
        ),
    )

    if st.button(
        "✨ Generate Query Code",
        type="primary",
        use_container_width=True,
        key="query_btn",
    ):
        if not query_prompt.strip():
            st.error(
                "Please enter a description of the query."
            )
        else:
            with st.spinner(
                f"🤖 Translating your request into "
                f"{query_platform} syntax..."
            ):
                results = st.session_state.results
                raw_context = "No extracted context."

                if results.get("structured_data"):
                    raw_context = (
                        "Available Fields: "
                        f"{list(results['structured_data'][0].keys())}"
                    )

                query_code = generate_log_query(
                    query_prompt,
                    query_platform,
                    raw_context,
                )

            st.success(
                f"✨ {query_platform} Query Generated!"
            )
            st.markdown(query_code)


# ============================================================
# TAB 5: AI CHAT ASSISTANT
# ============================================================
with main_tab5:
    heading_column, button_column = st.columns(
        [4, 1]
    )

    with heading_column:
        st.markdown(
            "### 💬 Interactive Log Investigation Assistant"
        )
        st.caption(
            "Ask questions about anomalies detected in the logs."
        )

    with button_column:
        if st.button(
            "🗑️ Clear Chat",
            use_container_width=True,
            key="clear_chat",
        ):
            st.session_state.messages = []
            st.rerun()

    results = st.session_state.results

    if (
        not results.get("security")
        and not results.get("performance")
    ):
        st.warning(
            "⚠️ No analyzed logs are loaded. "
            "Use the Log Analysis tab first."
        )

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if prompt := st.chat_input(
        "Ask about an IP, error, AWS service, RCA, or query..."
    ):
        st.session_state.messages.append(
            {
                "role": "user",
                "content": prompt,
            }
        )

        with st.chat_message("user"):
            st.markdown(prompt)

        context_payload = ""

        if results.get("security"):
            context_payload += (
                "Security Logs:\n"
                f"{results['security']}\n"
            )

        if results.get("performance"):
            context_payload += (
                "Performance Logs:\n"
                f"{results['performance']}\n"
            )

        with st.chat_message("assistant"):
            with st.spinner("Analyzing context..."):
                response = chat_with_logs(
                    prompt,
                    st.session_state.messages[:-1],
                    context_payload,
                )
                st.markdown(response)

        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": response,
            }
        )


# --- AUTOMATED LIVE POLLING LOOP ---
if st.session_state.get("auto_poll"):
    time.sleep(st.session_state.get("poll_interval", 10))

    # Auto-fetch based on active source context
    if "CloudWatch" in st.session_state.source_context and st.session_state.selected_log_group:
        content, _ = fetch_cloudwatch_logs(st.session_state.selected_log_group, role_arn=st.session_state.role_arn)
        if content:
            st.session_state.log_text = content

    elif "S3" in st.session_state.source_context and st.session_state.selected_bucket:
        content, _ = fetch_latest_s3_log(st.session_state.selected_bucket, role_arn=st.session_state.role_arn)
        if content:
            st.session_state.log_text = content

    elif "CloudTrail" in st.session_state.source_context:
        content, _ = fetch_cloudtrail_events(role_arn=st.session_state.role_arn)
        if content:
            st.session_state.log_text = content

    st.rerun()