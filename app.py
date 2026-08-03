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
    fetch_all_s3_buckets_logs,
    fetch_cloudtrail_events,
    fetch_cloudwatch_logs,
    fetch_latest_s3_log,
    get_aws_account_id,
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

if "sources_data" not in st.session_state:
    st.session_state.sources_data = {
        "S3 Bucket": {
            "log_text": "",
            "log_hash": "",
            "results": DEFAULT_RESULTS.copy(),
            "source_context": "S3 Bucket",
            "sec_report": "",
            "perf_report": "",
            "last_msg": "",
        },
        "CloudWatch Logs": {
            "log_text": "",
            "log_hash": "",
            "results": DEFAULT_RESULTS.copy(),
            "source_context": "CloudWatch Logs",
            "sec_report": "",
            "perf_report": "",
            "last_msg": "",
        },
        "CloudTrail Events": {
            "log_text": "",
            "log_hash": "",
            "results": DEFAULT_RESULTS.copy(),
            "source_context": "CloudTrail Events",
            "sec_report": "",
            "perf_report": "",
            "last_msg": "",
        },
    }

STATE_DEFAULTS = {
    "messages": [],
    "role_arn": "",
    "proactive_report": "",
    "selected_bucket": "",
    "selected_log_group": "",
    "active_source": "CloudWatch Logs",
    "auto_poll": False,
    "poll_interval": 30,
    "last_poll_time": time.time(),
}

for key, value in STATE_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


def render_playbook_section(
    incident_type: str,
    logs: list[str],
    source_name: str,
    btn_label: str,
    report_filename: str,
    alert_message: str,
    alert_type: str = "error",
):
    """Reusable UI component for rendering incident playbooks and snippets."""
    if not logs:
        st.success(f"✅ No {incident_type.lower()} risks detected in {source_name}.")
        return

    if alert_type == "error":
        st.error(alert_message)
    else:
        st.warning(alert_message)

    with st.expander(f"👁️ View Isolated {incident_type} Snippets ({source_name})", expanded=True):
        for item in logs:
            st.code(str(item), language="log")

    button_key = f"{source_name}_{incident_type.lower()}_btn"
    if st.button(
        btn_label,
        type="primary",
        use_container_width=True,
        key=button_key,
    ):
        with st.spinner(
            f"🤖 Llama 3.2 is generating an {incident_type} remediation plan for {source_name}..."
        ):
            report = generate_remediation_playbook(logs, incident_type.lower())
            if incident_type == "Security":
                st.session_state.sources_data[source_name]["sec_report"] = report
            else:
                st.session_state.sources_data[source_name]["perf_report"] = report

    report = (
        st.session_state.sources_data[source_name]["sec_report"]
        if incident_type == "Security"
        else st.session_state.sources_data[source_name]["perf_report"]
    )

    if report:
        st.success(f"✨ {incident_type} Analysis Complete ({source_name})!")
        st.markdown(report)

        st.download_button(
            f"📥 Download {incident_type} Report",
            data=report,
            file_name=f"{source_name.lower().replace(' ', '_')}_{report_filename}",
            mime="text/markdown",
            use_container_width=True,
            key=f"dl_{source_name}_{incident_type.lower()}_report",
        )


def build_incident_report(sources_data: dict) -> str:
    """Build a portable Markdown incident report combining all analyzed AWS sources."""
    lines = ["# AI-Powered AWS Log Analyzer - Multi-Source Incident Report", ""]

    for source_name, source_info in sources_data.items():
        results = source_info.get("results", {})
        security_logs = results.get("security", [])
        performance_logs = results.get("performance", [])

        if not security_logs and not performance_logs:
            continue

        lines.extend(
            [
                f"## 📌 Telemetry Source: {source_name}",
                f"**Context:** {source_info.get('source_context', source_name)}",
                f"**Security Incidents:** {len(security_logs)}",
                f"**Performance Incidents:** {len(performance_logs)}",
                "",
                "### Security Findings",
            ]
        )

        if security_logs:
            for index, item in enumerate(security_logs, start=1):
                lines.append(f"{index}. `{str(item)}`")
        else:
            lines.append("No security findings detected.")

        lines.extend(["", "### Performance Findings"])

        if performance_logs:
            for index, item in enumerate(performance_logs, start=1):
                lines.append(f"{index}. `{str(item)}`")
        else:
            lines.append("No performance findings detected.")

        lines.extend(["", "---", ""])

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

    account_id, _ = get_aws_account_id(st.session_state.get("role_arn"))
    if account_id:
        st.success(f"🆔 **AWS Account ID:**\n`{account_id}`")

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

        if pasted_logs:
            active_src = st.session_state.active_source
            st.session_state.sources_data[active_src]["log_text"] = pasted_logs
            st.session_state.sources_data[active_src]["source_context"] = f"Pasted Text ({active_src})"

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
                    st.error(f"Unable to read {uploaded_file.name}: {exc}")

            if decoded_files:
                active_src = st.session_state.active_source
                st.session_state.sources_data[active_src]["log_text"] = "\n".join(decoded_files)
                st.session_state.sources_data[active_src]["source_context"] = (
                    f"Uploaded Files: " + ", ".join(file.name for file in uploaded_files)
                )
                st.success(f"📄 Successfully loaded {len(decoded_files)} file(s).")

    with aws_tab:
        st.markdown("#### ☁️ Fetch AWS Telemetry")

        with st.expander(
            "🔑 AWS Auth (POD SSO) - Cross-Account Access",
            expanded=True,
        ):
            account_id, acc_err = get_aws_account_id(st.session_state.get("role_arn"))
            if account_id:
                st.info(f"Connected AWS Account ID: `{account_id}`")

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
                st.warning("Enter both the Access Key ID and Secret Access Key.")

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
                        st.success(f"Loaded ARN for {selected_profile}")

            if not role_arn_input:
                role_arn_input = st.text_input(
                    "Assume Role ARN (Manual)",
                    value=st.session_state.role_arn or "",
                    placeholder=("arn:aws:iam::123456789012:role/L1-Admin"),
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

        st.session_state.active_source = aws_source

        if aws_source == "S3 Bucket":
            buckets, error = list_s3_buckets(role_arn=st.session_state.role_arn)

            options_list = ["ALL BUCKETS (Scan Account)"] + (buckets if buckets else [])
            selected_bkt = st.selectbox("Select S3 Bucket to Fetch", options=options_list)

            if st.button("Fetch Selected S3 Log", type="primary", key="fetch_s3"):
                if selected_bkt == "ALL BUCKETS (Scan Account)":
                    with st.spinner("Scanning ALL S3 buckets in account..."):
                        content, message = fetch_all_s3_buckets_logs(role_arn=st.session_state.role_arn)
                    st.session_state.sources_data["S3 Bucket"]["last_msg"] = message
                    if content:
                        st.session_state.sources_data["S3 Bucket"]["log_text"] = content
                        st.session_state.sources_data["S3 Bucket"]["source_context"] = "All S3 Buckets"
                else:
                    with st.spinner(f"Fetching from S3 bucket '{selected_bkt}'..."):
                        content, message = fetch_latest_s3_log(
                            selected_bkt,
                            role_arn=st.session_state.role_arn,
                        )

                    st.session_state.sources_data["S3 Bucket"]["last_msg"] = message
                    if content:
                        st.session_state.sources_data["S3 Bucket"]["log_text"] = content
                        st.session_state.sources_data["S3 Bucket"]["source_context"] = f"S3 Bucket: {selected_bkt}"

        elif aws_source == "CloudWatch Logs":
            log_groups, error = list_cloudwatch_log_groups(role_arn=st.session_state.role_arn)

            if error:
                st.caption(f"⚠️ Notice: {error}")
                log_group = st.text_input(
                    "CloudWatch Log Group Name",
                    placeholder="/aws/lambda/my-function",
                )
            else:
                log_group = (
                    st.selectbox("Select CloudWatch Log Group", options=log_groups)
                    if log_groups
                    else st.text_input(
                        "CloudWatch Log Group Name manually",
                        placeholder="/aws/lambda/my-function",
                    )
                )

            st.session_state.selected_log_group = log_group

            if st.button("Fetch CloudWatch Logs", type="primary", key="fetch_cloudwatch"):
                if not log_group:
                    st.error("Please select or provide a Log Group Name.")
                else:
                    with st.spinner(f"Fetching ALL log streams from {log_group}..."):
                        content, message = fetch_cloudwatch_logs(
                            log_group,
                            role_arn=st.session_state.role_arn,
                        )

                    st.session_state.sources_data["CloudWatch Logs"]["last_msg"] = message
                    if content:
                        st.session_state.sources_data["CloudWatch Logs"]["log_text"] = content
                        st.session_state.sources_data["CloudWatch Logs"]["source_context"] = f"CloudWatch: {log_group}"

        elif aws_source == "CloudTrail Events":
            if st.button("Fetch Recent CloudTrail Events", type="primary", key="fetch_cloudtrail"):
                with st.spinner("Fetching CloudTrail events..."):
                    content, message = fetch_cloudtrail_events(role_arn=st.session_state.role_arn)

                st.session_state.sources_data["CloudTrail Events"]["last_msg"] = message
                if content:
                    st.session_state.sources_data["CloudTrail Events"]["log_text"] = content
                    st.session_state.sources_data["CloudTrail Events"]["source_context"] = "CloudTrail Events"

        # --- HANDS-FREE AUTO-POLLING CONTROL ---
        st.markdown("---")
        poll_col1, poll_col2 = st.columns([1, 2])

        with poll_col1:
            st.session_state.auto_poll = st.toggle(
                "🔄 Enable Hands-Free Live Auto-Polling",
                value=st.session_state.auto_poll,
                key="hands_free_auto_poll",
            )

        if st.session_state.auto_poll:
            st.session_state.poll_interval = st.slider(
                "Poll Interval (Seconds):",
                min_value=5,
                max_value=120,
                value=st.session_state.poll_interval,
                step=5,
                key="hands_free_poll_interval",
            )

        current_source = st.session_state.active_source
        last_msg = st.session_state.sources_data[current_source].get("last_msg", "")
        if last_msg:
            if "Error" in last_msg:
                st.error(last_msg)
            elif "No " in last_msg or "0" in last_msg:
                st.info(last_msg)
            else:
                st.success(last_msg)

    st.markdown("---")

    current_source = st.session_state.active_source
    active_data = st.session_state.sources_data[current_source]
    log_text = active_data.get("log_text", "")

    if log_text.strip():
        source_context = active_data.get("source_context", current_source)
        hash_input = f"{source_context}\n{log_text}"
        current_hash = hashlib.md5(hash_input.encode("utf-8")).hexdigest()

        if current_hash != active_data.get("log_hash"):
            active_data["log_hash"] = current_hash
            active_data["sec_report"] = ""
            active_data["perf_report"] = ""

            with st.spinner(f"🤖 AI is scanning {current_source} logs for anomalies..."):
                active_data["results"] = extract_critical_logs(log_text, source_context)

        results = active_data.get("results", DEFAULT_RESULTS)
        security_logs = results.get("security", [])
        performance_logs = results.get("performance", [])
        structured_data = results.get("structured_data", [])

        security_count = len(security_logs)
        performance_count = len(performance_logs)
        total_flagged = security_count + performance_count

        st.markdown(f"### 🔍 Active View: **{current_source}** Analysis")

        metric1, metric2, metric3 = st.columns(3)
        metric1.metric("Total Lines Scanned", len(log_text.splitlines()))
        metric2.metric("Security Risks", security_count)
        metric3.metric("Performance Issues", performance_count)

        if total_flagged == 0:
            st.success(f"✅ **Clean Scan for {current_source}!** No critical error signatures detected.")
        else:
            st.warning(f"⚠️ **Found {total_flagged} critical log entries in {current_source}.**")

            if structured_data:
                timeseries_df = generate_timeseries_dataframe(structured_data)

                if not timeseries_df.empty:
                    st.markdown("#### 📈 Visual Telemetry (Anomaly Timeline)")
                    timeline_chart = (
                        alt.Chart(timeseries_df)
                        .mark_area(opacity=0.6, interpolate="monotone")
                        .encode(
                            x=alt.X("Timestamp:T", title="Time (Min)"),
                            y=alt.Y("Count:Q", title="Incident Count"),
                            color=alt.Color(
                                "Type:N",
                                scale=alt.Scale(
                                    domain=["Security", "Performance"],
                                    range=["#ff4b4b", "#ffa421"],
                                ),
                            ),
                            tooltip=["Timestamp:T", "Type:N", "Count:Q"],
                        )
                        .properties(height=250)
                        .interactive()
                    )
                    st.altair_chart(timeline_chart, use_container_width=True)

            st.markdown("---")
            st.markdown(f"### 🛠️ Feature Output Workspaces ({current_source})")

            out_tab1, out_tab2, out_tab3, out_tab4 = st.tabs(
                [
                    "🛡️ SecOps Playbook",
                    "⚡ SRE Performance Playbook",
                    "👁️ Isolated Log Snippets",
                    "📋 Extracted Incident Data",
                ]
            )

            with out_tab1:
                render_playbook_section(
                    incident_type="Security",
                    logs=security_logs,
                    source_name=current_source,
                    btn_label=f"🚀 Generate SecOps Playbook ({current_source})",
                    report_filename="secops_playbook.md",
                    alert_message=f"🚨 **High Severity:** Security risks detected in {current_source}.",
                    alert_type="error",
                )

            with out_tab2:
                render_playbook_section(
                    incident_type="Performance",
                    logs=performance_logs,
                    source_name=current_source,
                    btn_label=f"🚀 Generate SRE Playbook ({current_source})",
                    report_filename="sre_playbook.md",
                    alert_message=f"⚠️ **Medium/High Severity:** Performance bottlenecks detected in {current_source}.",
                    alert_type="warning",
                )

            with out_tab3:
                st.markdown(f"#### Isolated Anomaly Snippets ({current_source})")
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
                st.markdown(f"#### Extracted Structured Context ({current_source})")
                if structured_data:
                    context_df = pd.DataFrame(structured_data)
                    if "Source" in context_df.columns:
                        ordered_columns = [
                            "Source",
                            *[column for column in context_df.columns if column != "Source"],
                        ]
                        context_df = context_df[ordered_columns]

                    st.dataframe(context_df, use_container_width=True, hide_index=True)
                else:
                    st.info("No structured metadata extracted.")

        # --- CROSS-SOURCE COMPARISON VIEW ---
        st.markdown("---")
        with st.expander("🆚 Cross-Source Log Comparison View", expanded=False):
            st.markdown("Compare findings across all fetched AWS telemetry sources side-by-side:")
            cmp_col1, cmp_col2, cmp_col3 = st.columns(3)

            for col, src_name in zip(
                [cmp_col1, cmp_col2, cmp_col3],
                ["S3 Bucket", "CloudWatch Logs", "CloudTrail Events"],
            ):
                with col:
                    st.markdown(f"#### {src_name}")
                    src_info = st.session_state.sources_data[src_name]
                    src_text = src_info.get("log_text", "")

                    if not src_text.strip():
                        st.caption("❌ No log data fetched for this source yet.")
                    else:
                        src_results = src_info.get("results", {})
                        sec_count = len(src_results.get("security", []))
                        perf_count = len(src_results.get("performance", []))

                        st.write(f"**Lines Scanned:** {len(src_text.splitlines())}")
                        st.write(f"**Security Risks:** `{sec_count}`")
                        st.write(f"**Performance Bottlenecks:** `{perf_count}`")

                        if src_results.get("security"):
                            st.markdown("**Top Security Issue:**")
                            st.code(str(src_results["security"][0]), language="log")

                        if src_results.get("performance"):
                            st.markdown("**Top Performance Issue:**")
                            st.code(str(src_results["performance"][0]), language="log")
    else:
        st.info("👈 **Get Started:** Paste, upload, or fetch logs to trigger analysis.")


# ============================================================
# TAB 2: INCIDENT DASHBOARD
# ============================================================
with main_tab2:
    st.markdown("### 📈 Incident Intelligence Dashboard")
    st.caption("Executive overview of incidents detected across all loaded AWS sources.")

    all_security_logs = []
    all_performance_logs = []
    all_structured_data = []

    for src_name, src_info in st.session_state.sources_data.items():
        res = src_info.get("results", {})
        all_security_logs.extend(res.get("security", []))
        all_performance_logs.extend(res.get("performance", []))
        all_structured_data.extend(res.get("structured_data", []))

    all_incidents = [*all_security_logs, *all_performance_logs]

    if not all_incidents:
        st.info("No incidents are available yet. Analyze logs in the Log Analysis & Ingestion tab first.")
    else:
        dashboard = calculate_metrics(all_incidents)
        severity_counts = dashboard.get("severity", {})

        total_incidents = len(all_incidents)
        critical_count = severity_counts.get("Critical", 0)
        high_count = severity_counts.get("High", 0)

        kpi1, kpi2, kpi3, kpi4 = st.columns(4)
        kpi1.metric("Total Incidents", total_incidents)
        kpi2.metric("Security", len(all_security_logs))
        kpi3.metric("Performance", len(all_performance_logs))
        kpi4.metric("Critical / High", critical_count + high_count)

        st.markdown("---")

        chart_column1, chart_column2 = st.columns(2)

        with chart_column1:
            st.markdown("#### Severity Distribution")
            severity_df = dashboard.get("severity_df")

            if severity_df is not None and not severity_df.empty:
                severity_chart = (
                    alt.Chart(severity_df)
                    .mark_arc(innerRadius=55)
                    .encode(
                        theta=alt.Theta("Count:Q", title="Count"),
                        color=alt.Color("Severity:N", title="Severity"),
                        tooltip=["Severity:N", "Count:Q"],
                    )
                    .properties(height=320)
                )
                st.altair_chart(severity_chart, use_container_width=True)

        with chart_column2:
            st.markdown("#### Incident Categories")
            error_df = dashboard.get("error_df")

            if error_df is not None and not error_df.empty:
                category_chart = (
                    alt.Chart(error_df)
                    .mark_bar()
                    .encode(
                        x=alt.X("Count:Q", title="Incident Count"),
                        y=alt.Y("Error:N", sort="-x", title="Category"),
                        tooltip=["Error:N", "Count:Q"],
                    )
                    .properties(height=320)
                )
                st.altair_chart(category_chart, use_container_width=True)

        st.markdown("---")
        st.markdown("#### Export Consolidated Evidence")

        report_markdown = build_incident_report(st.session_state.sources_data)
        st.download_button(
            "📥 Download Multi-Source Incident Report",
            data=report_markdown,
            file_name="multi_source_incident_report.md",
            mime="text/markdown",
            use_container_width=True,
        )


# ============================================================
# TAB 3: PROACTIVE DEFENSE & COMPLIANCE
# ============================================================
with main_tab3:
    st.info("🛡️ Map detected issues to compliance frameworks and generate preventive Terraform or CLI recommendations.")

    framework_column, context_column = st.columns(2)

    with framework_column:
        compliance_framework = st.selectbox(
            "Compliance Framework",
            ["SOC 2", "HIPAA", "PCI-DSS", "CIS AWS Foundations Benchmark"],
        )

    with context_column:
        available_sources = ["All Sources"] + list(st.session_state.sources_data.keys())
        selected_audit_source = st.selectbox("Select Log Source to Audit", available_sources)

    st.markdown("#### 🔍 Selection Context")

    sources_to_audit = (
        list(st.session_state.sources_data.keys())
        if selected_audit_source == "All Sources"
        else [selected_audit_source]
    )

    available_files = []
    file_to_content = {}

    for src_name in sources_to_audit:
        src_info = st.session_state.sources_data[src_name]
        context = src_info.get("source_context", src_name)
        res = src_info.get("results", {})
        sec = res.get("security", [])
        perf = res.get("performance", [])
        
        st.write(f"- **{src_name}**: `{context}` ({len(sec)} Security, {len(perf)} Performance issues)")

        log_text = src_info.get("log_text", "")
        if not log_text.strip():
            continue
            
        if src_name == "S3 Bucket":
            import re
            parts = re.split(r'(?=# S3_OBJECT: )', log_text)
            for part in parts:
                if part.strip():
                    if part.startswith("# S3_OBJECT: "):
                        newline_idx = part.find('\n')
                        if newline_idx != -1:
                            file_name = part[:newline_idx].replace("# S3_OBJECT: ", "").strip()
                            content = part[newline_idx+1:].strip()
                        else:
                            file_name = part.replace("# S3_OBJECT: ", "").strip()
                            content = ""
                            
                        if file_name not in available_files:
                            available_files.append(file_name)
                        file_to_content[file_name] = content
                    else:
                        file_name = f"Raw Data ({src_name})"
                        if file_name not in available_files:
                            available_files.append(file_name)
                        file_to_content[file_name] = file_to_content.get(file_name, "") + "\n" + part.strip()
        else:
            file_name = context
            if file_name not in available_files:
                available_files.append(file_name)
            file_to_content[file_name] = log_text

    st.markdown("#### 📂 File-Level Selection")
    
    if available_files:
        selected_files = st.multiselect(
            "Select specific log files or streams to run against the framework (Leave blank to use ALL):", 
            available_files, 
            key="proact_files"
        )
        
        actual_selected_files = selected_files if selected_files else available_files
        
        if actual_selected_files:
            total_lines = sum(len(file_to_content[f].splitlines()) for f in actual_selected_files)
            eta_seconds = max(10, 5 + (total_lines // 30))
            if eta_seconds > 120:
                eta_str = f"~{eta_seconds // 60} minutes"
            else:
                eta_str = f"~{eta_seconds} seconds"
            
            st.caption(f"⏱️ **Estimated Audit Time:** {eta_str} (Based on {total_lines} lines of logs)")

            if st.button("🚀 Generate Compliance Audit Report", type="primary", use_container_width=True, key="proact_btn"):
                with st.spinner(f"🤖 Llama 3.2 is auditing the selected logs against {compliance_framework}... ({eta_str})"):
                    raw_logs_to_audit = ""
                    for f in actual_selected_files:
                        raw_logs_to_audit += f"\n--- {f} ---\n{file_to_content[f]}\n"
                    
                    log_context = selected_audit_source if selected_audit_source != "All Sources" else "All Sources"
                    st.session_state.proactive_report = generate_proactive_defenses(
                        [], 
                        raw_logs_to_audit,
                        compliance_framework,
                        log_context,
                    )

            if st.session_state.proactive_report:
                st.success("✨ Proactive Defense Analysis Complete!")
                st.markdown(st.session_state.proactive_report)
        else:
            st.warning("⚠️ Please select at least one log file/stream to audit.")
    else:
        st.info("No logs have been fetched yet for the selected source(s). Please go to the 'Log Analysis & Ingestion' tab and fetch logs.")


# ============================================================
# TAB 4: AI QUERY BUILDER
# ============================================================
with main_tab4:
    st.info("🔍 Translate plain English into queries for Athena, CloudWatch Logs Insights, Splunk, or Datadog.")

    query_platform = st.selectbox(
        "Select Target Platform",
        ["AWS Athena", "CloudWatch Logs Insights", "Splunk SPL", "Datadog"],
    )
    query_prompt = st.text_area(
        "Describe what you want to search for:",
        placeholder="e.g., Find all 502 errors grouped by source IP from the last 24 hours",
    )

    if st.button("✨ Generate Query Code", type="primary", use_container_width=True, key="query_btn"):
        if not query_prompt.strip():
            st.error("Please enter a description of the query.")
        else:
            with st.spinner(f"🤖 Translating your request into {query_platform} syntax..."):
                query_code = generate_log_query(query_prompt, query_platform, "AWS Log Telemetry Context")
            st.success(f"✨ {query_platform} Query Generated!")
            st.markdown(query_code)


# ============================================================
# TAB 5: AI CHAT ASSISTANT
# ============================================================
with main_tab5:
    heading_column, button_column = st.columns([4, 1])

    with heading_column:
        st.markdown("### 💬 Interactive Log Investigation Assistant")
        st.caption("Ask questions about specific log files, streams, or anomalies detected.")

    with button_column:
        if st.button("🗑️ Clear Chat", use_container_width=True, key="clear_chat"):
            st.session_state.messages = []
            st.rerun()

    with st.expander("⚙️ Chat Context Settings", expanded=True):
        chat_src_col, chat_type_col = st.columns(2)
        
        with chat_src_col:
            available_sources = ["All Sources"] + list(st.session_state.sources_data.keys())
            chat_audit_source = st.selectbox("Select Log Source", available_sources, key="chat_src")
            
        with chat_type_col:
            chat_context_type = st.selectbox("Context Type", ["Anomalies Only (Faster)", "Raw Logs (Deep Dive)"], key="chat_type")
            
        sources_to_chat = (
            list(st.session_state.sources_data.keys())
            if chat_audit_source == "All Sources"
            else [chat_audit_source]
        )

        chat_available_files = []
        chat_file_to_content = {}
        
        for src_name in sources_to_chat:
            src_info = st.session_state.sources_data[src_name]
            log_text = src_info.get("log_text", "")
            
            if not log_text.strip():
                continue
                
            if src_name == "S3 Bucket":
                import re
                parts = re.split(r'(?=# S3_OBJECT: )', log_text)
                for part in parts:
                    if part.strip():
                        if part.startswith("# S3_OBJECT: "):
                            newline_idx = part.find('\n')
                            if newline_idx != -1:
                                file_name = part[:newline_idx].replace("# S3_OBJECT: ", "").strip()
                                content = part[newline_idx+1:].strip()
                            else:
                                file_name = part.replace("# S3_OBJECT: ", "").strip()
                                content = ""
                            if file_name not in chat_available_files:
                                chat_available_files.append(file_name)
                            chat_file_to_content[file_name] = content
                        else:
                            file_name = f"Raw Data ({src_name})"
                            if file_name not in chat_available_files:
                                chat_available_files.append(file_name)
                            chat_file_to_content[file_name] = chat_file_to_content.get(file_name, "") + "\n" + part.strip()
            else:
                file_name = src_info.get("source_context", src_name)
                if file_name not in chat_available_files:
                    chat_available_files.append(file_name)
                chat_file_to_content[file_name] = log_text

        chat_selected_files = st.multiselect(
            "Select specific logs to include in chat (Leave blank to include ALL):", 
            chat_available_files, 
            key="chat_files"
        )

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if prompt := st.chat_input("Ask about an IP, error, AWS service, RCA, or query..."):
        st.session_state.messages.append({"role": "user", "content": prompt})

        with st.chat_message("user"):
            st.markdown(prompt)

        # Build context_payload dynamically based on user selection
        context_payload = ""
        actual_chat_files = chat_selected_files if chat_selected_files else chat_available_files
        
        if not actual_chat_files:
            context_payload = "No logs selected or available."
        else:
            if chat_context_type == "Raw Logs (Deep Dive)":
                for f in actual_chat_files:
                    context_payload += f"--- {f} ---\n{chat_file_to_content[f]}\n\n"
            else:
                for f in actual_chat_files:
                    file_anomalies = []
                    for src_name in sources_to_chat:
                        res = st.session_state.sources_data[src_name].get("results", {})
                        for item in res.get("structured_data", []):
                            if item.get("Source") == f:
                                file_anomalies.append(item.get("Message"))
                    
                    if file_anomalies:
                        context_payload += f"--- Anomalies in {f} ---\n" + "\n".join(file_anomalies) + "\n\n"
                    else:
                        context_payload += f"--- Anomalies in {f} ---\nNone detected.\n\n"

        with st.chat_message("assistant"):
            with st.spinner("Analyzing context..."):
                response = chat_with_logs(prompt, st.session_state.messages[:-1], context_payload)
                st.markdown(response)

        st.session_state.messages.append({"role": "assistant", "content": response})


# ============================================================
# 🔄 LIVE AUTOMATED POLLING ENGINE
# ============================================================
if st.session_state.get("auto_poll"):
    poll_sec = int(st.session_state.get("poll_interval", 30))
    time.sleep(poll_sec)

    active_src = st.session_state.get("active_source", "S3 Bucket")
    role_arn = st.session_state.get("role_arn")

    if active_src == "CloudWatch Logs" and st.session_state.get("selected_log_group"):
        log_grp = st.session_state.get("selected_log_group")
        content, msg = fetch_cloudwatch_logs(log_grp, role_arn=role_arn)
        st.session_state.sources_data["CloudWatch Logs"]["last_msg"] = f"⚡ [Auto-Polled] {msg}"
        if content:
            st.session_state.sources_data["CloudWatch Logs"]["log_text"] = content
            st.session_state.sources_data["CloudWatch Logs"]["source_context"] = f"CloudWatch: {log_grp}"

    elif active_src == "S3 Bucket":
        selected_bkt = st.session_state.get("selected_bucket")
        if selected_bkt == "ALL BUCKETS (Scan Account)":
            content, msg = fetch_all_s3_buckets_logs(role_arn=role_arn)
            st.session_state.sources_data["S3 Bucket"]["last_msg"] = f"⚡ [Auto-Polled] {msg}"
            if content:
                st.session_state.sources_data["S3 Bucket"]["log_text"] = content
                st.session_state.sources_data["S3 Bucket"]["source_context"] = "All S3 Buckets"
        elif selected_bkt:
            content, msg = fetch_latest_s3_log(selected_bkt, role_arn=role_arn)
            st.session_state.sources_data["S3 Bucket"]["last_msg"] = f"⚡ [Auto-Polled] {msg}"
            if content:
                st.session_state.sources_data["S3 Bucket"]["log_text"] = content
                st.session_state.sources_data["S3 Bucket"]["source_context"] = f"S3 Bucket: {selected_bkt}"

    elif active_src == "CloudTrail Events":
        content, msg = fetch_cloudtrail_events(role_arn=role_arn)
        st.session_state.sources_data["CloudTrail Events"]["last_msg"] = f"⚡ [Auto-Polled] {msg}"
        if content:
            st.session_state.sources_data["CloudTrail Events"]["log_text"] = content
            st.session_state.sources_data["CloudTrail Events"]["source_context"] = "CloudTrail Events"

    st.rerun()