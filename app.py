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
from correlation_engine import find_cross_source_correlations
from incident_store import (
    calculate_mttr_minutes,
    clear_incident_rca,
    get_correlation,
    get_incident,
    get_incident_counts,
    initialize_database,
    list_correlations,
    list_incidents,
    save_correlation_group,
    save_detected_incidents,
    save_incident_rca,
    update_correlation_status,
    update_incident_status,
)


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


def calculate_rca_confidence(incident: dict) -> tuple[int, str]:
    """
    Calculate evidence confidence deterministically.
    The LLM does not choose this score.
    """
    score = 35

    events = int(incident.get("event_count") or 1)
    severity = str(incident.get("severity") or "Unknown")
    category = str(incident.get("category") or "Other")
    source = str(incident.get("source") or "Unknown Source")

    if events >= 2:
        score += 10
    if events >= 5:
        score += 10

    if severity in {"High", "Critical"}:
        score += 10

    if category not in {"", "Other", "Unknown"}:
        score += 10

    if source not in {"", "Unknown", "Unknown Source"}:
        score += 10

    if incident.get("first_seen") and incident.get("last_seen"):
        score += 5

    score = min(score, 95)

    if score >= 85:
        label = "High"
    elif score >= 65:
        label = "Medium"
    else:
        label = "Low"

    return score, label

def build_rca_evidence(incident: dict) -> list[str]:
    """Create transparent evidence used to support the RCA."""
    evidence = [
        f"Incident ID: {incident.get('incident_id', 'Unknown')}",
        f"Source: {incident.get('source', 'Unknown Source')}",
        f"Type: {incident.get('incident_type', 'Unknown')}",
        f"Severity: {incident.get('severity', 'Unknown')}",
        f"Category: {incident.get('category', 'Other')}",
        f"Correlated log events: {int(incident.get('event_count') or 1)}",
    ]

    if incident.get("first_seen"):
        evidence.append(f"First seen: {incident['first_seen']}")

    if incident.get("last_seen"):
        evidence.append(f"Last seen: {incident['last_seen']}")

    if incident.get("message"):
        evidence.append(
            "Representative log evidence: "
            + str(incident["message"])[:1500]
        )

    return evidence

def generate_incident_rca(incident: dict):
    """Generate and package one RCA for one correlated incident."""
    score, label = calculate_rca_confidence(incident)
    evidence = build_rca_evidence(incident)

    prompt_context = [
        "CORRELATED INCIDENT CONTEXT",
        *evidence,
        "",
        "Generate a concise Root Cause Analysis for this one incident.",
        "Include these sections:",
        "1. Probable Root Cause",
        "2. Technical Impact",
        "3. Supporting Evidence",
        "4. Immediate Remediation",
        "5. Long-Term Prevention",
        "Do not claim certainty beyond the provided evidence.",
    ]

    incident_type = str(
        incident.get("incident_type") or "security"
    ).lower()

    playbook_type = (
        "security"
        if incident_type == "security"
        else "performance"
    )

    report = generate_remediation_playbook(
        prompt_context,
        playbook_type,
    )

    if not report or not str(report).strip():
        raise RuntimeError(
            "The local AI model returned an empty RCA report."
        )

    return str(report), score, label, evidence

def refresh_cross_source_correlations():
    """
    Evaluate persistent incidents and store parent correlation groups.
    Child incidents are never deleted or modified by this operation.
    """
    persistent_incidents = list_incidents(limit=500)

    engine_input = []

    for item in persistent_incidents:
        engine_input.append(
            {
                "incident_id": item.get("Incident ID"),
                "created_at": item.get("Created At"),
                "first_seen": item.get("First Seen"),
                "last_seen": item.get("Last Seen"),
                "source": item.get("Source"),
                "incident_type": item.get("Type"),
                "severity": item.get("Severity"),
                "category": item.get("Category"),
                "message": item.get("Message"),
                "status": item.get("Status"),
            }
        )

    candidates = find_cross_source_correlations(
        engine_input,
        window_minutes=15,
        minimum_score=50,
    )

    created = []
    updated = []

    for candidate in candidates:
        correlation_id, created_new = save_correlation_group(
            candidate
        )

        if not correlation_id:
            continue

        if created_new:
            created.append(correlation_id)
        else:
            updated.append(correlation_id)

    return created, updated

def build_correlation_summary(correlation):
    """
    Build deterministic context for a cross-source parent incident.
    """
    child_incidents = correlation.get("incidents") or []

    lines = [
        f"Correlation ID: {correlation.get('correlation_id')}",
        f"Correlation confidence: {correlation.get('confidence', 0)}%",
        "Sources: "
        + ", ".join(correlation.get("sources") or []),
        f"First seen: {correlation.get('first_seen')}",
        f"Last seen: {correlation.get('last_seen')}",
        "",
        "Correlation reasons:",
    ]

    for reason in correlation.get("reasons") or []:
        lines.append(f"- {reason}")

    lines.extend(
        [
            "",
            "Related incidents:",
        ]
    )

    for incident in child_incidents:
        lines.extend(
            [
                f"- {incident.get('incident_id')}: "
                f"{incident.get('category')} / "
                f"{incident.get('severity')} / "
                f"{incident.get('source')}",
                f"  Evidence: {str(incident.get('message') or '')[:1000]}",
            ]
        )

    return "\n".join(lines)


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

                # Persist detected incidents in SQLite.
                # Repeated matching events are correlated by incident_store.py.
                if active_data["results"].get("structured_data"):
                    saved_incident_ids = save_detected_incidents(
                        active_data["results"].get("structured_data", []),
                        default_source=source_context,
                    )

                    if saved_incident_ids:
                        st.success(
                            f"💾 Created {len(saved_incident_ids)} new incident(s). "
                            "Repeated matching events were aggregated automatically."
                        )


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

    st.markdown("### 🕘 Persistent Incident History")
    st.caption(
        "Incidents stored in SQLite remain available after page refreshes "
        "and Streamlit restarts. Repeated matching log events within a "
        "15-minute window are correlated into one incident."
    )

    history = list_incidents(limit=200)

    if history:
        history_df = pd.DataFrame(history)
        counts = get_incident_counts()
        mttr_minutes = calculate_mttr_minutes()

        total_events = int(history_df["Events"].sum()) if "Events" in history_df.columns else len(history_df)

        hist_col1, hist_col2, hist_col3, hist_col4, hist_col5 = st.columns(5)
        hist_col1.metric("Open", counts.get("Open", 0))
        hist_col2.metric("Investigating", counts.get("Investigating", 0))
        hist_col3.metric("Resolved", counts.get("Resolved", 0))
        hist_col4.metric("Log Events", total_events)
        hist_col5.metric("MTTR", f"{mttr_minutes} min")

        status_filter = st.multiselect(
            "Filter by Status",
            options=["Open", "Investigating", "Resolved"],
            default=["Open", "Investigating", "Resolved"],
            key="incident_history_status_filter",
        )

        filtered_history_df = history_df
        if status_filter:
            filtered_history_df = history_df[
                history_df["Status"].isin(status_filter)
            ]

        st.dataframe(
            filtered_history_df,
            width="stretch",
            hide_index=True,
        )

        st.download_button(
            "📥 Download Incident History CSV",
            data=history_df.to_csv(index=False),
            file_name="persistent_incident_history.csv",
            mime="text/csv",
            width="stretch",
            key="download_persistent_incident_history",
        )

        st.markdown("#### 🔄 Update Incident Status")

        incident_ids = [
            incident["Incident ID"]
            for incident in history
            if incident.get("Incident ID")
        ]

        status_col1, status_col2 = st.columns(2)

        with status_col1:
            selected_incident = st.selectbox(
                "Incident",
                options=incident_ids,
                key="history_incident_select",
            )

        with status_col2:
            new_status = st.selectbox(
                "New Status",
                options=["Open", "Investigating", "Resolved"],
                key="history_status_select",
            )

        if st.button(
            "Update Incident Status",
            type="primary",
            width="stretch",
            key="update_incident_status_button",
        ):
            update_incident_status(
                selected_incident,
                new_status,
            )
            st.success(
                f"{selected_incident} updated to {new_status}."
            )
            st.rerun()


        st.markdown("---")
        st.markdown("### 🤖 AI Root Cause Analysis")
        st.caption(
            "Generate one RCA for the correlated incident instead of "
            "separate RCA reports for every underlying log event."
        )

        selected_incident_data = get_incident(selected_incident)

        if selected_incident_data:
            confidence_score, confidence_label = (
                calculate_rca_confidence(selected_incident_data)
            )

            rca_metric1, rca_metric2, rca_metric3 = st.columns(3)

            rca_metric1.metric(
                "Incident",
                selected_incident,
            )
            rca_metric2.metric(
                "Correlated Events",
                int(selected_incident_data.get("event_count") or 1),
            )
            rca_metric3.metric(
                "Evidence Confidence",
                f"{confidence_score}% ({confidence_label})",
            )

            if selected_incident_data.get("rca_report"):
                st.success(
                    "✅ A saved AI RCA is available for this incident."
                )

                with st.expander(
                    "🔎 Supporting Evidence",
                    expanded=False,
                ):
                    for evidence_item in (
                        selected_incident_data.get("rca_evidence") or []
                    ):
                        st.markdown(f"- {evidence_item}")

                st.markdown("#### Root Cause Analysis")
                st.markdown(
                    selected_incident_data["rca_report"]
                )

                if selected_incident_data.get("rca_generated_at"):
                    st.caption(
                        "Generated at: "
                        + str(
                            selected_incident_data["rca_generated_at"]
                        )
                    )

                download_col, regenerate_col = st.columns(2)

                with download_col:
                    st.download_button(
                        "📥 Download RCA",
                        data=selected_incident_data["rca_report"],
                        file_name=f"{selected_incident}_rca.md",
                        mime="text/markdown",
                        width="stretch",
                        key=f"download_rca_{selected_incident}",
                    )

                with regenerate_col:
                    if st.button(
                        "🔄 Regenerate RCA",
                        width="stretch",
                        key=f"regenerate_rca_{selected_incident}",
                    ):
                        clear_incident_rca(selected_incident)
                        st.rerun()

            else:
                with st.expander(
                    "🔎 Evidence that will be sent to AI",
                    expanded=True,
                ):
                    for evidence_item in build_rca_evidence(
                        selected_incident_data
                    ):
                        st.markdown(f"- {evidence_item}")

                if st.button(
                    "🤖 Generate AI RCA",
                    type="primary",
                    width="stretch",
                    key=f"generate_rca_{selected_incident}",
                ):
                    try:
                        with st.spinner(
                            "Llama 3.2 is analyzing the correlated incident..."
                        ):
                            (
                                rca_report,
                                score,
                                label,
                                evidence,
                            ) = generate_incident_rca(
                                selected_incident_data
                            )

                            save_incident_rca(
                                incident_id=selected_incident,
                                rca_report=rca_report,
                                confidence=score,
                                evidence=evidence,
                            )

                        st.success(
                            f"✨ RCA generated with {score}% "
                            f"{label.lower()} evidence confidence."
                        )
                        st.rerun()

                    except Exception as exc:
                        st.error(
                            f"Unable to generate RCA: {exc}"
                        )

    else:
        st.info(
            "No persistent incidents have been stored yet. "
            "Analyze logs containing detected security or performance issues."
        )



# ============================================================
# FEATURE 3: CROSS-SOURCE INCIDENT CORRELATION
# ============================================================
with main_tab2:
    st.markdown("---")
    st.markdown("### 🔗 Cross-Source Incident Correlation")
    st.caption(
        "Correlate related CloudTrail, CloudWatch, ALB/S3 and application "
        "incidents into a parent incident without deleting the original records."
    )

    correlation_action_col, correlation_info_col = st.columns([1, 2])

    with correlation_action_col:
        if st.button(
            "🔍 Run Correlation Engine",
            type="primary",
            width="stretch",
            key="run_correlation_engine",
        ):
            with st.spinner(
                "Correlating incidents across AWS log sources..."
            ):
                created_correlations, updated_correlations = (
                    refresh_cross_source_correlations()
                )

            if created_correlations:
                st.success(
                    f"Created {len(created_correlations)} new "
                    "cross-source correlation group(s)."
                )
            elif updated_correlations:
                st.info(
                    "Existing correlation groups were refreshed."
                )
            else:
                st.info(
                    "No cross-source incident relationships met "
                    "the correlation threshold."
                )

    with correlation_info_col:
        st.info(
            "Current rules use a 15-minute window plus shared AWS resources, "
            "services, error signals, severity and source diversity."
        )

    correlations = list_correlations(limit=100)

    if correlations:
        correlation_rows = []

        for correlation in correlations:
            correlation_rows.append(
                {
                    "Correlation ID": correlation.get("correlation_id"),
                    "Confidence": f"{correlation.get('confidence', 0)}%",
                    "Sources": ", ".join(
                        correlation.get("sources") or []
                    ),
                    "Related Incidents": ", ".join(
                        correlation.get("incident_ids") or []
                    ),
                    "First Seen": correlation.get("first_seen"),
                    "Last Seen": correlation.get("last_seen"),
                    "Status": correlation.get("status"),
                }
            )

        st.dataframe(
            pd.DataFrame(correlation_rows),
            width="stretch",
            hide_index=True,
        )

        correlation_ids = [
            item.get("correlation_id")
            for item in correlations
            if item.get("correlation_id")
        ]

        selected_correlation = st.selectbox(
            "Select Correlated Incident",
            correlation_ids,
            key="selected_correlation",
        )

        correlation_detail = get_correlation(
            selected_correlation
        )

        if correlation_detail:
            corr_metric1, corr_metric2, corr_metric3 = st.columns(3)

            corr_metric1.metric(
                "Correlation",
                selected_correlation,
            )

            corr_metric2.metric(
                "Related Incidents",
                len(
                    correlation_detail.get("incident_ids")
                    or []
                ),
            )

            corr_metric3.metric(
                "Correlation Confidence",
                f"{correlation_detail.get('confidence', 0)}%",
            )

            with st.expander(
                "🔎 Why these incidents were correlated",
                expanded=True,
            ):
                for reason in (
                    correlation_detail.get("reasons")
                    or []
                ):
                    st.markdown(f"- {reason}")

            st.markdown("#### Related Child Incidents")

            child_rows = []

            for child in (
                correlation_detail.get("incidents")
                or []
            ):
                child_rows.append(
                    {
                        "Incident ID": child.get("incident_id"),
                        "Source": child.get("source"),
                        "Type": child.get("incident_type"),
                        "Severity": child.get("severity"),
                        "Category": child.get("category"),
                        "Events": child.get("event_count"),
                    }
                )

            st.dataframe(
                pd.DataFrame(child_rows),
                width="stretch",
                hide_index=True,
            )

            st.markdown("#### Correlation Status")

            corr_status_col1, corr_status_col2 = st.columns(2)

            with corr_status_col1:
                new_correlation_status = st.selectbox(
                    "New Correlation Status",
                    [
                        "Open",
                        "Investigating",
                        "Resolved",
                    ],
                    index=[
                        "Open",
                        "Investigating",
                        "Resolved",
                    ].index(
                        correlation_detail.get(
                            "status",
                            "Open",
                        )
                    ),
                    key=f"correlation_status_{selected_correlation}",
                )

            with corr_status_col2:
                st.write("")
                st.write("")

                if st.button(
                    "Update Correlation Status",
                    width="stretch",
                    key=f"update_corr_{selected_correlation}",
                ):
                    update_correlation_status(
                        selected_correlation,
                        new_correlation_status,
                    )
                    st.success(
                        f"{selected_correlation} updated to "
                        f"{new_correlation_status}."
                    )
                    st.rerun()

            st.markdown("#### Combined Investigation Context")

            combined_context = build_correlation_summary(
                correlation_detail
            )

            st.code(
                combined_context,
                language="text",
            )

            st.download_button(
                "📥 Download Correlation Evidence",
                data=combined_context,
                file_name=f"{selected_correlation}_evidence.txt",
                mime="text/plain",
                width="stretch",
                key=f"download_corr_{selected_correlation}",
            )

    else:
        st.info(
            "No cross-source correlation groups exist yet. "
            "Analyze incidents from two or more sources and run "
            "the Correlation Engine."
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
        log_context = st.selectbox("Log Context to Audit", ["S3", "CloudWatch", "CloudTrail", "Application Logs"])

    all_structured_data = []
    all_raw_context = []

    for src_info in st.session_state.sources_data.values():
        res = src_info.get("results", {})
        all_structured_data.extend(res.get("structured_data", []))
        all_raw_context.extend(res.get("security", []))
        all_raw_context.extend(res.get("performance", []))

    if all_raw_context:
        if st.button("🚀 Generate Compliance Audit Report", type="primary", use_container_width=True, key="proact_btn"):
            with st.spinner(f"🤖 Llama 3.2 is auditing logs against {compliance_framework}..."):
                st.session_state.proactive_report = generate_proactive_defenses(
                    all_structured_data,
                    "\n".join(str(i) for i in all_raw_context),
                    compliance_framework,
                    log_context,
                )

        if st.session_state.proactive_report:
            st.success("✨ Proactive Defense Analysis Complete!")
            st.markdown(st.session_state.proactive_report)
    else:
        st.warning("⚠️ No security or performance issues are available. Fetch logs first.")


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
        st.caption("Ask questions about anomalies detected across S3, CloudWatch, or CloudTrail.")

    with button_column:
        if st.button("🗑️ Clear Chat", use_container_width=True, key="clear_chat"):
            st.session_state.messages = []
            st.rerun()

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if prompt := st.chat_input("Ask about an IP, error, AWS service, RCA, or query..."):
        st.session_state.messages.append({"role": "user", "content": prompt})

        with st.chat_message("user"):
            st.markdown(prompt)

        context_payload = ""
        for src_name, src_info in st.session_state.sources_data.items():
            res = src_info.get("results", {})
            if res.get("security") or res.get("performance"):
                context_payload += f"--- {src_name} ---\nSecurity: {res.get('security')}\nPerformance: {res.get('performance')}\n"

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