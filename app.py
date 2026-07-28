import time
import streamlit as st

# --- PARSER AND AI ENGINE IMPORTS ---
from log_parser import prepare_raw_logs_for_ai
from ai_engine import analyze_raw_logs_with_ai

# --- AWS FETCHERS INGESTION IMPORTS ---
from aws_fetcher import (
    get_aws_account_info,
    list_s3_buckets, 
    fetch_latest_s3_log, 
    fetch_cloudwatch_logs, 
    fetch_cloudtrail_events
)

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AI Log Analyzer & Live Watcher",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- SIDEBAR: SETTINGS & IDENTITY ---
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/cloud-lighting.png", width=60)
    st.title("Settings & Status")
    
    st.markdown("### ⚙️ Engine Config")
    st.info("**Model:** `llama3.2` (Local)\n\n**Mode:** Full AI Context Inspection")
    
    st.markdown("---")
    st.markdown("### ☁️ AWS Region Config")
    
    # AWS Region Selector Dropdown
    aws_regions_list = [
        "us-east-1",      # US East (N. Virginia)
        "us-east-2",      # US East (Ohio)
        "us-west-1",      # US West (N. California)
        "us-west-2",      # US West (Oregon)
        "ap-south-1",     # Asia Pacific (Mumbai)
        "ap-southeast-1", # Asia Pacific (Singapore)
        "ap-northeast-1", # Asia Pacific (Tokyo)
        "eu-west-1",      # Europe (Ireland)
        "eu-central-1",   # Europe (Frankfurt)
        "sa-east-1"       # South America (São Paulo)
    ]
    
    aws_region = st.selectbox(
        "Select AWS Region:", 
        options=aws_regions_list, 
        index=0, 
        key="aws_region_select"
    )
    
    st.markdown("---")
    st.markdown("### 🆔 Active Account Details")
    
    # Fetch and Display AWS Account ID & IAM Identity
    account_id, user_arn, sts_error = get_aws_account_info(region_name=aws_region)
    
    if account_id:
        st.success(f"🏢 **Account ID:**\n`{account_id}`")
        with st.expander("🔑 View IAM Identity"):
            st.caption(f"**ARN:** `{user_arn}`")
    else:
        st.error("❌ **AWS Credentials Inactive**")
        if sts_error:
            st.caption(f"⚠️ `{sts_error}`")

# --- HEADER ---
st.title("🛡️ AI-Powered Log Analyzer & Incident Triage")
st.caption("Autonomous L1 Incident Triage for Real-Time AWS S3 Logs, CloudWatch, CloudTrail, and Local Files")
st.markdown("---")

# --- TAB NAVIGATION ---
tab1, tab2, tab3, tab4 = st.tabs([
    "🪣 AWS S3", 
    "📈 AWS CloudWatch", 
    "🛡️ AWS CloudTrail", 
    "📁 Upload / Paste Logs"
])


# ==========================================
# 🛰️ TAB 1: AWS S3 AUTO-SYNC & OUTPUT
# ==========================================
with tab1:
    st.markdown("### 🛰️ Live Stream Logs from Amazon S3")
    
    col_bucket, col_prefix = st.columns([2, 1])
    
    with col_bucket:
        buckets, s3_err = list_s3_buckets(region_name=aws_region)
        if buckets:
            selected_bucket = st.selectbox("Select S3 Bucket:", buckets, key="s3_bucket_select")
        else:
            selected_bucket = st.text_input("Enter S3 Bucket Name:", placeholder="my-alb-logs-bucket", key="s3_bucket_text")
            if s3_err:
                st.caption(f"⚠️ Notice: {s3_err}")
                
    with col_prefix:
        s3_prefix = st.text_input("Folder/Prefix (Optional):", placeholder="AWSLogs/", key="s3_prefix_input")

    st.markdown("---")
    
    # Automation Controls
    col_btn, col_auto = st.columns([1, 1])
    
    with col_btn:
        manual_sync = st.button("📡 Sync Once Now", type="secondary", use_container_width=True, key="btn_s3_sync")
        
    with col_auto:
        auto_poll_s3 = st.toggle("🔄 Enable Hands-Free Live Auto-Polling", value=False, key="s3_auto_poll_toggle")
        if auto_poll_s3:
            s3_poll_interval = st.slider("Poll Interval (Seconds):", min_value=10, max_value=300, value=30, step=10, key="s3_poll_slider")

    # Fetching & Output Logic for Tab 1
    if manual_sync or auto_poll_s3:
        if selected_bucket:
            with st.spinner(f"Scanning `{selected_bucket}` for new logs..."):
                content, status_msg = fetch_latest_s3_log(selected_bucket, s3_prefix, aws_region)
                
                if content:
                    st.session_state['s3_logs'] = content
                    st.success(f"✅ {status_msg} (Last checked: {time.strftime('%H:%M:%S')})")
                else:
                    st.error(f"❌ {status_msg}")
        else:
            st.warning("Please specify a valid S3 Bucket name.")

    # Dedicated S3 AI Inspector Output
    if 's3_logs' in st.session_state and st.session_state['s3_logs'].strip():
        s3_log_text = st.session_state['s3_logs']
        prepared_log = prepare_raw_logs_for_ai(s3_log_text)
        
        st.markdown("#### 📊 S3 Log Analytics Workspace")
        st.metric(label="Total Lines Ingested", value=len(s3_log_text.splitlines()))

        with st.expander("👁️ View Raw S3 Stream Sample", expanded=False):
            st.code(prepared_log, language="log")

        if st.button("🚀 Analyze Raw Stream with Llama 3.2", type="primary", use_container_width=True, key="btn_s3_ai"):
            with st.spinner("🤖 Llama 3.2 is reading raw S3 stream and detecting anomalies..."):
                report = analyze_raw_logs_with_ai(prepared_log)
                st.markdown("---")
                st.success("✨ Analysis Complete!")
                st.markdown(report)
                st.download_button(
                    label="📥 Download S3 Incident Report (.md)",
                    data=report,
                    file_name="s3_ai_incident_report.md",
                    mime="text/markdown",
                    key="dl_s3_report"
                )


# ==========================================
# 📈 TAB 2: CLOUDWATCH LOGS WORKSPACE
# ==========================================
with tab2:
    st.markdown("### 📈 CloudWatch Log Ingestion")
    
    col_group, col_stream = st.columns([2, 1])
    with col_group:
        cw_group = st.text_input("CloudWatch Log Group Name:", placeholder="/aws/lambda/my-function", key="cw_group_input")
    with col_stream:
        cw_stream = st.text_input("Log Stream Name (Optional):", placeholder="Latest active stream used if empty", key="cw_stream_input")

    fetch_cw_btn = st.button("📡 Fetch CloudWatch Logs", type="primary", key="btn_cw_fetch")

    if fetch_cw_btn:
        if not cw_group:
            st.warning("Please specify a CloudWatch Log Group Name.")
        else:
            with st.spinner(f"Fetching logs from CloudWatch group `{cw_group}`..."):
                cw_logs, status_msg = fetch_cloudwatch_logs(cw_group, cw_stream, region_name=aws_region)
                
                if cw_logs:
                    st.session_state['cw_logs'] = cw_logs
                    st.success(f"✅ {status_msg}")
                else:
                    st.error(f"❌ {status_msg}")

    # Dedicated CloudWatch AI Inspector Output
    if 'cw_logs' in st.session_state and st.session_state['cw_logs'].strip():
        cw_log_text = st.session_state['cw_logs']
        prepared_log = prepare_raw_logs_for_ai(cw_log_text)
        
        st.markdown("#### 📊 CloudWatch Analytics Workspace")
        st.metric(label="Total Lines Ingested", value=len(cw_log_text.splitlines()))

        with st.expander("👁️ View Raw CloudWatch Stream Sample", expanded=False):
            st.code(prepared_log, language="log")
                    
        if st.button("🚀 Analyze CloudWatch Stream with Llama 3.2", type="primary", use_container_width=True, key="btn_cw_ai"):
            with st.spinner("🤖 Llama 3.2 is inspecting CloudWatch stream for errors..."):
                report = analyze_raw_logs_with_ai(prepared_log)
                st.markdown("---")
                st.success("✨ Analysis Complete!")
                st.markdown(report)
                st.download_button(
                    label="📥 Download CloudWatch Report (.md)",
                    data=report,
                    file_name="cloudwatch_ai_report.md",
                    mime="text/markdown",
                    key="dl_cw_report"
                )


# ==========================================
# 🛡️ TAB 3: CLOUDTRAIL EVENT WORKSPACE
# ==========================================
with tab3:
    st.markdown("### 🛡️ CloudTrail Security & API Audit Ingestion")
    
    col_time, col_auto = st.columns([1, 1])
    
    with col_time:
        time_window = st.slider("Lookback Window (Minutes):", min_value=15, max_value=360, value=60, step=15, key="ct_slider")
    
    with col_auto:
        auto_poll_ct = st.toggle("🔄 Enable Hands-Free Live Auto-Polling", value=False, key="ct_auto_poll_toggle")
        if auto_poll_ct:
            ct_poll_interval = st.slider("Poll Interval (Seconds):", min_value=10, max_value=300, value=30, step=10, key="ct_poll_slider")

    fetch_ct_btn = st.button("🔍 Scan CloudTrail Events Now", type="primary", use_container_width=True, key="btn_ct_fetch")

    if fetch_ct_btn or auto_poll_ct:
        with st.spinner("Scanning CloudTrail API audit logs..."):
            ct_logs, status_msg = fetch_cloudtrail_events(minutes_back=time_window, region_name=aws_region)
            
            if ct_logs:
                st.session_state['ct_logs'] = ct_logs
                st.success(f"✅ {status_msg} (Last checked: {time.strftime('%H:%M:%S')})")
            else:
                st.error(f"❌ {status_msg}")

    # Dedicated CloudTrail AI Inspector Output
    if 'ct_logs' in st.session_state and st.session_state['ct_logs'].strip():
        ct_log_text = st.session_state['ct_logs']
        prepared_log = prepare_raw_logs_for_ai(ct_log_text)
        
        st.markdown("#### 📊 CloudTrail Security Workspace")
        st.metric(label="Total Audit Events", value=len(ct_log_text.splitlines()))

        with st.expander("👁️ View Raw Audit Events Sample", expanded=False):
            st.code(prepared_log, language="text")

        if st.button("🚀 Analyze Audit Stream with Llama 3.2", type="primary", use_container_width=True, key="btn_ct_ai"):
            with st.spinner("🤖 Llama 3.2 is auditing CloudTrail security events..."):
                report = analyze_raw_logs_with_ai(prepared_log)
                st.markdown("---")
                st.success("✨ Security Audit Complete!")
                st.markdown(report)
                st.download_button(
                    label="📥 Download Security Report (.md)",
                    data=report,
                    file_name="cloudtrail_security_report.md",
                    mime="text/markdown",
                    key="dl_ct_report"
                )


# ==========================================
# 📁 TAB 4: UPLOAD & PASTE LOGS WORKSPACE
# ==========================================
with tab4:
    st.markdown("### 📁 Static Log Ingestion (Upload or Paste)")
    
    sub_tab1, sub_tab2 = st.tabs(["📋 Paste Raw Text", "📁 Upload Log File"])
    
    local_log_text = ""
    
    with sub_tab1:
        pasted_logs = st.text_area(
            "Paste raw log entries here:",
            height=180,
            placeholder="e.g., Paste raw web logs, container output, or stack traces...",
            key="pasted_text_input"
        )
        if pasted_logs.strip():
            local_log_text = pasted_logs

    with sub_tab2:
        uploaded_file = st.file_uploader(
            "Upload a log file (.log, .txt, .json):", 
            type=["log", "txt", "json"],
            key="file_uploader_widget"
        )
        if uploaded_file is not None:
            local_log_text = uploaded_file.read().decode("utf-8")
            st.success(f"📄 Loaded file: **{uploaded_file.name}**")

    # Static Logs AI Output
    if local_log_text.strip():
        prepared_log = prepare_raw_logs_for_ai(local_log_text)
        
        st.markdown("---")
        st.markdown("#### 📊 Static Log Analytics Workspace")
        st.metric(label="Total Lines Ingested", value=len(local_log_text.splitlines()))

        with st.expander("👁️ View Uploaded Log Sample", expanded=False):
            st.code(prepared_log, language="log")

        if st.button("🚀 Analyze File/Text with Llama 3.2", type="primary", use_container_width=True, key="btn_static_ai"):
            with st.spinner("🤖 Llama 3.2 is scanning log content for errors..."):
                report = analyze_raw_logs_with_ai(prepared_log)
                st.markdown("---")
                st.success("✨ Analysis Complete!")
                st.markdown(report)
                st.download_button(
                    label="📥 Download Incident Report (.md)",
                    data=report,
                    file_name="static_log_ai_report.md",
                    mime="text/markdown",
                    key="dl_static_report"
                )


# --- AUTO-REFRESH LOOP FOR S3 AND CLOUDTRAIL AUTO-POLLING ---
s3_polling = st.session_state.get('s3_auto_poll_toggle', False)
ct_polling = st.session_state.get('ct_auto_poll_toggle', False)

if s3_polling or ct_polling:
    interval = st.session_state.get('ct_poll_slider', 30) if ct_polling else st.session_state.get('s3_poll_slider', 30)
    time.sleep(interval)
    st.rerun()