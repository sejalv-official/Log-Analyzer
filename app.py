import time
import streamlit as st
from log_parser import extract_critical_logs
from ai_engine import generate_remediation_playbook
from s3_fetcher import list_s3_buckets, fetch_latest_s3_log

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AI Log Analyzer & Live Watcher",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- SIDEBAR: SETTINGS ---
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/cloud-lighting.png", width=60)
    st.title("Settings & Status")
    
    st.markdown("### ⚙️ Engine Config")
    st.info("**Model:** `llama3.2` (Local)\n\n**Mode:** AWS S3 Live Auto-Polling")
    
    st.markdown("---")
    st.markdown("### ☁️ AWS Config")
    aws_region = st.text_input("AWS Region", value="us-east-1")
    st.caption("Ensure AWS credentials are configured via `aws configure`.")

# --- HEADER ---
st.title("🛡️ AI-Powered Log Analyzer & Incident Triage")
st.caption("Automated L1 Incident Triage for Real-Time AWS S3 Logs & Static Log Files")
st.markdown("---")

# --- INPUT TABS ---
tab1, tab2, tab3 = st.tabs(["🪣 AWS S3 Auto-Sync", "📋 Paste Raw Text", "📁 Upload Log File"])

log_text = ""

# --- TAB 1: S3 AUTO-SYNC WITH AUTO-POLLING ---
with tab1:
    st.markdown("### 🛰️ Live Stream Logs from Amazon S3")
    
    col_bucket, col_prefix = st.columns([2, 1])
    
    with col_bucket:
        buckets, s3_err = list_s3_buckets(region_name=aws_region)
        if buckets:
            selected_bucket = st.selectbox("Select S3 Bucket:", buckets)
        else:
            selected_bucket = st.text_input("Enter S3 Bucket Name:", placeholder="my-alb-logs-bucket")
            if s3_err:
                st.caption(f"⚠️ Notice: {s3_err}")
                
    with col_prefix:
        s3_prefix = st.text_input("Folder/Prefix (Optional):", placeholder="AWSLogs/")

    st.markdown("---")
    
    # Automation Controls
    col_btn, col_auto = st.columns([1, 1])
    
    with col_btn:
        manual_sync = st.button("📡 Sync Once Now", type="secondary", use_container_width=True)
        
    with col_auto:
        auto_poll = st.toggle("🔄 Enable Hands-Free Live Auto-Polling", value=False)
        if auto_poll:
            poll_interval = st.slider("Poll Interval (Seconds):", min_value=10, max_value=300, value=30, step=10)

    # Fetching logic
    if manual_sync or auto_poll:
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

    if 's3_logs' in st.session_state:
        log_text = st.session_state['s3_logs']

# --- TAB 2: PASTE TEXT ---
with tab2:
    pasted_logs = st.text_area(
        "Paste raw log entries here:",
        height=180,
        placeholder="e.g., 2026-07-23 14:32:05 ALB 502 Bad Gateway AccessDenied..."
    )
    if pasted_logs:
        log_text = pasted_logs

# --- TAB 3: FILE UPLOAD ---
with tab3:
    uploaded_file = st.file_uploader("Upload a log file (.log, .txt, .json)", type=["log", "txt", "json"])
    if uploaded_file is not None:
        log_text = uploaded_file.read().decode("utf-8")
        st.success(f"📄 Successfully loaded: **{uploaded_file.name}**")

st.markdown("---")

# --- COMMON ANALYSIS ENGINE ---
if log_text.strip():
    matched_errors = extract_critical_logs(log_text)
    
    col1, col2 = st.columns(2)
    col1.metric(label="Total Lines Scanned", value=len(log_text.splitlines()))
    col2.metric(label="Critical Issues Flagged", value=len(matched_errors))

    st.markdown("### 🔍 Analysis Overview")

    if not matched_errors:
        st.success("✅ **Clean Scan!** No critical error signatures detected in the current log.")
    else:
        st.warning(f"⚠️ **Found {len(matched_errors)} critical log entries.**")
        
        with st.expander("👁️ View Isolated Error Snippets", expanded=True):
            for err in matched_errors:
                st.code(err, language="log")
                
        st.markdown("### 🤖 AI Incident Playbook")
        
        if st.button("🚀 Generate AI Remediation Guide", type="primary", use_container_width=True):
            with st.spinner("🤖 Llama 3.2 is analyzing errors and generating RCA report..."):
                report = generate_remediation_playbook(matched_errors)
                st.markdown("---")
                st.success("✨ Analysis Complete!")
                st.markdown(report)
                
                st.download_button(
                    label="📥 Download Remediation Report (.md)",
                    data=report,
                    file_name="remediation_playbook.md",
                    mime="text/markdown"
                )

# --- AUTO-REFRESH LOOP FOR AUTO-POLLING ---
if auto_poll:
    time.sleep(poll_interval)
    st.rerun()