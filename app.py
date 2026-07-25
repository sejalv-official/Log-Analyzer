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
    st.info("**Model:** `llama3.2` (Local)\n\n**Mode:** Multi-Feature Isolation")
    
    st.markdown("---")
    st.markdown("### ☁️ AWS Config")
    aws_region = st.text_input("AWS Region", value="us-east-1")
    st.caption("Ensure AWS credentials are configured via active terminal session.")

# --- HEADER ---
st.title("🛡️ AI-Powered Log Analyzer & Incident Triage")
st.caption("Automated L1 Incident Triage for Real-Time AWS S3 Logs, Static Log Files, and Raw Text")
st.markdown("---")

# --- INPUT TABS ---
tab1, tab2, tab3 = st.tabs(["🪣 AWS S3 Auto-Sync", "📋 Paste Raw Text", "📁 Upload Log File"])


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
        auto_poll = st.toggle("🔄 Enable Hands-Free Live Auto-Polling", value=False, key="s3_auto_poll_toggle")
        if auto_poll:
            poll_interval = st.slider("Poll Interval (Seconds):", min_value=10, max_value=300, value=30, step=10, key="s3_poll_slider")

    # Fetching & Output Logic for Tab 1
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

    # Dedicated S3 Output Window
    if 's3_logs' in st.session_state and st.session_state['s3_logs'].strip():
        s3_log_text = st.session_state['s3_logs']
        matched_errors = extract_critical_logs(s3_log_text)
        
        st.markdown("#### 📊 S3 Log Analysis Dashboard")
        col1, col2 = st.columns(2)
        col1.metric(label="Total Lines Scanned", value=len(s3_log_text.splitlines()))
        col2.metric(label="Critical Issues Flagged", value=len(matched_errors))

        if not matched_errors:
            st.success("✅ **Clean Scan!** No critical error signatures detected in the current S3 log.")
        else:
            st.warning(f"⚠️ **Found {len(matched_errors)} critical log entries.**")
            with st.expander("👁️ View Isolated S3 Error Snippets", expanded=True):
                for err in matched_errors:
                    st.code(err, language="log")
            
            if st.button("🚀 Generate S3 AI Remediation Guide", type="primary", use_container_width=True, key="btn_s3_ai"):
                with st.spinner("🤖 Llama 3.2 is analyzing S3 errors..."):
                    report = generate_remediation_playbook(matched_errors)
                    st.markdown("---")
                    st.success("✨ Analysis Complete!")
                    st.markdown(report)
                    st.download_button(
                        label="📥 Download S3 Remediation Report (.md)",
                        data=report,
                        file_name="s3_remediation_playbook.md",
                        mime="text/markdown",
                        key="dl_s3_report"
                    )


# ==========================================
# 📋 TAB 2: RAW TEXT INPUT & OUTPUT
# ==========================================
with tab2:
    st.markdown("### 📋 Manual Raw Text Analysis")
    
    pasted_logs = st.text_area(
        "Paste raw log entries here:",
        height=180,
        placeholder="e.g., 2026-07-23 14:32:05 ALB 502 Bad Gateway AccessDenied...",
        key="raw_pasted_logs"
    )
    
    analyze_raw_btn = st.button("🔍 Analyze Raw Text", type="primary", key="btn_raw_analyze")

    # Dedicated Raw Text Output Window
    if analyze_raw_btn or pasted_logs.strip():
        if pasted_logs.strip():
            matched_errors = extract_critical_logs(pasted_logs)
            
            st.markdown("#### 📊 Raw Text Analysis Dashboard")
            col1, col2 = st.columns(2)
            col1.metric(label="Total Lines Scanned", value=len(pasted_logs.splitlines()))
            col2.metric(label="Critical Issues Flagged", value=len(matched_errors))

            if not matched_errors:
                st.success("✅ **Clean Scan!** No critical error signatures detected in pasted text.")
            else:
                st.warning(f"⚠️ **Found {len(matched_errors)} critical log entries.**")
                with st.expander("👁️ View Isolated Raw Error Snippets", expanded=True):
                    for err in matched_errors:
                        st.code(err, language="log")
                
                if st.button("🚀 Generate Raw Text AI Remediation Guide", type="primary", use_container_width=True, key="btn_raw_ai"):
                    with st.spinner("🤖 Llama 3.2 is analyzing raw text errors..."):
                        report = generate_remediation_playbook(matched_errors)
                        st.markdown("---")
                        st.success("✨ Analysis Complete!")
                        st.markdown(report)
                        st.download_button(
                            label="📥 Download Raw Text Report (.md)",
                            data=report,
                            file_name="raw_text_remediation_playbook.md",
                            mime="text/markdown",
                            key="dl_raw_report"
                        )
        else:
            st.info("Paste log entries above and click analyze.")


# ==========================================
# 📁 TAB 3: FILE UPLOAD & OUTPUT
# ==========================================
with tab3:
    st.markdown("### 📁 Uploaded Log File Analysis")
    
    uploaded_file = st.file_uploader(
        "Upload a log file (.log, .txt, .json)", 
        type=["log", "txt", "json"],
        key="file_uploader_widget"
    )
    
    # Dedicated File Upload Output Window
    if uploaded_file is not None:
        file_log_text = uploaded_file.read().decode("utf-8")
        st.success(f"📄 Successfully loaded: **{uploaded_file.name}**")
        
        matched_errors = extract_critical_logs(file_log_text)
        
        st.markdown("#### 📊 File Upload Analysis Dashboard")
        col1, col2 = st.columns(2)
        col1.metric(label="Total Lines Scanned", value=len(file_log_text.splitlines()))
        col2.metric(label="Critical Issues Flagged", value=len(matched_errors))

        if not matched_errors:
            st.success("✅ **Clean Scan!** No critical error signatures detected in this file.")
        else:
            st.warning(f"⚠️ **Found {len(matched_errors)} critical log entries.**")
            with st.expander("👁️ View Isolated File Error Snippets", expanded=True):
                for err in matched_errors:
                    st.code(err, language="log")
            
            if st.button("🚀 Generate File AI Remediation Guide", type="primary", use_container_width=True, key="btn_file_ai"):
                with st.spinner("🤖 Llama 3.2 is analyzing file errors..."):
                    report = generate_remediation_playbook(matched_errors)
                    st.markdown("---")
                    st.success("✨ Analysis Complete!")
                    st.markdown(report)
                    st.download_button(
                        label="📥 Download File Remediation Report (.md)",
                        data=report,
                        file_name="file_remediation_playbook.md",
                        mime="text/markdown",
                        key="dl_file_report"
                    )


# --- AUTO-REFRESH LOOP FOR S3 AUTO-POLLING ---
if 's3_auto_poll_toggle' in st.session_state and st.session_state['s3_auto_poll_toggle']:
    time.sleep(poll_interval)
    st.rerun()