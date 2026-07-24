import streamlit as st
import pandas as pd
import hashlib
from log_parser import extract_critical_logs
from ai_engine import generate_remediation_playbook, chat_with_logs, generate_proactive_defenses, generate_log_query
from s3_fetcher import list_s3_buckets, fetch_latest_s3_log
from metrics_engine import generate_timeseries_dataframe
import time
import altair as alt

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AI Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- SESSION STATE ---
if "log_hash" not in st.session_state:
    st.session_state.log_hash = ""
if "messages" not in st.session_state:
    st.session_state.messages = []
if "results" not in st.session_state:
    st.session_state.results = {"security": [], "performance": [], "structured_data": []}

# --- CUSTOM STYLING FOR BETTER READABILITY ---
st.markdown("""
    <style>
    /* Clean font and title styling */
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E88E5;
        margin-bottom: 0px;
    }
    .sub-header {
        font-size: 1rem;
        color: #666;
        margin-bottom: 20px;
    }
    /* Card-like containers for outputs */
    .stCodeBlock {
        border-radius: 8px;
    }
    </style>
""", unsafe_allow_html=True)

# --- SIDEBAR: SETTINGS & INFO ---
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/cloud-lighting.png", width=60)
    st.title("Settings & Status")
    
    st.markdown("### ⚙️ Engine Config")
    st.info("**Model:** `llama3.2:1b` (Local)\n\n**Mode:** Privacy-Preserving")
    
    st.markdown("---")
    st.markdown("### 📌 Supported Log Formats")
    st.caption("• AWS Application Load Balancer (ALB)\n• AWS CloudWatch Logs\n• AWS CloudTrail Events\n• Custom Application Logs")
    
    st.markdown("---")
    st.caption("Developed for Automated L1 Incident Triage.")

# --- MAIN HEADER ---
st.markdown('<div class="main-header">🛡️ AI-Powered Log Analyzer</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Automated Root Cause Analysis & Remediation for AWS Infrastructure Logs</div>', unsafe_allow_html=True)

# --- TOP LEVEL TABS ---
main_tab1, main_tab2, main_tab3, main_tab4 = st.tabs([
    "📊 Log Analysis & Ingestion", 
    "🛡️ Proactive Defense & Compliance", 
    "🔍 AI Query Builder", 
    "💬 AI Chat Assistant"
])

with main_tab1:
    st.markdown("### 📥 Select Input Method")
    tab1, tab2, tab3 = st.tabs(["📋 Paste Raw Text", "📁 Upload Log File", "☁️ Pull from AWS"])
    
    log_text = ""
    with tab1:
        pasted_logs = st.text_area(
            "Paste log lines directly from CloudWatch or terminal:",
            height=180,
            placeholder="e.g., 2026-07-21 14:32:05 ALB 502 Bad Gateway /api/v1/checkout AccessDenied..."
        )
        if pasted_logs:
            log_text = pasted_logs
            
    with tab2:
        uploaded_files = st.file_uploader(
            "Upload log files (.log, .txt, .json)", 
            type=["log", "txt", "json"],
            accept_multiple_files=True
        )
        if uploaded_files:
            for f in uploaded_files:
                log_text += f.read().decode("utf-8") + "\n"
            st.success(f"📄 Successfully loaded {len(uploaded_files)} file(s).")
            
    with tab3:
        st.markdown("#### 🪣 AWS S3 Auto-Sync")
        buckets, err = list_s3_buckets()
        if err:
            st.error(err)
            bucket = st.text_input("S3 Bucket Name manually")
        else:
            bucket = st.selectbox("Select S3 Bucket", buckets) if buckets else st.text_input("S3 Bucket Name manually")
            
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Fetch Latest S3 Log", type="primary", use_container_width=True):
                if bucket:
                    with st.spinner("Fetching logs from S3..."):
                        content, msg = fetch_latest_s3_log(bucket)
                        if "Error" in msg:
                            st.error(msg)
                        else:
                            st.success(msg)
                            log_text = content
                else:
                    st.error("Please provide a bucket name.")
        with col2:
            auto_poll = st.toggle("🔄 Enable Hands-Free Live Auto-Polling", value=st.session_state.get("auto_poll", False))
            if auto_poll:
                st.session_state.auto_poll = True
                st.session_state.poll_bucket = bucket
            else:
                st.session_state.auto_poll = False
                
        # If auto-polling is active, fetch the latest log automatically
        if st.session_state.get("auto_poll") and st.session_state.get("poll_bucket"):
            content, msg = fetch_latest_s3_log(st.session_state.poll_bucket)
            if "Error" not in msg and content:
                log_text = content
            
    st.markdown("---")
    
    if log_text.strip():
        current_hash = hashlib.md5(log_text.encode()).hexdigest()
        if current_hash != st.session_state.log_hash or "results" not in st.session_state:
            st.session_state.log_hash = current_hash
            st.session_state.messages = []
            with st.spinner("🤖 AI is actively scanning logs for anomalies... This may take a moment for large files."):
                st.session_state.results = extract_critical_logs(log_text)
                
        results = st.session_state.results
        num_security = len(results["security"])
        num_performance = len(results["performance"])
        total_flagged = num_security + num_performance
        
        col1, col2, col3 = st.columns(3)
        with col1: st.metric(label="Total Lines Scanned", value=len(log_text.splitlines()))
        with col2: st.metric(label="Security Risks", value=num_security, delta_color="inverse")
        with col3: st.metric(label="Performance Issues", value=num_performance, delta_color="inverse")
        
        st.markdown("### 🔍 Analysis Overview")
        if total_flagged == 0:
            st.success("✅ **Clean Scan!** No critical error signatures detected.")
        else:
            st.warning(f"⚠️ **Found {total_flagged} critical log entries requiring attention.**")
            
            # --- VISUAL TELEMETRY ---
            if results["structured_data"]:
                df_timeseries = generate_timeseries_dataframe(results["structured_data"])
                if not df_timeseries.empty:
                    st.markdown("#### 📈 Visual Telemetry (Anomaly Timeline)")
                    
                    chart = alt.Chart(df_timeseries).mark_area(opacity=0.6, interpolate='monotone').encode(
                        x=alt.X('Timestamp:T', title='Time (Min)'),
                        y=alt.Y('Count:Q', title='Incident Count'),
                        color=alt.Color('Type:N', scale=alt.Scale(domain=['Security', 'Performance'], range=['#ff4b4b', '#ffa421'])),
                        tooltip=['Timestamp:T', 'Type:N', 'Count:Q']
                    ).properties(
                        height=250
                    ).interactive()
                    
                    st.altair_chart(chart, use_container_width=True)
                
                st.markdown("#### 📊 Auto-Extracted Context")
                st.dataframe(pd.DataFrame(results["structured_data"]), use_container_width=True, hide_index=True)
                
            st.markdown("### 🤖 AI Incident Playbooks")
            tab_sec, tab_perf = st.tabs(["🛡️ Security Events", "⚡ Performance Anomalies"])
            with tab_sec:
                if num_security > 0:
                    st.error("🚨 **High Severity:** Security risks detected.")
                    with st.expander("👁️ View Isolated Security Snippets", expanded=True):
                        for err in results["security"]: st.code(err if isinstance(err, str) else str(err), language="log")
                    if st.button("🚀 Generate SecOps Playbook", type="primary", use_container_width=True, key="sec_btn"):
                        with st.spinner("🤖 Llama 3.2 is analyzing security logs and crafting a remediation plan..."):
                            report = generate_remediation_playbook(results["security"], "security")
                            st.markdown("---")
                            st.success("✨ SecOps Analysis Complete!")
                            st.markdown(report)
                else:
                    st.success("✅ No security risks detected.")
            with tab_perf:
                if num_performance > 0:
                    st.warning("⚠️ **Medium/High Severity:** Performance bottlenecks detected.")
                    with st.expander("👁️ View Isolated Performance Snippets", expanded=True):
                        for err in results["performance"]: st.code(err if isinstance(err, str) else str(err), language="log")
                    if st.button("🚀 Generate SRE Playbook", type="primary", use_container_width=True, key="perf_btn"):
                        with st.spinner("🤖 Llama 3.2 is analyzing performance logs and crafting a remediation plan..."):
                            report = generate_remediation_playbook(results["performance"], "performance")
                            st.markdown("---")
                            st.success("✨ SRE Analysis Complete!")
                            st.markdown(report)
                else:
                    st.success("✅ No performance anomalies detected.")
    else:
        st.info("👈 **Get Started:** Paste raw log text in the box above or upload a log file to trigger analysis.")

with main_tab2:
    st.info("🛡️ Analyze logs to map to compliance frameworks and generate Terraform/CLI rules to block threats.")
    results = st.session_state.results
    total_flagged = len(results["security"]) + len(results["performance"])
    
    if total_flagged > 0:
        if st.button("🚀 Generate Compliance & Defense Posture", type="primary", use_container_width=True, key="proact_btn"):
            with st.spinner("🤖 Llama 3.2 is analyzing compliance and generating IAC defenses..."):
                raw_logs_context = "\n".join([str(item) for item in results["security"] + results["performance"]])
                report = generate_proactive_defenses(results["structured_data"], raw_logs_context)
                st.markdown("---")
                st.success("✨ Proactive Defense Analysis Complete!")
                st.markdown(report)
    else:
        st.warning("⚠️ No security or performance issues detected to generate defenses for. Upload logs in the Log Analysis tab first.")

with main_tab3:
    st.info("🔍 Translate Plain English into perfectly formatted Log Queries (Athena, Splunk, CloudWatch).")
    query_platform = st.selectbox("Select Target Platform", ["AWS Athena", "CloudWatch Logs Insights", "Splunk SPL", "Datadog"])
    query_prompt = st.text_area("Describe what you want to search for in plain English:", placeholder="e.g., Find all 502 errors grouped by Source IP from the last 24 hours")
    
    if st.button("✨ Generate Query Code", type="primary", use_container_width=True, key="query_btn"):
        if not query_prompt.strip():
            st.error("Please enter a description of the query you want to build.")
        else:
            with st.spinner(f"🤖 Translating your request into {query_platform} syntax..."):
                results = st.session_state.results
                raw_logs_context = "No extracted context."
                if results.get("structured_data"):
                    raw_logs_context = f"Available Fields: {list(results['structured_data'][0].keys())}"
                
                query_code = generate_log_query(query_prompt, query_platform, raw_logs_context)
                st.markdown("---")
                st.success(f"✨ {query_platform} Query Generated!")
                st.markdown(query_code)

with main_tab4:
    st.markdown("### 💬 Interactive Log Investigation Assistant")
    st.caption("Ask questions about the anomalies found in the logs. The AI retains context.")
    
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            
    if prompt := st.chat_input("E.g., What did the IP 192.168.1.1 do? or Write an Athena query to find this error."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
            
        results = st.session_state.results
        context_payload = ""
        if results["security"]: context_payload += f"Security Logs:\n{results['security']}\n"
        if results["performance"]: context_payload += f"Performance Logs:\n{results['performance']}\n"
        
        with st.chat_message("assistant"):
            with st.spinner("Analyzing context..."):
                response = chat_with_logs(prompt, st.session_state.messages[:-1], context_payload)
                st.markdown(response)
                
        st.session_state.messages.append({"role": "assistant", "content": response})

# --- AUTO POLLING BACKGROUND LOOP ---
if st.session_state.get("auto_poll"):
    time.sleep(5)
    st.rerun()