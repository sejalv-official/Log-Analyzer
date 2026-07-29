import streamlit as st
import pandas as pd
import hashlib
from log_parser import extract_critical_logs
from ai_engine import generate_remediation_playbook, chat_with_logs, generate_proactive_defenses, generate_log_query
from aws_fetcher import list_s3_buckets, fetch_latest_s3_log, fetch_cloudwatch_logs, fetch_cloudtrail_events
from ini_parser import parse_aws_extension_ini
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
if "role_arn" not in st.session_state:
    st.session_state.role_arn = ""
if "source_context" not in st.session_state:
    st.session_state.source_context = "Unknown Source"

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
        st.markdown("#### ☁️ Fetch AWS Telemetry")
        
        with st.expander("🔑 AWS Auth (POD SSO) - Cross-Account Access", expanded=True):
            st.warning("⚠️ **Note:** This multi-account authentication feature is currently a work-in-progress and might not work as expected in all environments.")
            st.caption("Input the client's Assume Role ARN to switch context. Base auth uses your SSO login.")
            
            # INI Config Integration
            ini_config = st.text_area(
                "AWS Extension Config (INI)", 
                placeholder="[profile my-client]\nrole_arn = arn:aws:iam::123...", 
                help="Paste your AWS Extend Switch Roles INI config here to auto-populate a client dropdown.",
                height=100
            )
            
            role_arn_input = ""
            if ini_config.strip():
                profiles = parse_aws_extension_ini(ini_config)
                if profiles:
                    selected_profile = st.selectbox("Select Client Profile", options=["Manual ARN Input"] + list(profiles.keys()))
                    if selected_profile != "Manual ARN Input":
                        role_arn_input = profiles[selected_profile]
                        st.success(f"Loaded ARN for {selected_profile}")
            
            if not role_arn_input:
                role_arn_input = st.text_input("Assume Role ARN (Manual)", value=st.session_state.role_arn or "", placeholder="arn:aws:iam::123456789012:role/L1-Admin")
                
            st.session_state.role_arn = role_arn_input if (role_arn_input and role_arn_input.strip()) else None

        aws_source = st.radio("Select Source", ["S3 Bucket", "CloudWatch Logs", "CloudTrail Events"], horizontal=True)

        if aws_source == "S3 Bucket":
            buckets, err = list_s3_buckets(role_arn=st.session_state.role_arn)
            if err:
                st.error(err)
                bucket = st.text_input("S3 Bucket Name manually")
            else:
                bucket = st.selectbox("Select S3 Bucket", buckets) if buckets else st.text_input("S3 Bucket Name manually")
                
            if st.button("Fetch Latest S3 Log", type="primary"):
                if bucket:
                    with st.spinner(f"Fetching from S3 bucket {bucket}..."):
                        content, msg = fetch_latest_s3_log(bucket, role_arn=st.session_state.role_arn)
                        if "Error" in msg:
                            st.error(msg)
                        else:
                            st.success(msg)
                            log_text = content
                            st.session_state.source_context = f"S3 Bucket: {bucket}"
                else:
                    st.error("Please provide a bucket name.")

        elif aws_source == "CloudWatch Logs":
            log_group = st.text_input("CloudWatch Log Group Name", placeholder="/aws/lambda/my-function")
            if st.button("Fetch CloudWatch Logs", type="primary"):
                if log_group:
                    with st.spinner(f"Fetching logs from {log_group}..."):
                        content, msg = fetch_cloudwatch_logs(log_group, role_arn=st.session_state.role_arn)
                        if "Error" in msg:
                            st.error(msg)
                        else:
                            st.success(msg)
                            log_text = content
                            st.session_state.source_context = f"CloudWatch: {log_group}"
                else:
                    st.error("Please provide a Log Group Name.")

        elif aws_source == "CloudTrail Events":
            if st.button("Fetch Recent CloudTrail Events", type="primary"):
                with st.spinner("Fetching CloudTrail events..."):
                    content, msg = fetch_cloudtrail_events(role_arn=st.session_state.role_arn)
                    if "Error" in msg:
                        st.error(msg)
                    else:
                        st.success(msg)
                        log_text = content
                        st.session_state.source_context = "CloudTrail"
            
    st.markdown("---")
    
    if log_text.strip():
        # Include source_context in hash so changing sources forces a fresh AI scan
        hash_input = log_text + st.session_state.get("source_context", "")
        current_hash = hashlib.md5(hash_input.encode()).hexdigest()
        if current_hash != st.session_state.log_hash or "results" not in st.session_state:
            st.session_state.log_hash = current_hash
            st.session_state.messages = []
            with st.spinner("🤖 AI is actively scanning logs for anomalies... This may take a moment for large files."):
                # Pass source context into the parsing
                st.session_state.results = extract_critical_logs(log_text, st.session_state.get("source_context", "Pasted/Uploaded Data"))
                
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
                
                st.markdown("#### 📊 Incident History & Extracted Context")
                df = pd.DataFrame(results["structured_data"])
                if "Source" in df.columns:
                    # Move Source to the front
                    cols = ["Source"] + [c for c in df.columns if c != "Source"]
                    df = df[cols]
                st.dataframe(df, use_container_width=True, hide_index=True)
                
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
    col1, col2 = st.columns(2)
    with col1:
        compliance_framework = st.selectbox("Compliance Framework", ["SOC 2", "HIPAA", "PCI-DSS", "CIS AWS Foundations Benchmark"])
    with col2:
        log_context = st.selectbox("Log Context to Audit", ["S3", "CloudWatch", "CloudTrail", "Application Logs"])
        
    results = st.session_state.results
    total_flagged = len(results["security"]) + len(results["performance"])
    
    if total_flagged > 0:
        if st.button("🚀 Generate Compliance Audit Report", type="primary", use_container_width=True, key="proact_btn"):
            with st.spinner(f"🤖 Llama 3.2 is auditing logs against {compliance_framework} framework..."):
                raw_logs_context = "\n".join([str(item) for item in results["security"] + results["performance"]])
                report = generate_proactive_defenses(results["structured_data"], raw_logs_context, compliance_framework, log_context)
                st.session_state.proactive_report = report
                
        if "proactive_report" in st.session_state:
            st.markdown("---")
            st.success("✨ Proactive Defense Analysis Complete!")
            st.markdown(st.session_state.proactive_report)
            st.download_button(
                label="📥 Download Audit Report",
                data=st.session_state.proactive_report,
                file_name=f"compliance_audit_{compliance_framework.lower().replace(' ', '_')}.md",
                mime="text/markdown",
                use_container_width=True
            )
    else:
        st.warning("⚠️ No security or performance issues detected to generate defenses for. Upload logs in the Log Analysis tab first.")

with main_tab3:
    st.info("🔍 Translate Plain English into perfectly formatted Log Queries (Athena, Splunk, CloudWatch).")
    
    if len(st.session_state.results.get("structured_data", [])) == 0:
        st.warning("⚠️ No logs are currently loaded. The AI will generate a generic query without your specific log schema.")
        
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
    col1, col2 = st.columns([4, 1])
    with col1:
        st.markdown("### 💬 Interactive Log Investigation Assistant")
        st.caption("Ask questions about the anomalies found in the logs. The AI retains context.")
    with col2:
        if st.button("🗑️ Clear Chat", use_container_width=True):
            st.session_state.messages = []
            st.rerun()
            
    if len(st.session_state.results.get("security", [])) == 0 and len(st.session_state.results.get("performance", [])) == 0:
        st.warning("⚠️ You are currently chatting without any logs loaded. Go to Log Analysis to upload logs first for context.")
    
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