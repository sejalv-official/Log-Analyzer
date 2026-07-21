import streamlit as st
from log_parser import extract_critical_logs
from ai_engine import generate_remediation_playbook

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AI Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

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
    st.info("**Model:** `llama3.2` (Local)\n\n**Mode:** Privacy-Preserving")
    
    st.markdown("---")
    st.markdown("### 📌 Supported Log Formats")
    st.caption("• AWS Application Load Balancer (ALB)\n• AWS CloudWatch Logs\n• AWS CloudTrail Events\n• Custom Application Logs")
    
    st.markdown("---")
    st.caption("Developed for Automated L1 Incident Triage.")

# --- MAIN HEADER ---
st.markdown('<div class="main-header">🛡️ AI-Powered Log Analyzer</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Automated Root Cause Analysis & Remediation for AWS Infrastructure Logs</div>', unsafe_allow_html=True)

# --- INPUT SECTION: TABBED NAVIGATION ---
st.markdown("### 📥 Select Input Method")
tab1, tab2 = st.tabs(["📋 Paste Raw Text", "📁 Upload Log File"])

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
    uploaded_file = st.file_uploader(
        "Upload a log file (.log, .txt, .json)", 
        type=["log", "txt", "json"]
    )
    if uploaded_file is not None:
        log_text = uploaded_file.read().decode("utf-8")
        st.success(f"📄 Successfully loaded: **{uploaded_file.name}**")

st.markdown("---")

# --- ANALYSIS & RESULTS SECTION ---
if log_text.strip():
    # Parse logs
    matched_errors = extract_critical_logs(log_text)
    
    # Visual Metrics Summary
    col1, col2 = st.columns(2)
    with col1:
        st.metric(label="Total Lines Scanned", value=len(log_text.splitlines()))
    with col2:
        st.metric(label="Critical Issues Flagged", value=len(matched_errors), delta_color="inverse")

    st.markdown("### 🔍 Analysis Overview")

    if not matched_errors:
        st.success("✅ **Clean Scan!** No critical error signatures (502, 504, AccessDenied, ERROR) detected.")
    else:
        st.warning(f"⚠️ **Found {len(matched_errors)} critical log entries requiring attention.**")
        
        # Isolated Error Accordion
        with st.expander("👁️ View Isolated Error Snippets", expanded=True):
            for err in matched_errors:
                st.code(err, language="log")
                
        st.markdown("### 🤖 AI Incident Playbook")
        
        # Prominent Action Button
        if st.button("🚀 Generate AI Remediation Guide", type="primary", use_container_width=True):
            with st.spinner("🤖 Llama 3.2 is analyzing logs and crafting root cause report..."):
                report = generate_remediation_playbook(matched_errors)
                
                # Output Container
                st.markdown("---")
                st.success("✨ Analysis Complete!")
                
                # Render AI output in a structured container
                with st.container():
                    st.markdown(report)
                    
                    # Download button for generated report
                    st.download_button(
                        label="📥 Download Remediation Report (.md)",
                        data=report,
                        file_name="remediation_playbook.md",
                        mime="text/markdown"
                    )
else:
    st.info("👈 **Get Started:** Paste raw log text in the box above or upload a log file to trigger analysis.")