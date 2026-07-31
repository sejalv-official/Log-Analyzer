# 🛡️ AI-Powered AWS Log Analyzer & L1 Incident Triage Engine

An intelligent, privacy-preserving incident triage engine that automates root cause analysis (RCA), security anomaly detection, and remediation playbook generation for AWS cloud infrastructure logs.

Powered by a two-tier hybrid engine featuring local **Llama 3.2 via Ollama**, this platform turns raw log streams from CloudWatch, S3, and CloudTrail into actionable, copy-pasteable AWS CLI and Terraform remediation scripts in real-time—100% locally with **zero data leakage**.

---

## 🌟 Key Features

* **📥 Multi-Source Log Ingestion & AWS Authentication:**
  * Pull logs directly from **AWS CloudWatch Log Groups**, **S3 Buckets** (supports `.gz` decompression), and **CloudTrail Management Events**.
  * Supports manual text pasting and log file uploads (`.log`, `.txt`, `.json`).
  * Cross-account access support via IAM Role Assumption (`sts:AssumeRole`) and AWS Switch Role INI parser.

* **🔄 Hands-Free Live Auto-Polling:**
  * Configurable background polling engine (5s–120s) that continuously fetches fresh telemetry streams from active AWS services without freezing the UI.

* **💾 Multi-Source State Persistence & Side-by-Side Comparison:**
  * Isolated state management across S3, CloudWatch, and CloudTrail. Switching views preserves all previous findings and AI reports.
  * Dedicated **Cross-Source Comparison View** for comparing security risks, performance bottlenecks, and line counts side-by-side.

* **🔒 Privacy-Preserving Two-Tier Local AI Engine:**
  * **Tier 1 (Regex & MD5 Filtering):** Instant pre-filtering to isolate critical error signatures (`502 Bad Gateway`, `AccessDenied`, timeout issues) and eliminate duplicate processing.
  * **Tier 2 (Local LLM):** Uses **Llama 3.2** via Ollama running locally on-premise. Credentials and production logs never leave your machine.

* **🛠️ Operational Playbook Workspaces:**
  * **SecOps Playbook:** Isolates unauthorized access or policy violations and generates automated security playbooks with copy-pasteable Terraform/AWS CLI fixes.
  * **SRE Performance Playbook:** Pinpoints latency spikes, timeouts, and gateway errors with concrete system optimization steps.
  * **Structured Data Extractor:** Converts raw logs into interactive Pandas DataFrames displaying extracted IPs, timestamps, and metadata.

* **📈 Executive Incident Intelligence Dashboard:**
  * Real-time KPI summary, interactive Altair visual telemetry charts, severity distribution breakdowns, and one-click consolidated Markdown report export.

* **🛡️ Compliance Audit Engine & Natural Language Query Builder:**
  * Audits findings against **SOC 2**, **HIPAA**, **PCI-DSS**, and **CIS AWS Foundations Benchmarks**.
  * Translates plain English requests into platform-specific log queries (**AWS Athena**, **CloudWatch Insights**, **Splunk SPL**, **Datadog**).

* **💬 Interactive AI Chat Assistant:**
  * Session-persistent AI investigator pre-loaded with active telemetry context for interactive incident Q&A.

---

## 🏗️ System Architecture

```text
[ S3 Buckets / CloudWatch Logs / CloudTrail Events / Uploads ]
                             │
                             ▼
              [ Hands-Free Auto-Polling Loop ]
                             │
                             ▼
         [ Tier 1: Local Regex & MD5 Hash Filter ]
                             │
                             ▼
       [ Tier 2: Ollama - Llama 3.2 (Local Privacy) ]
                             │
      ┌──────────────────────┴──────────────────────┐
      ▼                                             ▼
[ Operational Workspaces ]             [ Executive Dashboards ]
• SecOps Playbook                      • Incident Intelligence Dashboard
• SRE Performance Playbook             • Proactive Compliance Audits
• Isolated Error Snippets              • Natural Language Query Builder
• Extracted Structured Context          • Interactive AI Chatbot
