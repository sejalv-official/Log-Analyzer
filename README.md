# ⚡ AI-Powered Incident Triage & Log Analyzer

An automated, privacy-focused incident response dashboard designed to accelerate L1 DevOps triage. The platform ingests application and load balancer logs from AWS S3, strips away operational noise, and leverages a local **Llama 3.2** model via Ollama to generate instantaneous **Root Cause Analyses (RCA)** and remediation playbooks.

---

## 🌟 Key Features

* 🔄 **Live S3 Auto-Polling:** Continuously streams and ingests the newest application or ALB log files directly from AWS S3 into memory.
* 📁 **Hybrid Ingestion:** Supports both automated cloud log polling and manual log file uploads for flexible debugging.
* 🎯 **Regex Noise Reduction:** Pre-filters raw log data by stripping out routine `200 OK` traffic to isolate failure signatures (`502`, `504`, `AccessDenied`, `Exception`).
* 🤖 **Local AI Analysis:** Interfaces with a locally hosted **Llama 3.2** model to synthesize plain-English root causes, system impact, and actionable CLI/AWS fix commands.
* 🔒 **Zero-Trust Security & Privacy:**
  * **Memory-Only AWS Credentials:** Reads credentials exclusively from active terminal session variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), preventing disk credential leaks.
  * **100% On-Premise Data Privacy:** Sensitive server logs, IP addresses, and stack traces never leave your environment or hit third-party LLM APIs.

---

## 🏗️ Architecture & Data Flow
