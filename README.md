# ⚡ AI-Powered Incident Triage & Log Analyzer

An automated, privacy-focused incident response dashboard designed to accelerate L1 DevOps triage. The platform ingests application and load balancer logs directly from **AWS S3**, strips away operational noise, and leverages a local **Llama 3.2** model via **Ollama** to generate instantaneous **Root Cause Analyses (RCA)** and remediation playbooks.

---

## 🌟 Key Features

* 🔄 **Live S3 Auto-Polling:** Continuously streams and ingests the newest application or ALB log files directly from AWS S3 into memory.
* 📁 **Hybrid Log Ingestion:** Supports both automated cloud log polling and manual log file uploads for flexible debugging.
* 🎯 **Regex Noise Reduction:** Pre-filters raw log data by stripping out routine `200 OK` traffic to isolate failure signatures (`502`, `504`, `AccessDenied`, `Exception`).
* 🤖 **Local AI Analysis:** Interfaces with a locally hosted **Llama 3.2** model to synthesize plain-English root causes, system impact, and actionable CLI/AWS fix commands.
* 🔒 **Zero-Trust Security & Privacy:**
  * **Memory-Only AWS Credentials:** Reads credentials exclusively from active terminal session variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), preventing disk credential leaks.
  * **100% On-Premise Data Privacy:** Sensitive server logs, IP addresses, and stack traces never leave your environment or hit third-party LLM APIs.

---

## 🏗️ Architecture & Data Flow

```text
[ AWS S3 Bucket ]
       │
       │ (1. Stream newest log via boto3)
       ▼
[ s3_fetcher.py ] 
       │
       │ (2. Raw log contents)
       ▼
[ log_parser.py ] ──► (3. Strip 200 OK noise via Regex) ──► [ Error Snippets ]
                                                                 │
                                                                 │ (4. Prompt context)
                                                                 ▼
[ Streamlit UI ] ◄─── (5. Display RCA Playbook) ──────── [ Llama 3.2 via Ollama ]

```
## 📁 Project Structure
```text
LOG-ANALYZER/
├── app.py           # Streamlit web UI & state management
├── s3_fetcher.py    # Memory-only AWS S3 client & log streaming
├── log_parser.py    # Regex engine for noise reduction & error isolation
├── ai_engine.py     # Ollama API client for Llama 3.2 inference
├── requirements.txt # Python dependency declarations
└── .gitignore       # Security mask for environment & temporary files
```
## 🚀 Quick Start Guide

### Prerequisites
1. **Python 3.10+** installed.
2. **Ollama** installed and running locally with the **Llama 3.2** model:
   ```bash
   ollama pull llama3.2
   ```
### Step 1 Inject AWS Credentials (In-Memory)
```bash
export AWS_ACCESS_KEY_ID="your_access_key_here"
export AWS_SECRET_ACCESS_KEY="your_secret_key_here"
export AWS_DEFAULT_REGION="us-east-1"
```
### Step 2 Run the Application
```bash
ollama serve
streamlit run app.py
http://localhost:8501
```
