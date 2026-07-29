# ⚡ AI-Powered Incident Triage & Log Analyzer

An automated, privacy-focused incident response dashboard designed to accelerate L1 DevOps triage. The platform ingests application and load balancer logs directly from **AWS S3**, strips away operational noise, and leverages a local **Llama 3.2** model via **Ollama** to generate instantaneous **Root Cause Analyses (RCA)** and remediation playbooks.

---

## 🌟 Key Features

* 🔄 **Live Cloud Auto-Polling:** Continuously streams and ingests the newest application logs from **AWS S3, CloudWatch, and CloudTrail**.
* 📁 **Hybrid Log Ingestion:** Supports automated cloud log polling, Assume-Role switching for multi-account triage, and manual log file uploads.
* 🎯 **Regex & AI Noise Reduction:** Pre-filters raw log data to isolate failure signatures (`502`, `504`, `AccessDenied`, `Exception`).
* 🤖 **Local AI Analysis:** Interfaces with a locally hosted **Llama 3.2** model to synthesize plain-English root causes, system impact, and actionable CLI/AWS fix commands.
* 🔒 **Zero-Trust Security & Privacy:**
  * **Memory-Only AWS Credentials:** Reads credentials exclusively from active terminal session variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), preventing disk credential leaks.
  * **100% On-Premise Data Privacy:** Sensitive server logs, IP addresses, and stack traces never leave your environment or hit third-party LLM APIs.

---

## 🏗️ Architecture & Data Flow

```text
[ AWS S3 / CloudWatch / CloudTrail ]
       │
       │ (1. Assume Role & Fetch Log Stream)
       ▼
[ aws_fetcher.py ] 
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
├── aws_fetcher.py   # Multi-account AWS client (Assume Role, S3, CloudWatch, CloudTrail)
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
```

## 🏢 POD L1 Team Setup (Multi-Account Workflow)

For L1/Triage teams operating in a shared-resource POD model (e.g., Service-Based Companies), this application supports seamless context switching across client AWS accounts without hardcoding static credentials.

### Workflow:
1. **Keycloak SSO Login:** The L1 engineer logs into the base company AWS account using Keycloak AWS SSO.
2. **Base Role Access:** From there, they reach their internal Switch Role (e.g., `internal_-SwitchRole/User@company.com`).
3. **AWS Config Extension:** The team uses an AWS Config Extension (such as AWS Extend Switch Roles) to seamlessly switch between different client accounts. 
4. **INI Configuration:** Engineers define their roles in the extension's editor using the standard INI format. For example:
   ```ini
   # Lines prefixed with # are comments
   # Section headers define the display name
   [profile my-client-role]
   role_arn = arn:aws:iam::123456789012:role/L1-Support-Role
   region = us-east-1
   ```
5. **Fetch & Analyze:** The `aws_fetcher.py` engine leverages these assumed roles dynamically to fetch the client's logs across S3, CloudWatch, or CloudTrail without compromising the security posture of either organization.
# 🛡️ AI-Powered Log Analyzer & L1 Incident Triage Tool

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30%2B-FF4B4B.svg)](https://streamlit.io/)
[![Ollama](https://img.shields.io/badge/Ollama-Llama--3.2-black.svg)](https://ollama.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An automated, privacy-first incident response assistant designed to parse AWS infrastructure logs (Application Load Balancers, CloudWatch, CloudTrail), isolate critical error signatures, and generate structured L1 triage playbooks using a local **Llama 3.2** model via **Ollama**.

---

## 📸 Overview & Key Features

- **⚡ Smart Context Filtering:** Filters raw logs for actionable keywords (`502`, `504`, `AccessDenied`, `ERROR`, `CRITICAL`), reducing LLM context window noise by **>80%**.
- **📋 Dual Input Support:** Supports both interactive copy-pasting of raw log streams and drag-and-drop file uploads (`.log`, `.txt`, `.json`).
- **🔒 Privacy-Preserving AI:** Operates 100% locally on your machine—no proprietary log data, IP addresses, or IAM paths are ever sent to external cloud APIs.
- **🛠️ Automated Playbook Generation:** Delivers structured Markdown incident reports complete with:
  - 🔍 **Identified Issues**
  - 🪵 **Root Cause Analysis (RCA)**
  - ⚠️ **Severity Rating**
  - 🛠️ **Step-by-Step Remediation Steps**
- **📥 One-Click Export:** Download the generated AI remediation report as a `.md` file for immediate ticket attachment (Jira/ServiceNow).

---

## 🏗️ Architecture & Tech Stack

```text
[ Raw AWS Logs ] ──► [ log_parser.py ] ──► [ Isolated Errors ] ──► [ ai_engine.py ]
(ALB / CloudWatch)   (Keyword Extraction)   (Context Filtered)    (Ollama / Llama 3.2)
                                                                            │
                                                                            ▼
                                                                  [ Streamlit Dashboard ]
                                                                  (Interactive UI & Download)
