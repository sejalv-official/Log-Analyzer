# 🛡️ AI-Powered Log Analyzer & Incident Triage Tool

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
