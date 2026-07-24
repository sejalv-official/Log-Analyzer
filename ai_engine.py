import ollama

def generate_remediation_playbook(error_lines, incident_type="performance"):
    """
    Sends filtered log snippets to local Llama 3.2 model and returns Markdown report.
    Uses dynamic personas based on the incident type (Security vs Performance).
    """
    if not error_lines:
        return "No logs provided for analysis."
        
    log_payload = "\n".join(error_lines)
    
    if incident_type == "security":
        system_prompt = (
            "You are an expert AWS SecOps & Compliance Engineer analyzing logs. "
            "Focus on vulnerability triage, IAM least-privilege violations, and security risks. "
            "Provide a clean, structured report using Markdown formatting with:\n"
            "### 🔍 Security Risks Identified\n"
            "### 🪵 Root Cause & Attack Vector Analysis\n"
            "### ⚠️ Severity Level (Low/Medium/High/Critical)\n"
            "### 🛠️ Step-by-Step Remediation\n"
            "**CRITICAL:** You MUST provide explicitly copy-pasteable AWS CLI commands or Terraform snippets to remediate the vulnerability (e.g., updating a security group, patching an IAM role)."
        )
    else:
        system_prompt = (
            "You are an expert AWS SRE & DevOps Engineer analyzing logs. "
            "Focus on reducing MTTR, scaling issues, and performance bottlenecks. "
            "Provide a clean, structured report using Markdown formatting with:\n"
            "### 🔍 Performance Bottlenecks Identified\n"
            "### 🪵 Root Cause Analysis\n"
            "### ⚠️ Severity Level (Low/Medium/High/Critical)\n"
            "### 🛠️ Step-by-Step Remediation\n"
            "**CRITICAL:** You MUST provide explicitly copy-pasteable AWS CLI commands or Terraform snippets to remediate the issue instantly."
        )
    
    try:
        response = ollama.chat(
            model="llama3.2:1b",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Analyze these raw log entries and output the requested report:\n\n{log_payload}"}
            ]
        )
        return response.message.content
    except Exception as e:
        return f"Error communicating with local LLM: {str(e)}"

import json

def ai_analyze_log_chunk(log_chunk):
    """
    Sends a chunk of raw logs to the local LLM to dynamically detect anomalies
    and extract structured JSON metadata without using hardcoded keywords.
    """
    if not log_chunk.strip():
        return {"security": [], "performance": [], "structured_data": []}
        
    system_prompt = (
        "You are an expert AI Log Analyzer. Read the following raw log lines. "
        "Detect any security risks (e.g., unauthorized access, probes) or performance issues (e.g., timeouts, 5xx errors). "
        "Extract metadata where possible (Source IP, User, Event). "
        "You MUST return ONLY a valid JSON object matching this schema exactly, and nothing else (no markdown blocks, no text before or after):\n"
        "{\n"
        '  "security": ["line 1 text", "line 2 text"],\n'
        '  "performance": ["line 3 text"],\n'
        '  "structured_data": [\n'
        '    {"Line": "number or N/A", "Timestamp": "time", "Type": "Security/Performance", "Event": "event name", "User/ARN": "user", "Source IP": "ip"}\n'
        "  ]\n"
        "}"
    )
    
    try:
        response = ollama.chat(
            model="llama3.2:1b",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Logs:\n{log_chunk}"}
            ]
        )
        
        # Clean the response to parse JSON
        content = response.message.content.strip()
        if content.startswith("```json"):
            content = content[7:]
        if content.endswith("```"):
            content = content[:-3]
            
        result = json.loads(content.strip())
        
        # Ensure schema
        if "security" not in result: result["security"] = []
        if "performance" not in result: result["performance"] = []
        if "structured_data" not in result: result["structured_data"] = []
        
        return result
    except Exception as e:
        # Fallback empty structure
        print(f"AI parsing error: {e}")
        return {"security": [], "performance": [], "structured_data": []}

def generate_proactive_defenses(structured_data, raw_logs):
    """
    Generates Compliance mapping and Proactive IAC (Terraform/CLI) defenses.
    """
    if not structured_data and not raw_logs:
        return "No data available for proactive defense generation."
        
    system_prompt = (
        "You are an expert AWS Security Architect and Compliance Auditor. "
        "Analyze the provided log context and generate a Proactive Defense & Compliance Report. "
        "The report MUST be in Markdown format and include:\n\n"
        "### 🏛️ Compliance & Posture Mapping\n"
        "- Map detected anomalies to specific CIS AWS Foundations Benchmark or SOC2 violations.\n\n"
        "### 🛡️ Auto-Generated Prevention Rules\n"
        "- Provide exact, ready-to-deploy **Terraform** or **AWS CLI** code to prevent these issues (e.g., AWS WAF rules to block malicious IPs, CloudWatch alarms for 5xx errors).\n\n"
        "### ⏱️ Incident Timeline\n"
        "- Reconstruct a chronological timeline of the events across different sources to show the blast radius.\n"
    )
    
    context = f"Structured Anomalies:\n{json.dumps(structured_data, indent=2)}\n\nRaw Anomalous Logs:\n{raw_logs}"
    
    try:
        response = ollama.chat(
            model="llama3.2:1b",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Generate the Proactive Defense & Compliance Report based on this data:\n\n{context}"}
            ]
        )
        return response.message.content
    except Exception as e:
        return f"Error communicating with local LLM: {str(e)}"

def generate_log_query(user_prompt, platform, context):
    """
    Translates natural language into log querying syntax (e.g., AWS Athena, Splunk SPL).
    """
    system_prompt = (
        f"You are an expert Data Engineer and DevOps specialist in {platform}. "
        f"Your task is to translate the user's natural language request into a highly optimized, perfectly formatted {platform} query. "
        "You MUST output ONLY the query code block, wrapped in ```sql or appropriate markdown. "
        "Do not include any other conversational text or explanations. Just the code.\n\n"
        "Here is the context of the logs being analyzed to help you understand column names and structure:\n"
        f"{context}\n"
    )
    
    try:
        response = ollama.chat(
            model="llama3.2:1b",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Write a query for this request: {user_prompt}"}
            ]
        )
        return response.message.content
    except Exception as e:
        return f"Error communicating with local LLM: {str(e)}"

def chat_with_logs(user_message, chat_history, log_context):
    """
    Handles conversational interactions about the parsed logs.
    """
    system_prompt = (
        "You are an expert interactive AWS Cloud DevOps and Security Assistant. "
        "The user is investigating an incident based on the following extracted logs:\n"
        f"{log_context}\n\n"
        "Answer their questions concisely and directly based on this context. "
        "If they ask for a query (like SQL, AWS Athena, or CLI), provide the exact query in a code block."
    )
    
    # Format messages for Ollama
    messages = [{"role": "system", "content": system_prompt}]
    
    for msg in chat_history:
        messages.append({"role": msg["role"], "content": msg["content"]})
        
    messages.append({"role": "user", "content": user_message})
    
    try:
        response = ollama.chat(
            model="llama3.2:1b",
            messages=messages
        )
        return response.message.content
    except Exception as e:
        return f"Error communicating with local LLM: {str(e)}"