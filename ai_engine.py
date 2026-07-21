import ollama

def generate_remediation_playbook(error_lines):
    """
    Sends filtered log snippets to local Llama 3.2 model and returns Markdown report.
    """
    log_payload = "\n".join(error_lines)
    
    system_prompt = (
        "You are an expert Cloud DevOps and Security Engineer analyzing AWS logs. "
        "Provide a clean, structured report using Markdown formatting with:\n"
        "### 🔍 Identified Issues\n"
        "### 🪵 Root Cause Analysis\n"
        "### ⚠️ Severity Level (Low/Medium/High/Critical)\n"
        "### 🛠️ Step-by-Step Remediation Steps for an L1 Engineer"
    )
    
    response = ollama.chat(
        model="llama3.2",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze these raw log entries:\n\n{log_payload}"}
        ]
    )
    return response.message.content