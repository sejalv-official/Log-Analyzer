import ollama

def analyze_raw_logs_with_ai(raw_log_text, model_name="llama3.2"):
    """
    Analyzes raw, unfiltered log text using local Llama 3.2 to detect anomalies,
    errors, and security concerns automatically.
    """
    if not raw_log_text or not raw_log_text.strip():
        return "⚠️ No log data provided for AI analysis."

    prompt = f"""
    You are an expert DevSecOps and SRE engineer reviewing raw system/cloud logs.
    Your task is to autonomously inspect the log stream below and identify any anomalies, failures, 
    misconfigurations, or security issues—WITHOUT relying on strict keyword filters.

    ### RAW LOG DATA:
    ```
    {raw_log_text}
    ```

    ### INSTRUCTIONS:
    Provide a comprehensive, beautifully structured Markdown analysis containing:

    1. 📊 **Log Stream Health Overview**: Briefly state if the overall log stream appears healthy or problematic.
    2. 🔍 **Detected Anomalies & Errors**: List any unusual patterns, failed HTTP statuses, stack traces, or authorization issues you discovered.
    3. 🚨 **Severity Level**: Assign a overall severity (LOW, MEDIUM, HIGH, CRITICAL).
    4. 🛠️ **Recommended Action Items**: Practical, step-by-step guidance for L1/L2 responders to resolve any found issues.
    """

    try:
        response = ollama.chat(
            model=model_name,
            messages=[
                {
                    "role": "system",
                    "content": "You are an intelligent DevSecOps assistant capable of detecting subtle anomalies in raw logs."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        return response['message']['content']

    except Exception as e:
        return f"❌ **AI Engine Error:** `{str(e)}`\n\n*Troubleshooting:* Ensure Ollama is running (`ollama run llama3.2`)."