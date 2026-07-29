import json
from ai_engine import ai_analyze_log_chunk

def extract_critical_logs(file_content, source_context="Unknown Source"):
    """
    Parses raw log text using an AI-powered detection engine.
    Chunks the logs and sends them to the local LLM for anomaly detection.
    """
    results = {
        "security": [],
        "performance": [],
        "structured_data": []
    }
    
    # FAST PRE-FILTER: Only send lines that look remotely suspicious to the AI
    # This prevents sending 10,000 normal log lines to an LLM.
    suspicious_keywords = ["ERROR", "WARN", "FAIL", "DENIED", "CRITICAL", "50", "40", "EXCEPTION", "TIMEOUT", "UNAUTHORIZED"]
    
    lines = file_content.splitlines()
    suspicious_lines = []
    
    for i, line in enumerate(lines):
        upper_line = line.upper()
        if any(keyword in upper_line for keyword in suspicious_keywords):
            suspicious_lines.append(f"Line {i+1}: {line}")
            
    # If no suspicious lines, return empty immediately
    if not suspicious_lines:
        return results
        
    chunk_size = 50
    
    for i in range(0, len(suspicious_lines), chunk_size):
        chunk = suspicious_lines[i:i + chunk_size]
        chunk_text = "\n".join(chunk)
        
        if not chunk_text.strip():
            continue
            
        # Send to AI
        ai_result = ai_analyze_log_chunk(chunk_text, source_context)
        
        # Merge results
        if isinstance(ai_result, dict):
            if "security" in ai_result and isinstance(ai_result["security"], list):
                results["security"].extend(ai_result["security"])
            if "performance" in ai_result and isinstance(ai_result["performance"], list):
                results["performance"].extend(ai_result["performance"])
            if "structured_data" in ai_result and isinstance(ai_result["structured_data"], list):
                results["structured_data"].extend(ai_result["structured_data"])
                
    return results