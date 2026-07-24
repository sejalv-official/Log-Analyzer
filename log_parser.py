import json
from ai_engine import ai_analyze_log_chunk

def extract_critical_logs(file_content):
    """
    Parses raw log text using an AI-powered detection engine.
    Chunks the logs and sends them to the local LLM for anomaly detection.
    """
    results = {
        "security": [],
        "performance": [],
        "structured_data": []
    }
    
    lines = file_content.splitlines()
    chunk_size = 50
    
    for i in range(0, len(lines), chunk_size):
        chunk = lines[i:i + chunk_size]
        chunk_text = "\n".join(f"Line {i+j+1}: {line}" for j, line in enumerate(chunk) if line.strip())
        
        if not chunk_text.strip():
            continue
            
        # Send to AI
        ai_result = ai_analyze_log_chunk(chunk_text)
        
        # Merge results
        if isinstance(ai_result, dict):
            if "security" in ai_result and isinstance(ai_result["security"], list):
                results["security"].extend(ai_result["security"])
            if "performance" in ai_result and isinstance(ai_result["performance"], list):
                results["performance"].extend(ai_result["performance"])
            if "structured_data" in ai_result and isinstance(ai_result["structured_data"], list):
                results["structured_data"].extend(ai_result["structured_data"])
                
    return results