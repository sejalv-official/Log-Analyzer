def extract_critical_logs(file_content):
    """
    Parses raw log text and extracts only lines containing critical keywords.
    """
    error_keywords = ["ERROR", "502", "504", "AccessDenied", "CRITICAL", "FAILED", "403"]
    flagged_lines = []
    
    lines = file_content.splitlines()
    for line_number, line in enumerate(lines, 1):
        clean_line = line.strip()
        if any(keyword in clean_line for keyword in error_keywords):
            flagged_lines.append(f"Line {line_number}: {clean_line}")
            
    return flagged_lines