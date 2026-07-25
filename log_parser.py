def prepare_raw_logs_for_ai(log_text, max_lines=200):
    """
    Prepares raw logs for AI analysis without keyword filtering.
    If the log is very large, it samples the head and tail lines to fit 
    within the AI model's context window.
    """
    if not log_text or not isinstance(log_text, str):
        return ""

    lines = log_text.splitlines()

    # If log is small enough, return as-is
    if len(lines) <= max_lines:
        return "\n".join(lines)

    # Otherwise, sample the first 100 lines (startup context) and last 100 lines (recent events)
    half = max_lines // 2
    head = lines[:half]
    tail = lines[-half:]

    sampled_log = "\n".join(head) + f"\n\n... [TRUNCATED {len(lines) - max_lines} MIDDLE LINES FOR AI CONTEXT] ...\n\n" + "\n".join(tail)
    return sampled_log