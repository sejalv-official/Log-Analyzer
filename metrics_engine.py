from collections import Counter

import pandas as pd


def generate_timeseries_dataframe(structured_data):
    """
    Convert structured log data into an aggregated pandas DataFrame
    suitable for time-series charting in Altair or Streamlit.

    Expected fields:
    - Timestamp
    - Type
    """

    if not structured_data:
        return pd.DataFrame()

    df = pd.DataFrame(structured_data)

    required_columns = {"Timestamp", "Type"}
    if not required_columns.issubset(df.columns):
        return pd.DataFrame()

    # Convert invalid timestamps to NaT, then remove them.
    df["Timestamp"] = pd.to_datetime(
        df["Timestamp"],
        errors="coerce",
    )
    df = df.dropna(subset=["Timestamp"])

    if df.empty:
        return pd.DataFrame()

    def clean_type(value):
        """
        Normalize log event types.
        """
        normalized = str(value).lower()

        if "secur" in normalized:
            return "Security"

        if "perf" in normalized:
            return "Performance"

        return "Normal"

    df["Type"] = df["Type"].apply(clean_type)
    df["Count"] = 1

    # Group events into one-minute intervals.
    df["Time_Min"] = df["Timestamp"].dt.floor("min")

    aggregated_df = (
        df.groupby(
            ["Time_Min", "Type"],
            as_index=False,
        )["Count"]
        .sum()
        .rename(columns={"Time_Min": "Timestamp"})
    )

    return aggregated_df


def calculate_metrics(logs):
    """
    Generate dashboard metrics from parsed log entries.
    """

    logs = logs or []

    severity_counter = Counter()
    error_counter = Counter()

    for line in logs:
        text = str(line).lower()

        # Severity classification
        if "critical" in text:
            severity_counter["Critical"] += 1
        elif "high" in text:
            severity_counter["High"] += 1
        elif "medium" in text:
            severity_counter["Medium"] += 1
        elif "low" in text:
            severity_counter["Low"] += 1
        elif "error" in text or "failed" in text:
            severity_counter["Error"] += 1
        else:
            severity_counter["Unknown"] += 1

        # Error category classification
        if "accessdenied" in text or "access denied" in text:
            error_counter["AccessDenied"] += 1
        elif "iam" in text:
            error_counter["IAM"] += 1
        elif "bucket" in text or "s3" in text:
            error_counter["S3"] += 1
        elif "database" in text or "rds" in text:
            error_counter["Database"] += 1
        elif "cpu" in text:
            error_counter["CPU"] += 1
        elif "memory" in text:
            error_counter["Memory"] += 1
        elif "timeout" in text:
            error_counter["Timeout"] += 1
        elif "502" in text or "503" in text or "504" in text:
            error_counter["HTTP 5xx"] += 1
        else:
            error_counter["Other"] += 1

    severity_df = pd.DataFrame(
        severity_counter.items(),
        columns=["Severity", "Count"],
    )

    error_df = pd.DataFrame(
        error_counter.items(),
        columns=["Error", "Count"],
    )

    return {
        "total_logs": len(logs),
        "severity": dict(severity_counter),
        "severity_df": severity_df,
        "error_df": error_df,
    }