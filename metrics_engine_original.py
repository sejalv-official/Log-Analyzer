import pandas as pd

def generate_timeseries_dataframe(structured_data):
    """
    Takes a list of dictionaries (structured_data from AI parsing)
    and converts it into an aggregated pandas DataFrame suitable for
    time-series charting in Altair/Streamlit.
    """
    if not structured_data:
        return pd.DataFrame()
        
    df = pd.DataFrame(structured_data)
    
    if 'Timestamp' not in df.columns or 'Type' not in df.columns:
        return pd.DataFrame()
        
    # Convert to datetime, coerce errors to NaT, then drop rows with NaT
    # This handles "N/A" or garbage timestamps the AI might spit out.
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df = df.dropna(subset=['Timestamp'])
    
    if df.empty:
        return pd.DataFrame()
        
    # Standardize Type strings to match our Security/Performance naming
    def clean_type(val):
        val = str(val).lower()
        if 'secur' in val: return 'Security'
        if 'perf' in val: return 'Performance'
        return 'Normal'
        
    df['Type'] = df['Type'].apply(clean_type)
    
    # We want to aggregate counts over time.
    # We add a dummy 'Count' column
    df['Count'] = 1
    
    # Group by Timestamp (e.g. rounding to nearest minute/second depending on density)
    # To keep it simple, we use the raw timestamp (or round to minute if needed).
    # Grouping by 1 minute for a smoother chart:
    df['Time_Min'] = df['Timestamp'].dt.floor('Min')
    
    # Aggregate
    agg_df = df.groupby(['Time_Min', 'Type'])['Count'].sum().reset_index()
    
    # Rename column back to Timestamp for the chart
    agg_df = agg_df.rename(columns={'Time_Min': 'Timestamp'})
    
    return agg_df
