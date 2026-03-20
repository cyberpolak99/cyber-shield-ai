import csv
import io
import pandas as pd
from typing import List, Dict

class BulkIPProcessor:
    """
    Service for processing Bulk IP CSV files and enriching them with Threat Intelligence data.
    """
    def __init__(self, lookup_func, max_rows=2000):
        self.lookup_func = lookup_func
        self.max_rows = max_rows
        self.cache = {}

    def process_csv(self, csv_file_bytes: bytes) -> str:
        """
        Processes the input CSV bytes, performs lookups, and returns enriched CSV string.
        """
        # Load CSV
        try:
            df = pd.read_csv(io.BytesIO(csv_file_bytes))
        except Exception as e:
            raise ValueError(f"Failed to parse CSV: {e}")

        if 'ip' not in df.columns:
            raise ValueError("CSV must contain an 'ip' column.")

        if len(df) > self.max_rows:
            raise ValueError(f"CSV exceeds the limit of {self.max_rows} rows.")

        # Prepare enrichment columns
        ti_scores = []
        risk_levels = []
        sources_list = []
        honeypot_flags = []

        # Process rows with in-memory caching
        for ip in df['ip']:
            ip_str = str(ip).strip()
            
            if ip_str not in self.cache:
                self.cache[ip_str] = self.lookup_func(ip_str)
            
            res = self.cache[ip_str]
            ti_scores.append(res['ti_score'])
            risk_levels.append(res['risk_level'])
            sources_list.append(res['sources'])
            honeypot_flags.append(res['seen_in_honeypot'])

        # Add enrichment columns to DataFrame
        df['ti_score'] = ti_scores
        df['risk_level'] = risk_levels
        df['sources'] = sources_list
        df['seen_in_honeypot'] = honeypot_flags

        # Convert back to CSV string
        output = io.StringIO()
        df.to_csv(output, index=False)
        return output.getvalue()
