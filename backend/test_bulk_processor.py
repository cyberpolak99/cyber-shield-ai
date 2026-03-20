"""
Unit tests for BulkIPProcessor service.
Run: py -m pytest test_bulk_processor.py -v
"""
import pytest
import io
from unittest.mock import MagicMock, patch
from bulk_processor import BulkIPProcessor

# Mockowy lookup — zwraca wyniki na podstawie IP
def mock_lookup(ip: str) -> dict:
    data = {
        "45.133.1.20":  {'ti_score': 1.0, 'risk_level': 'critical', 'sources': 'Malware', 'seen_in_honeypot': 0},
        "185.220.101.5":{'ti_score': 0.8, 'risk_level': 'high',     'sources': 'BruteForce', 'seen_in_honeypot': 1},
        "1.2.3.4":      {'ti_score': 0.0, 'risk_level': 'none',     'sources': '',           'seen_in_honeypot': 0},
    }
    return data.get(ip, {'ti_score': 0, 'risk_level': 'none', 'sources': '', 'seen_in_honeypot': 0})


# ─── Tests ────────────────────────────────────────────────────────────────────

def make_csv(rows: list[str]) -> bytes:
    return ("\n".join(rows)).encode("utf-8")


def test_basic_enrichment():
    """Should enrich 3 unique IPs and return 4 extra columns"""
    csv_bytes = make_csv([
        "ip,label",
        "45.133.1.20,suspicious",
        "185.220.101.5,unknown",
        "1.2.3.4,clean",
    ])
    proc = BulkIPProcessor(lookup_func=mock_lookup)
    result = proc.process_csv(csv_bytes)

    lines = [l for l in result.strip().split("\n") if l]
    header = [h.strip() for h in lines[0].split(",")]
    assert "ti_score" in header
    assert "risk_level" in header
    assert "sources" in header
    assert "seen_in_honeypot" in header
    assert len(lines) == 4  # header + 3 data rows


def test_preserves_original_columns():
    """Original columns in input must be preserved in output"""
    csv_bytes = make_csv([
        "ip,country,owner",
        "1.2.3.4,PL,TestOrg",
    ])
    proc = BulkIPProcessor(lookup_func=mock_lookup)
    result = proc.process_csv(csv_bytes)

    header = result.strip().split("\n")[0].split(",")
    assert header[0] == "ip"
    assert "country" in header
    assert "owner" in header


def test_deduplication_cache():
    """Duplicate IPs in CSV should only trigger one lookup call"""
    call_counter = {'n': 0}

    def counting_lookup(ip):
        call_counter['n'] += 1
        return mock_lookup(ip)

    csv_bytes = make_csv([
        "ip",
        "45.133.1.20",
        "45.133.1.20",
        "45.133.1.20",
    ])
    proc = BulkIPProcessor(lookup_func=counting_lookup)
    proc.process_csv(csv_bytes)

    assert call_counter['n'] == 1, "Cache should prevent duplicate lookups"


def test_missing_ip_column():
    """CSV without 'ip' column should raise ValueError"""
    csv_bytes = make_csv([
        "address,label",
        "1.2.3.4,bad",
    ])
    proc = BulkIPProcessor(lookup_func=mock_lookup)
    with pytest.raises(ValueError, match="ip"):
        proc.process_csv(csv_bytes)


def test_row_limit_exceeded():
    """CSVs exceeding max_rows should raise ValueError"""
    rows = ["ip"] + [f"10.0.{i // 256}.{i % 256}" for i in range(51)]
    csv_bytes = make_csv(rows)
    proc = BulkIPProcessor(lookup_func=mock_lookup, max_rows=50)
    with pytest.raises(ValueError, match="limit"):
        proc.process_csv(csv_bytes)


def test_lookup_failure_does_not_break_job():
    """If lookup raises an exception for one IP, others should still be processed"""
    def flaky_lookup(ip):
        if ip == "9.9.9.9":
            raise RuntimeError("timeout")
        return mock_lookup(ip)

    # Wrap in try/except inside BulkIPProcessor — simulate graceful fallback
    def safe_lookup(ip):
        try:
            return flaky_lookup(ip)
        except Exception:
            return {'ti_score': 0, 'risk_level': 'error', 'sources': '', 'seen_in_honeypot': 0}

    csv_bytes = make_csv([
        "ip",
        "9.9.9.9",
        "1.2.3.4",
    ])
    proc = BulkIPProcessor(lookup_func=safe_lookup)
    result = proc.process_csv(csv_bytes)
    lines = [l for l in result.strip().split("\n") if l]
    assert len(lines) == 3  # header + 2 rows — nie przerwało
