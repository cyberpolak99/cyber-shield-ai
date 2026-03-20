"""
Integration tests for API Key Auth + Rate Limiting.
Run: py -m pytest test_security.py -v
"""
import pytest
import io
from unittest.mock import patch
from threat_api import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


VALID_KEY = "test-key-1"
BAD_KEY = "invalid-key-xyz"


# ─── Auth tests ───────────────────────────────────────────────────────────────

def test_check_ip_valid_key(client):
    """Valid X-API-Key → 200 OK"""
    resp = client.get("/api/check/1.2.3.4", headers={"X-API-Key": VALID_KEY})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "ip" in data


def test_check_ip_no_key(client):
    """Missing X-API-Key → 401"""
    resp = client.get("/api/check/1.2.3.4")
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid or missing API key"


def test_check_ip_bad_key(client):
    """Wrong X-API-Key → 401"""
    resp = client.get("/api/check/1.2.3.4", headers={"X-API-Key": BAD_KEY})
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid or missing API key"


def test_bulk_csv_valid_key(client):
    """Valid key + valid CSV → 200 with text/csv response"""
    csv_data = b"ip\n1.2.3.4\n5.6.7.8\n"
    data = {"file": (io.BytesIO(csv_data), "test.csv")}
    resp = client.post(
        "/api/bulk-ip-csv",
        headers={"X-API-Key": VALID_KEY},
        content_type="multipart/form-data",
        data=data
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.content_type


def test_bulk_csv_no_key(client):
    """Bulk CSV without key → 401"""
    csv_data = b"ip\n1.2.3.4\n"
    data = {"file": (io.BytesIO(csv_data), "test.csv")}
    resp = client.post(
        "/api/bulk-ip-csv",
        content_type="multipart/form-data",
        data=data
    )
    assert resp.status_code == 401


def test_health_public(client):
    """/api/health should be accessible without API key"""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "healthy"


# ─── Rate Limit tests ─────────────────────────────────────────────────────────

def test_rate_limit_exceeded(client):
    """Exceed per-key request limit → 429 with retry_after field"""
    # Patch REQUESTS_PER_MINUTE to 3 for fast testing
    import security
    original = security.REQUESTS_PER_MINUTE
    security.REQUESTS_PER_MINUTE = 3
    # Use a unique key so it doesn't interfere with other tests
    rate_key = "rate-test-key"
    security.ALLOWED_API_KEYS.add(rate_key)
    security._rate_store.clear()

    try:
        for i in range(3):
            r = client.get("/api/check/1.2.3.4", headers={"X-API-Key": rate_key})
            assert r.status_code == 200

        # 4th request must be blocked
        r = client.get("/api/check/1.2.3.4", headers={"X-API-Key": rate_key})
        assert r.status_code == 429
        body = r.get_json()
        assert body["error"] == "Rate limit exceeded"
        assert "retry_after_seconds" in body
    finally:
        security.REQUESTS_PER_MINUTE = original
        security.ALLOWED_API_KEYS.discard(rate_key)
        security._rate_store.clear()


def test_rate_limit_different_keys_independent(client):
    """Two different keys should have independent rate limit counters"""
    import security
    original = security.REQUESTS_PER_MINUTE
    security.REQUESTS_PER_MINUTE = 2
    key_a = "key-a-test"
    key_b = "key-b-test"
    security.ALLOWED_API_KEYS.update({key_a, key_b})
    security._rate_store.clear()

    try:
        # Exhaust key_a
        for _ in range(2):
            client.get("/api/check/1.2.3.4", headers={"X-API-Key": key_a})

        # key_a blocked, key_b still allowed
        r_a = client.get("/api/check/1.2.3.4", headers={"X-API-Key": key_a})
        r_b = client.get("/api/check/1.2.3.4", headers={"X-API-Key": key_b})

        assert r_a.status_code == 429
        assert r_b.status_code == 200
    finally:
        security.REQUESTS_PER_MINUTE = original
        security.ALLOWED_API_KEYS.discard(key_a)
        security.ALLOWED_API_KEYS.discard(key_b)
        security._rate_store.clear()
