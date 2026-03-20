"""
Integration tests for unified API Key Auth + RapidAPI Auth + Rate Limiting.
Run: py -m pytest test_security.py -v
"""
import pytest
import io
from threat_api import app
import security


@pytest.fixture(autouse=True)
def clean_rate_store():
    """Reset rate store before each test."""
    security._rate_store.clear()
    yield
    security._rate_store.clear()


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


VALID_KEY = "test-key-1"
BAD_KEY = "invalid-key-xyz"
VALID_RAPID_SECRET = "rapidapi-test-secret-9999"


# ─── Helper to temporarily set env-driven config ──────────────────────────────

@pytest.fixture
def with_rapid_secret(monkeypatch):
    """Enable RapidAPI secret enforcement for the duration of the test."""
    monkeypatch.setattr(security, "RAPIDAPI_SECRET", VALID_RAPID_SECRET)
    yield VALID_RAPID_SECRET


# ─── Public endpoint tests ────────────────────────────────────────────────────

def test_health_is_public(client):
    """/api/health should be accessible without any auth header."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "healthy"


def test_home_is_public(client):
    """GET / should be accessible without any auth header."""
    resp = client.get("/")
    assert resp.status_code == 200


# ─── API Key auth tests ───────────────────────────────────────────────────────

def test_check_ip_valid_api_key(client):
    """Valid X-API-Key → 200 OK"""
    resp = client.get("/api/check/1.2.3.4", headers={"X-API-Key": VALID_KEY})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "ip" in data


def test_check_ip_no_auth(client):
    """No auth header at all → 401"""
    resp = client.get("/api/check/1.2.3.4")
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid or missing API key"


def test_check_ip_bad_api_key(client):
    """Wrong X-API-Key → 401"""
    resp = client.get("/api/check/1.2.3.4", headers={"X-API-Key": BAD_KEY})
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid or missing API key"


# ─── RapidAPI auth tests ──────────────────────────────────────────────────────

def test_check_ip_valid_rapidapi_secret(client, with_rapid_secret):
    """Valid X-RapidAPI-Proxy-Secret → 200 OK (no API key needed)"""
    resp = client.get(
        "/api/check/1.2.3.4",
        headers={"X-RapidAPI-Proxy-Secret": with_rapid_secret, "X-RapidAPI-User": "testuser123"}
    )
    assert resp.status_code == 200


def test_check_ip_bad_rapidapi_secret(client, with_rapid_secret):
    """Wrong X-RapidAPI-Proxy-Secret AND no X-API-Key → 401"""
    resp = client.get(
        "/api/check/1.2.3.4",
        headers={"X-RapidAPI-Proxy-Secret": "WRONG-SECRET"}
    )
    assert resp.status_code == 401


def test_check_ip_rapid_secret_ignored_when_not_configured(client):
    """When RAPIDAPI_PROXY_SECRET is not set, sending that header doesn't grant access."""
    # RAPIDAPI_SECRET is "" by default in test env (not set)
    # So sending the header without X-API-Key must still fail
    resp = client.get(
        "/api/check/1.2.3.4",
        headers={"X-RapidAPI-Proxy-Secret": "any-value-here"}
    )
    assert resp.status_code == 401


# ─── Bulk CSV auth tests ──────────────────────────────────────────────────────

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


# ─── Rate Limit tests ─────────────────────────────────────────────────────────

def test_rate_limit_exceeded(client):
    """Exceed per-key request limit → 429 with retry_after field"""
    original = security.REQUESTS_PER_MINUTE
    security.REQUESTS_PER_MINUTE = 3
    rate_key = "rate-test-unique-key"
    security.ALLOWED_API_KEYS.add(rate_key)

    try:
        for _ in range(3):
            r = client.get("/api/check/1.2.3.4", headers={"X-API-Key": rate_key})
            assert r.status_code == 200

        r = client.get("/api/check/1.2.3.4", headers={"X-API-Key": rate_key})
        assert r.status_code == 429
        body = r.get_json()
        assert body["error"] == "Rate limit exceeded"
        assert "retry_after_seconds" in body
    finally:
        security.REQUESTS_PER_MINUTE = original
        security.ALLOWED_API_KEYS.discard(rate_key)


def test_rate_limit_two_keys_independent(client):
    """Two different keys have independent counters."""
    original = security.REQUESTS_PER_MINUTE
    security.REQUESTS_PER_MINUTE = 2
    key_a, key_b = "rate-key-A", "rate-key-B"
    security.ALLOWED_API_KEYS.update({key_a, key_b})

    try:
        for _ in range(2):
            client.get("/api/check/1.2.3.4", headers={"X-API-Key": key_a})

        r_a = client.get("/api/check/1.2.3.4", headers={"X-API-Key": key_a})
        r_b = client.get("/api/check/1.2.3.4", headers={"X-API-Key": key_b})

        assert r_a.status_code == 429
        assert r_b.status_code == 200
    finally:
        security.REQUESTS_PER_MINUTE = original
        security.ALLOWED_API_KEYS.discard(key_a)
        security.ALLOWED_API_KEYS.discard(key_b)


def test_rapidapi_user_rate_limit_separate_from_api_key(client, with_rapid_secret):
    """RapidAPI user identity and direct API key identity are tracked separately."""
    original = security.REQUESTS_PER_MINUTE
    security.REQUESTS_PER_MINUTE = 2

    try:
        for _ in range(2):
            client.get(
                "/api/check/1.2.3.4",
                headers={
                    "X-RapidAPI-Proxy-Secret": with_rapid_secret,
                    "X-RapidAPI-User": "rapid-user-ABC"
                }
            )

        # RapidAPI user exhausted
        r_rapid = client.get(
            "/api/check/1.2.3.4",
            headers={
                "X-RapidAPI-Proxy-Secret": with_rapid_secret,
                "X-RapidAPI-User": "rapid-user-ABC"
            }
        )
        # Direct API key still fresh
        r_direct = client.get(
            "/api/check/1.2.3.4",
            headers={"X-API-Key": VALID_KEY}
        )

        assert r_rapid.status_code == 429
        assert r_direct.status_code == 200
    finally:
        security.REQUESTS_PER_MINUTE = original
