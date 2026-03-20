"""
test_honeypot_feed.py – Tests for honeypot feed integration.
Run: py -m pytest test_honeypot_feed.py -v
"""
import pytest
import io
import sqlite3
import os
import tempfile
from unittest.mock import patch


# ─── Shared test DB fixture ───────────────────────────────────────────────────

@pytest.fixture(scope="module")
def test_db():
    """Create a temp SQLite DB with the anomalies schema and seed data."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db_path = tmp.name

    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            type TEXT,
            severity TEXT,
            score REAL,
            bytes_transferred INTEGER,
            description TEXT,
            label INTEGER DEFAULT 0
        )
    """)
    # Seed: one known honeypot IP
    conn.execute("""
        INSERT INTO anomalies (src_ip, type, severity, score, description, label)
        VALUES (?, ?, ?, ?, ?, ?)
    """, ("45.133.1.20", "Malware", "CRITICAL", 1.0, "Cobalt Strike C2", 1))
    conn.commit()
    conn.close()

    yield db_path
    os.unlink(db_path)


# ─── honeypot_feed unit tests ─────────────────────────────────────────────────

def test_is_ip_in_honeypot_true(test_db):
    """IP seeded in DB → is_ip_in_honeypot returns True."""
    import honeypot_feed
    honeypot_feed.invalidate_cache()

    with patch.dict(os.environ, {"DATABASE_URL": test_db}):
        honeypot_feed.invalidate_cache()
        # Patch internal _get_db_path
        with patch("honeypot_feed._get_db_path", return_value=test_db):
            honeypot_feed.invalidate_cache()
            result = honeypot_feed.is_ip_in_honeypot.__wrapped__("45.133.1.20")
    assert result is True


def test_is_ip_in_honeypot_false(test_db):
    """IP not in DB → is_ip_in_honeypot returns False."""
    with patch("honeypot_feed._get_db_path", return_value=test_db):
        import honeypot_feed
        honeypot_feed.invalidate_cache()
        result = honeypot_feed.is_ip_in_honeypot.__wrapped__("1.2.3.4")
    assert result is False


def test_get_honeypot_details(test_db):
    """get_honeypot_details returns correct stats for known IP."""
    with patch("honeypot_feed._get_db_path", return_value=test_db):
        import honeypot_feed
        details = honeypot_feed.get_honeypot_details("45.133.1.20")
    assert details["hit_count"] == 1
    assert "Malware" in details["types"]


def test_get_all_honeypot_ips(test_db):
    """get_all_honeypot_ips returns list with the seeded IP."""
    with patch("honeypot_feed._get_db_path", return_value=test_db):
        import honeypot_feed
        ips = honeypot_feed.get_all_honeypot_ips()
    assert any(row["src_ip"] == "45.133.1.20" for row in ips)


# ─── lookup_ip_internal integration tests ────────────────────────────────────

@pytest.fixture
def client_with_honeypot_db(test_db):
    """Flask test client with DB pointing to the test DB."""
    os.environ["DATABASE_URL"] = test_db
    from threat_api import app
    import honeypot_feed
    honeypot_feed.invalidate_cache()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c
    honeypot_feed.invalidate_cache()


def test_lookup_ip_in_honeypot(client_with_honeypot_db, test_db):
    """IP in honeypot DB → seen_in_honeypot=1, sources contains cybershield-honeypot."""
    import threat_api
    import honeypot_feed
    honeypot_feed.invalidate_cache()

    with patch("honeypot_feed._get_db_path", return_value=test_db):
        with patch("threat_api.db.db_path", test_db):
            result = threat_api.lookup_ip_internal("45.133.1.20")

    assert result["seen_in_honeypot"] == 1
    assert "cybershield-honeypot" in result["sources"]
    assert result["risk_level"] in ["high", "critical"]


def test_lookup_ip_not_in_honeypot(client_with_honeypot_db, test_db):
    """IP NOT in honeypot → seen_in_honeypot=0, no cybershield-honeypot in sources."""
    import threat_api
    import honeypot_feed
    honeypot_feed.invalidate_cache()

    with patch("honeypot_feed._get_db_path", return_value=test_db):
        with patch("threat_api.db.db_path", test_db):
            result = threat_api.lookup_ip_internal("9.9.9.9")

    assert result["seen_in_honeypot"] == 0
    assert "cybershield-honeypot" not in result["sources"]


# ─── Bulk CSV integration test ─────────────────────────────────────────────────

def test_bulk_csv_honeypot_enrichment(test_db):
    """In bulk CSV, IP from honeypot gets seen_in_honeypot=1 in output."""
    import security
    security._rate_store.clear()
    os.environ["DATABASE_URL"] = test_db

    import honeypot_feed
    honeypot_feed.invalidate_cache()

    from threat_api import app
    app.config["TESTING"] = True

    csv_data = b"ip,comment\n45.133.1.20,known_bad\n1.2.3.4,clean\n"
    data = {"file": (io.BytesIO(csv_data), "test.csv")}

    with patch("honeypot_feed._get_db_path", return_value=test_db):
        with app.test_client() as client:
            resp = client.post(
                "/api/bulk-ip-csv",
                headers={"X-API-Key": "test-key-1"},
                content_type="multipart/form-data",
                data=data
            )

    assert resp.status_code == 200
    output = resp.data.decode("utf-8")
    lines = [l for l in output.strip().split("\n") if l]
    # Find index of seen_in_honeypot column
    header = [h.strip() for h in lines[0].split(",")]
    hp_idx = header.index("seen_in_honeypot")
    src_idx = header.index("sources")
    ip_idx = header.index("ip")

    # Check the 45.133.1.20 row
    for line in lines[1:]:
        cols = line.split(",")
        if cols[ip_idx].strip() == "45.133.1.20":
            assert cols[hp_idx].strip() == "1"
            assert "cybershield-honeypot" in cols[src_idx]
