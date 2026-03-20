# Cyber Shield AI 🛡️

> **Real-time IP Threat Intelligence powered by an active honeypot sensor network.**

[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## What is Cyber Shield AI?

Cyber Shield AI is an open-source threat intelligence platform that:

- 🕷️ **Catches real attackers** via a live honeypot sensor (CyberShield)
- 🔍 **Scores IP reputation** using aggregated honeypot + threat feed data
- 📊 **Enriches CSV lists** of IPs in bulk with `ti_score`, `risk_level`, `sources`, `seen_in_honeypot`
- 🔑 **Exposes a production-ready API** with key auth + RapidAPI support + rate limiting
- 🖥️ **Provides a live dashboard** for security operations

---

## Architecture

```
┌─────────────────────┐     SQLite      ┌─────────────────────┐
│   CyberShield       │─────────────────│  Threat Intel API   │
│   Honeypot Sensor   │  (shared DB)    │  Flask + Python     │
│   (cyber_shield/)   │                 │  :10000             │
└─────────────────────┘                 └────────┬────────────┘
                                                 │ REST API
                                        ┌────────▼────────────┐
                                        │  CyberShield        │
                                        │  Dashboard          │
                                        │  FastAPI :8000      │
                                        └─────────────────────┘
```

---

## Quick Start

### 1. Requirements

```bash
py -m pip install flask flask-cors fastapi uvicorn pandas sqlite3
```

### 2. Set environment variables

```powershell
# API keys for Threat Intelligence API
$env:THREAT_API_KEYS = "your-key-1,your-key-2"

# Optional: RapidAPI proxy secret
$env:RAPIDAPI_PROXY_SECRET = "your-rapidapi-proxy-secret"

# Optional: rate limiting (default: 60 req/min per key)
$env:REQUESTS_PER_MINUTE = "60"
```

### 3. Start the full stack

```powershell
# Terminal 1 – Threat Intelligence API (port 10000)
cd "C:\Users\Tata\Desktop\czyszczenie danych\threat-intelligence-api"
py threat_api.py

# Terminal 2 – CyberShield Honeypot (port 8080)
cd "C:\Users\Tata\Desktop\bartek\cyber_shield"
set PYTHONPATH=C:\Users\Tata\Desktop\bartek\cyber_shield
py cyber_shield_live.py

# Terminal 3 – Dashboard (port 8000)
cd "C:\Users\Tata\Desktop\bartek\cyber_shield"
py dashboard.py
```

### 4. Access

| Service | URL | Credentials |
|---|---|---|
| Dashboard | http://localhost:8000 | admin / PolskiCyber2026 |
| TI API | http://localhost:10000 | X-API-Key header |
| API Docs | http://localhost:10000/api/health | — |

---

## API Endpoints

### `GET /api/check/{ip}` — Single IP Lookup

```bash
curl -H "X-API-Key: your-key-1" http://localhost:10000/api/check/45.133.1.20
```

**Response:**
```json
{
  "ip": "45.133.1.20",
  "is_malicious": true,
  "ti_score": 1.0,
  "risk_level": "critical",
  "sources": "Malware;cybershield-honeypot",
  "seen_in_honeypot": 1,
  "honeypot_details": {
    "hit_count": 3,
    "first_seen": "2026-03-15 12:00:00",
    "last_seen": "2026-03-20 21:00:00",
    "types": ["Malware", "BruteForce"]
  }
}
```

---

### `POST /api/bulk-ip-csv` — Bulk IP Enrichment

Upload a `.csv` file with an `ip` column. Receive enriched CSV back.

```bash
curl -H "X-API-Key: your-key-1" \
     -F "file=@ips.csv" \
     http://localhost:10000/api/bulk-ip-csv \
     -o enriched_ips.csv
```

**Input CSV:**
```csv
ip,label,comment
45.133.1.20,suspicious,known_c2
1.2.3.4,unknown,
```

**Output CSV:**
```csv
ip,label,comment,ti_score,risk_level,sources,seen_in_honeypot
45.133.1.20,suspicious,known_c2,1.0,critical,Malware;cybershield-honeypot,1
1.2.3.4,unknown,,0.0,none,,0
```

**Limits:**
- Max file size: 5 MB
- Max rows: 2,000 IPs
- Rate limit: 60 req/min per key

---

### `GET /api/honeypot-feed` — Honeypot IP Feed

Get all IPs observed by the honeypot sensor.

```bash
curl -H "X-API-Key: your-key-1" \
     "http://localhost:10000/api/honeypot-feed?limit=100"
```

**Response:**
```json
{
  "status": "success",
  "count": 12,
  "data": [
    {
      "src_ip": "45.133.1.20",
      "hit_count": 7,
      "first_seen": "2026-03-15 12:00:00",
      "last_seen": "2026-03-20 21:00:00"
    }
  ]
}
```

---

### `GET /api/health` — Health Check (public, no auth)

```bash
curl http://localhost:10000/api/health
```

---

## Dashboard Features

| View | URL | Description |
|---|---|---|
| Main Dashboard | `/` | Total anomalies & active blocks |
| Anomaly Log | `/anomalies` | Last 50 events with AI scores |
| Top Attackers | `/top-attackers` | Honeypot attacker list with export |
| Bulk Enrichment | `/enrich` | CSV upload UI |

---

## Running Tests

```bash
cd "C:\Users\Tata\Desktop\czyszczenie danych\threat-intelligence-api"
py -m pytest test_security.py test_bulk_processor.py test_honeypot_feed.py -v
```

Expected: **26 passed**

---

## Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `THREAT_API_KEYS` | `test-key-1,...` | Comma-separated API keys |
| `RAPIDAPI_PROXY_SECRET` | *(empty)* | RapidAPI proxy secret |
| `REQUESTS_PER_MINUTE` | `60` | Rate limit per key |
| `DATABASE_URL` | `data/cyber_shield.db` | Path to SQLite |
| `PORT` | `10000` | Threat API port |
| `ADMIN_USER` | `admin` | Dashboard admin user |
| `ADMIN_PASS` | `PolskiCyber2026` | Dashboard admin password |
| `THREAT_API_URL` | `http://localhost:10000` | API base URL (for dashboard) |

---

## License

MIT © cyberpolak99
