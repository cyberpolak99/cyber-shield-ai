## Threat Intelligence API & Bulk IP Enrichment

The Threat Intelligence API provides real-time IP reputation lookups and bulk enrichment for security operations. It combines data from an active honeypot sensor network with automated threat feeds to deliver actionable intelligence.

### Authentication

All protected endpoints require one of the following headers:

| Header | Purpose |
|---|---|
| `X-API-Key: <key>` | Direct access — for developers, internal tools |
| `X-RapidAPI-Proxy-Secret: <secret>` | RapidAPI subscription access |

Public endpoints (`GET /`, `GET /api/health`) require no authentication.

---

### Endpoint: `GET /api/check/{ip}`

Look up a single IP address against the threat database.

**Request:**
```http
GET /api/check/45.133.1.20
X-API-Key: your-api-key
```

**Response:**
```json
{
  "ip": "45.133.1.20",
  "is_malicious": true,
  "ti_score": 1.0,
  "risk_level": "critical",
  "sources": "Malware;BruteForce",
  "seen_in_honeypot": 1
}
```

**Fields:**

| Field | Type | Description |
|---|---|---|
| `ip` | string | The queried IP address |
| `is_malicious` | bool | True if any threat record exists |
| `ti_score` | float | Risk score (0.0 = clean, 1.0 = confirmed threat) |
| `risk_level` | string | `none`, `low`, `medium`, `high`, `critical` |
| `sources` | string | Semicolon-separated threat source names |
| `seen_in_honeypot` | int | `1` if detected by honeypot sensor, else `0` |

---

### Endpoint: `POST /api/bulk-ip-csv`

Upload a CSV file containing a list of IP addresses and receive an enriched CSV in return.

**Request:**
- Method: `POST`
- Content-Type: `multipart/form-data`
- Field name: `file` (`.csv` file)
- Required CSV column: `ip`

**Limits:**
- Max file size: **5 MB**
- Max rows: **2,000 IPs per request**
- Rate limit: **60 requests/minute per key**

**Example (curl):**
```bash
curl -H "X-API-Key: your-key" \
     -F "file=@ips.csv" \
     https://your-api.example.com/api/bulk-ip-csv \
     -o enriched_ips.csv
```

**Input CSV:**
```csv
ip,label
45.133.1.20,suspicious
1.2.3.4,unknown
```

**Output CSV (enriched):**
```csv
ip,label,ti_score,risk_level,sources,seen_in_honeypot
45.133.1.20,suspicious,1.0,critical,Malware,1
1.2.3.4,unknown,0.0,none,,0
```

---

### Rate Limiting

| Dimension | Limit |
|---|---|
| Per API key / RapidAPI user | 60 requests / 60 seconds |
| Algorithm | Sliding window |
| Exceeded response | `429` with `retry_after_seconds` in JSON |

```json
{
  "error": "Rate limit exceeded",
  "retry_after_seconds": 42
}
```
