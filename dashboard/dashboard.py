from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from db_manager import DBManager
import uvicorn
import secrets
import html
import sqlite3
import io
import csv
import os
import logging

logger = logging.getLogger("CyberShieldDashboard")

app = FastAPI(title="PolskiCyberShield Dashboard")
db = DBManager()
security = HTTPBasic()

# Auth config
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "PolskiCyber2026")

# Threat API base URL (for Bulk CSV export button)
THREAT_API_URL = os.environ.get("THREAT_API_URL", "http://localhost:10000")
THREAT_API_KEY = os.environ.get("THREAT_API_KEY", "test-key-1")

# ─── Shared CSS ───────────────────────────────────────────────────────────────
_SHARED_CSS = """
    body { font-family: 'Segoe UI', sans-serif; background: #111; color: #e0e0e0; margin: 0; padding: 0; }
    .topbar { background: #1a1a1a; border-bottom: 2px solid #ff0000; padding: 14px 30px; display: flex; align-items: center; gap: 20px; }
    .topbar h1 { color: #ff3333; font-size: 1.4em; margin: 0; }
    .nav a { color: #00ff88; text-decoration: none; padding: 6px 14px; border: 1px solid #00ff88; border-radius: 4px; font-size: 0.9em; transition: all .2s; }
    .nav a:hover { background: #00ff88; color: #000; }
    .page { padding: 30px; }
    .cards { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 30px; }
    .card { background: #1e1e1e; border: 1px solid #333; border-radius: 10px; padding: 24px 30px; flex: 1; min-width: 160px; }
    .card h3 { margin: 0 0 10px 0; color: #888; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }
    .stat { font-size: 2.8em; font-weight: bold; color: #00ff88; }
    .stat.danger { color: #ff4444; }
    table { width: 100%; border-collapse: collapse; background: #1a1a1a; border-radius: 8px; overflow: hidden; font-size: 0.9em; }
    thead th { background: #252525; color: #00ff88; padding: 12px 14px; text-align: left; border-bottom: 1px solid #333; }
    tbody tr { border-bottom: 1px solid #222; transition: background .15s; }
    tbody tr:hover { background: #252525; }
    td { padding: 10px 14px; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75em; font-weight: bold; }
    .badge-critical { background: #4a0000; color: #ff4444; }
    .badge-high { background: #3a1a00; color: #ff8800; }
    .badge-medium { background: #2a2a00; color: #ffcc00; }
    .badge-low { background: #002a10; color: #00cc66; }
    .badge-none { background: #222; color: #666; }
    .btn { display: inline-block; padding: 8px 18px; border-radius: 5px; font-size: 0.9em; cursor: pointer; border: none; font-weight: bold; }
    .btn-green { background: #00ff88; color: #000; text-decoration: none; }
    .btn-green:hover { background: #00cc66; }
    .section-title { font-size: 1.2em; font-weight: bold; color: #ccc; margin: 30px 0 15px 0; border-left: 3px solid #00ff88; padding-left: 12px; }
    code { background: #252525; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; color: #00ff88; }
    .upload-box { background: #1e1e1e; border: 2px dashed #333; border-radius: 10px; padding: 30px; max-width: 600px; }
    .upload-box:hover { border-color: #00ff88; }
    input[type=file] { color: #ccc; margin: 12px 0; display: block; }
    footer { margin-top: 40px; color: #444; font-size: 0.8em; border-top: 1px solid #222; padding-top: 16px; }
"""

def _nav(active=""):
    links = [
        ("/", "🏠 Dashboard"),
        ("/anomalies", "🚨 Anomalie"),
        ("/top-attackers", "🔥 Top Attackers"),
        ("/enrich", "📊 Bulk Enrichment"),
    ]
    html_out = '<div class="nav" style="display:flex;gap:10px;margin-left:auto;">'
    for href, label in links:
        style = ' style="background:#00ff88;color:#000;"' if href == active else ""
        html_out += f'<a href="{href}"{style}>{label}</a>'
    html_out += '</div>'
    return html_out


def _topbar(active=""):
    return f"""
    <div class="topbar">
        <h1>🛡️ PolskiCyberShield</h1>
        {_nav(active)}
    </div>"""


def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    ok_user = secrets.compare_digest(credentials.username, ADMIN_USER)
    ok_pass = secrets.compare_digest(credentials.password, ADMIN_PASS)
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


def _risk_badge(level: str) -> str:
    level = str(level).lower()
    cls = {"critical": "badge-critical", "high": "badge-high",
           "medium": "badge-medium", "low": "badge-low"}.get(level, "badge-none")
    return f'<span class="badge {cls}">{level.upper()}</span>'


# ─── Dashboard Home ───────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def get_dashboard(username: str = Depends(authenticate)):
    stats = db.get_stats()
    return f"""<!DOCTYPE html>
<html><head><title>CyberShield Dashboard</title><style>{_SHARED_CSS}</style></head>
<body>
{_topbar("/")}
<div class="page">
  <div class="cards">
    <div class="card"><h3>Total Anomalies</h3><div class="stat">{stats['total_anomalies']}</div></div>
    <div class="card"><h3>Active IP Blocks</h3><div class="stat danger">{stats['active_blocks']}</div></div>
  </div>
  <div class="section-title">Quick Links</div>
  <div style="display:flex;gap:14px;flex-wrap:wrap;">
    <a class="btn btn-green" href="/top-attackers">🔥 View Top Attackers</a>
    <a class="btn btn-green" href="/anomalies">🚨 View Anomaly Log</a>
    <a class="btn btn-green" href="/enrich">📊 Bulk IP Enrichment</a>
  </div>
  <footer>CyberShield AI v6.0 PROF | Logged in as: {html.escape(username)}</footer>
</div>
</body></html>"""


# ─── Anomalies ────────────────────────────────────────────────────────────────
@app.get("/anomalies", response_class=HTMLResponse)
async def get_anomalies(username: str = Depends(authenticate)):
    anomalies = db.get_anomalies_with_geo(limit=50, use_geo=False)
    rows = ""
    for a in anomalies:
        ts   = html.escape(str(a.get('timestamp', '')))
        src  = html.escape(str(a.get('src_ip', '')))
        dst  = html.escape(str(a.get('dst_ip', '')))
        desc = html.escape(str(a.get('description', '')))
        score = float(a.get('iso_score') or a.get('score') or 0)
        score_color = "#ff4444" if score < -0.3 else "#00ff88"
        label_icon = "⚠️" if a.get('label') == 1 else ""
        rows += f"""<tr>
            <td>{ts}</td>
            <td style="color:#ff8800;font-weight:bold">{src}</td>
            <td>{dst}</td>
            <td>{desc}</td>
            <td style="color:{score_color}">{score:.4f}</td>
            <td style="text-align:center">{label_icon}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><title>Anomalies – CyberShield</title><style>{_SHARED_CSS}</style></head>
<body>
{_topbar("/anomalies")}
<div class="page">
  <div class="section-title">🚨 Last 50 Anomalies</div>
  <table>
    <thead><tr><th>Timestamp</th><th>Source IP</th><th>Destination</th><th>Description</th><th>AI Score</th><th>Label</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <footer>Showing up to 50 recent events · CyberShield AI</footer>
</div>
</body></html>"""


# ─── Top Attackers (Honeypot Feed) ────────────────────────────────────────────
@app.get("/top-attackers", response_class=HTMLResponse)
async def top_attackers(username: str = Depends(authenticate)):
    """Show top attacking IPs from honeypot with ti_score from DB."""
    try:
        with sqlite3.connect(db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    src_ip,
                    COUNT(*)          AS hit_count,
                    MIN(timestamp)    AS first_seen,
                    MAX(timestamp)    AS last_seen,
                    GROUP_CONCAT(DISTINCT type) AS types,
                    MAX(score)        AS max_score,
                    MAX(severity)     AS max_severity
                FROM anomalies
                WHERE src_ip IS NOT NULL AND src_ip != ''
                GROUP BY src_ip
                ORDER BY hit_count DESC
                LIMIT 100
            """)
            rows_data = [dict(r) for r in cursor.fetchall()]
    except Exception as e:
        rows_data = []
        logger.error(f"Top attackers query failed: {e}")

    severity_to_risk = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

    rows = ""
    for r in rows_data:
        ip       = html.escape(str(r.get("src_ip", "")))
        hits     = r.get("hit_count", 0)
        first    = html.escape(str(r.get("first_seen", ""))[:19])
        last     = html.escape(str(r.get("last_seen", ""))[:19])
        types    = html.escape(str(r.get("types") or ""))
        score    = float(r.get("max_score") or 0)
        sev_raw  = str(r.get("max_severity") or "").upper()
        risk     = severity_to_risk.get(sev_raw, "none")
        badge    = _risk_badge(risk)
        rows += f"""<tr>
            <td style="color:#ff8800;font-weight:bold">{ip}</td>
            <td style="text-align:center;font-weight:bold;color:#ff4444">{hits}</td>
            <td style="font-size:0.8em;color:#888">{first}</td>
            <td style="font-size:0.8em;color:#888">{last}</td>
            <td style="font-size:0.8em">{types}</td>
            <td style="text-align:center">{score:.2f}</td>
            <td>{badge}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><title>Top Attackers – CyberShield</title>
<style>{_SHARED_CSS}</style>
</head>
<body>
{_topbar("/top-attackers")}
<div class="page">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
    <div class="section-title" style="margin:0">🔥 Top Attacking IPs from Honeypot</div>
    <a class="btn btn-green" href="/export-top-attackers-csv">⬇ Export Enriched CSV</a>
  </div>
  <table>
    <thead>
      <tr>
        <th>IP Address</th><th>Hits</th><th>First Seen</th><th>Last Seen</th>
        <th>Attack Types</th><th>Score</th><th>Risk Level</th>
      </tr>
    </thead>
    <tbody>{rows if rows else '<tr><td colspan="7" style="text-align:center;color:#555;padding:30px">No data yet – start the honeypot sensor</td></tr>'}</tbody>
  </table>
  <p style="color:#555;font-size:0.8em;margin-top:12px">
    Click <strong>Export Enriched CSV</strong> to download this list enriched with full threat intelligence scores.
  </p>
  <footer>Showing top 100 honeypot attackers · CyberShield AI</footer>
</div>
</body></html>"""


# ─── Export Enriched CSV ──────────────────────────────────────────────────────
@app.get("/export-top-attackers-csv")
async def export_top_attackers_csv(username: str = Depends(authenticate)):
    """
    Generates a CSV of top honeypot IPs enriched from the local DB and returns as download.
    (No external call to /api/bulk-ip-csv needed – uses the same DB directly.)
    """
    try:
        with sqlite3.connect(db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    src_ip                      AS ip,
                    COUNT(*)                    AS hit_count,
                    MIN(timestamp)              AS first_seen,
                    MAX(timestamp)              AS last_seen,
                    GROUP_CONCAT(DISTINCT type) AS sources,
                    MAX(score)                  AS ti_score,
                    MAX(severity)               AS max_severity
                FROM anomalies
                WHERE src_ip IS NOT NULL AND src_ip != ''
                GROUP BY src_ip
                ORDER BY hit_count DESC
                LIMIT 500
            """)
            rows = [dict(r) for r in cursor.fetchall()]
    except Exception:
        rows = []

    severity_to_risk = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["ip", "hit_count", "first_seen", "last_seen",
                    "sources", "ti_score", "risk_level", "seen_in_honeypot"],
        extrasaction="ignore"
    )
    writer.writeheader()
    for r in rows:
        sev = str(r.get("max_severity") or "").upper()
        # Add cybershield-honeypot to sources
        sources_val = r.get("sources") or ""
        if "cybershield-honeypot" not in sources_val:
            sources_val = (sources_val + ";cybershield-honeypot").lstrip(";")
        writer.writerow({
            "ip":               r.get("ip", ""),
            "hit_count":        r.get("hit_count", 0),
            "first_seen":       str(r.get("first_seen", ""))[:19],
            "last_seen":        str(r.get("last_seen", ""))[:19],
            "sources":          sources_val,
            "ti_score":         r.get("ti_score", 0),
            "risk_level":       severity_to_risk.get(sev, "low"),
            "seen_in_honeypot": 1,
        })

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=top_attackers_enriched.csv"}
    )


# ─── Bulk CSV Enrichment UI ───────────────────────────────────────────────────
@app.get("/enrich", response_class=HTMLResponse)
async def get_enrich(username: str = Depends(authenticate)):
    example_csv = "ip,label,comment\n45.133.1.20,suspicious,known_c2\n185.220.101.5,scanner,\n1.2.3.4,unknown,"

    return f"""<!DOCTYPE html>
<html><head><title>Bulk Enrichment – CyberShield</title>
<style>{_SHARED_CSS}
pre {{ background:#1a1a1a; border:1px solid #333; border-radius:6px; padding:14px; font-size:0.85em; color:#00ff88; overflow-x:auto; }}
</style>
</head>
<body>
{_topbar("/enrich")}
<div class="page">
  <div class="section-title">📊 Bulk IP CSV Enrichment</div>
  <p style="color:#aaa;max-width:700px;">
    Upload a CSV file containing an <code>ip</code> column. The system will enrich each row with threat intelligence data:
    <code>ti_score</code>, <code>risk_level</code>, <code>sources</code>, and <code>seen_in_honeypot</code>.
    All original columns are preserved in the output.
  </p>

  <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:flex-start;">
    <div class="upload-box">
      <h3 style="margin:0 0 10px 0;color:#ccc">Upload CSV File</h3>
      <p style="color:#666;font-size:0.85em;">Max 5MB · Max 2,000 rows · Required column: <code>ip</code></p>
      <form action="{THREAT_API_URL}/api/bulk-ip-csv" method="POST" enctype="multipart/form-data">
        <input type="hidden" name="x-api-key" value="{THREAT_API_KEY}">
        <input type="file" name="file" accept=".csv" required />
        <br>
        <button type="submit" class="btn btn-green" style="margin-top:10px">⬆ Enrich CSV</button>
      </form>
      <p style="color:#444;font-size:0.75em;margin-top:12px">
        Note: The download will start automatically. Auth is handled via the configured API key.
      </p>
    </div>

    <div style="flex:1;min-width:280px">
      <div class="section-title" style="margin-top:0">Example Input CSV</div>
      <pre>{html.escape(example_csv)}</pre>
      <div class="section-title">Expected Output Columns</div>
      <table style="font-size:0.85em">
        <thead><tr><th>Column</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><code>ti_score</code></td><td>0.0 (clean) – 1.0 (critical threat)</td></tr>
          <tr><td><code>risk_level</code></td><td>none · low · medium · high · critical</td></tr>
          <tr><td><code>sources</code></td><td>Threat types; cybershield-honeypot if applicable</td></tr>
          <tr><td><code>seen_in_honeypot</code></td><td>1 if detected by honeypot, 0 otherwise</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <footer>Powered by Cyber Shield AI · <a href="https://github.com/cyberpolak99/cyber-shield-ai" style="color:#00ff88">GitHub</a> · <a href="{THREAT_API_URL}/api/health" style="color:#00ff88">API Health</a></footer>
</div>
</body></html>"""


if __name__ == "__main__":
    print("Starting CyberShield Dashboard on http://0.0.0.0:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
