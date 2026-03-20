from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from db_manager import DBManager
import uvicorn
import secrets
import html

app = FastAPI(title="PolskiCyberShield Dashboard")
db = DBManager()
security = HTTPBasic()

# Simple Auth
ADMIN_USER = "admin"
ADMIN_PASS = "PolskiCyber2026"

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    is_correct_username = secrets.compare_digest(credentials.username, ADMIN_USER)
    is_correct_password = secrets.compare_digest(credentials.password, ADMIN_PASS)
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@app.get("/", response_class=HTMLResponse)
async def get_dashboard(username: str = Depends(authenticate)):
    stats = db.get_stats()
    return f"""
    <html>
        <head>
            <title>PolskiCyberShield Dashboard</title>
            <style>
                body {{ font-family: sans-serif; background: #1a1a1a; color: white; text-align: center; padding: 20px; }}
                .card {{ background: #2a2a2a; padding: 20px; margin: 20px; border-radius: 10px; border: 1px solid #444; min-width: 200px; }}
                .stat {{ font-size: 3em; color: #00ff00; font-weight: bold; }}
                .header {{ color: #ff0000; font-size: 2.5em; margin-bottom: 30px; border-bottom: 2px solid #ff0000; display: inline-block; padding-bottom: 10px; }}
                .nav {{ margin: 20px; }}
                .nav a {{ color: #00ff00; text-decoration: none; margin: 0 15px; padding: 5px 10px; border: 1px solid #00ff00; border-radius: 5px; }}
                .nav a:hover {{ background: #00ff00; color: #000; }}
            </style>
        </head>
        <body>
            <div class="header">🛡️ PolskiCyberShield LIVE DASHBOARD</div>
            <div class="nav">
                <a href="/">Dashboard</a>
                <a href="/anomalies">Anomalie</a>
            </div>
            <div style="display: flex; justify-content: center; flex-wrap: wrap;">
                <div class="card">
                    <h3>Wykryte Anomalie</h3>
                    <div class="stat">{stats['total_anomalies']}</div>
                </div>
                <div class="card">
                    <h3>Aktywne Blokady IP</h3>
                    <div class="stat" style="color: #ff4444;">{stats['active_blocks']}</div>
                </div>
            </div>
            <p style="color: #888; margin-top: 40px;">Zalogowany jako: {username} | v6.0 PROF</p>
        </body>
    </html>
    """

@app.get("/anomalies", response_class=HTMLResponse)
async def get_anomalies(username: str = Depends(authenticate)):
    # Limit to 50 for better performance
    anomalies = db.get_anomalies_with_geo(limit=50, use_geo=False)

    rows = ""
    for anomaly in anomalies:
        timestamp = html.escape(str(anomaly.get('timestamp', 'N/A')))
        src_ip = html.escape(str(anomaly.get('src_ip', 'N/A')))
        dst_ip = html.escape(str(anomaly.get('dst_ip', 'N/A')))
        description = html.escape(str(anomaly.get('description', 'N/A')))
        score = anomaly.get('score', 0)
        label_html = '<span title="Confirmed Attack" style="color: #ff4444; font-size: 1.2em;">⚠️</span>' if anomaly.get('label') == 1 else ''

        rows += f"""
            <tr style="border-bottom: 1px solid #333;">
                <td style="padding: 12px;">{timestamp}</td>
                <td style="padding: 12px; color: #ff6600; font-weight: bold;">{src_ip}</td>
                <td style="padding: 12px;">{dst_ip}</td>
                <td style="padding: 12px; text-align: left;">{description}</td>
                <td style="padding: 12px; color: {'#ff4444' if score < -0.4 else '#00ff00'};">{score:.4f}</td>
                <td style="padding: 12px; text-align: center;">{label_html}</td>
            </tr>
        """

    return f"""
    <html>
        <head>
            <title>PolskiCyberShield - Anomalie</title>
            <style>
                body {{ font-family: sans-serif; background: #1a1a1a; color: white; padding: 20px; }}
                .header {{ color: #ff0000; font-size: 2em; margin-bottom: 20px; }}
                .nav {{ margin-bottom: 30px; }}
                .nav a {{ color: #00ff00; text-decoration: none; margin-right: 20px; padding: 5px 10px; border: 1px solid #00ff00; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; background: #2a2a2a; border-radius: 10px; overflow: hidden; }}
                th {{ padding: 15px; text-align: left; background: #333; color: #00ff00; }}
                tr:hover {{ background: #333; }}
            </style>
        </head>
        <body>
            <div class="header">🚨 Wykryte Anomalie (Ostatnie 50)</div>
            <div class="nav">
                <a href="/">← Dashboard</a>
                <a href="/enrich">Bulk Enrichment</a>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Source IP</th>
                        <th>Destination</th>
                        <th>Reason / Description</th>
                        <th>AI Score</th>
                        <th>Label</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
            <footer style="margin-top: 30px; color: #666; font-size: 0.8em;">
                Wygenerowano: {html.escape(str(db.get_stats()))}
            </footer>
        </body>
    </html>
    """

@app.get("/enrich", response_class=HTMLResponse)
async def get_enrich(username: str = Depends(authenticate)):
    return f"""
    <html>
        <head>
            <title>PolskiCyberShield - Wzbogacanie CSV</title>
            <style>
                body {{ font-family: sans-serif; background: #1a1a1a; color: white; text-align: center; padding: 20px; }}
                .header {{ color: #ff0000; font-size: 2.5em; margin-bottom: 30px; border-bottom: 2px solid #ff0000; display: inline-block; padding-bottom: 10px; }}
                .nav {{ margin: 20px; }}
                .nav a {{ color: #00ff00; text-decoration: none; margin: 0 15px; padding: 5px 10px; border: 1px solid #00ff00; border-radius: 5px; }}
                .nav a:hover {{ background: #00ff00; color: #000; }}
                .card {{ background: #2a2a2a; padding: 30px; margin: 30px auto; border-radius: 10px; border: 1px solid #444; max-width: 600px; }}
                button {{ background-color: #00ff00; color: #000; padding: 10px 20px; margin-top: 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 1.1em; font-weight: bold; }}
                button:hover {{ background-color: #00cc00; }}
                input[type=file] {{ display: block; margin: 20px auto; color: #fff; }}
            </style>
        </head>
        <body>
            <div class="header">🛡️ Bulk IP Enrichment</div>
            <div class="nav">
                <a href="/">← Dashboard</a>
                <a href="/anomalies">Anomalie</a>
            </div>
            
            <div class="card">
                <h3>🔍 Wzbogać listę adresów IP (CSV)</h3>
                <p>Upload a CSV file containing an <code>ip</code> column. We will enrich it with threat intelligence scores and sources.</p>
                <form action="http://localhost:10000/api/bulk-ip-csv" method="POST" enctype="multipart/form-data">
                    <input type="file" name="file" accept=".csv" required />
                    <!-- If RapidAPI is used locally, you might need to supply the header via JS instead of standard form submit. Assuming local DEV without proxy for now. -->
                    <button type="submit">Enrich CSV</button>
                </form>
            </div>
            
        </body>
    </html>
    """

if __name__ == "__main__":
    print("Uruchamianie Zabezpieczonego Dashboardu na http://0.0.0.0:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
