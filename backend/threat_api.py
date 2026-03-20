from flask import Flask, jsonify, request, abort, Response
from flask_cors import CORS
from datetime import datetime
import os
import logging
import sqlite3
from db_manager import DBManager
from security import protected
from bulk_processor import BulkIPProcessor
from honeypot_feed import is_ip_in_honeypot, get_honeypot_details, get_all_honeypot_ips

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ThreatAPI')

app = Flask(__name__)
CORS(app)

# Initialize DB Manager
db = DBManager(db_path=os.environ.get("DATABASE_URL", "data/cyber_shield.db"))

# Migracja przykładowych danych jeśli baza jest pusta
def migrate_sample_data():
    stats = db.get_stats()
    if stats['total_anomalies'] == 0:
        logger.info("Baza danych jest pusta. Migracja przykładowych danych...")
        sample_data = [
            {"type": "Phishing", "severity": "HIGH", "ip": "192.168.1.100", "desc": "Wykryto kampanię phishingową"},
            {"type": "Malware", "severity": "CRITICAL", "ip": "45.133.1.20", "desc": "Aktywność malware Cobalt Strike"},
            {"type": "Brute Force", "severity": "MEDIUM", "ip": "185.220.101.5", "desc": "Próba łamania haseł SSH"},
            {"type": "DDoS", "severity": "HIGH", "ip": "103.212.223.4", "desc": "Atak typu UDP Flood"},
            {"type": "SQL Injection", "severity": "CRITICAL", "ip": "91.240.118.12", "desc": "Próba wstrzyknięcia kodu SQL"},
        ]
        for item in sample_data:
            db.log_anomaly(item['ip'], "", "6", item['type'], item['severity'], 1.0, 0, item['desc'], 1)

migrate_sample_data()

# Auth is handled entirely by @protected in security.py.
# RAPIDAPI_PROXY_SECRET and THREAT_API_KEYS are read from env there.

@app.errorhandler(400)
def bad_request(e):
    return jsonify(error=str(e)), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify(error="Resource not found"), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal Server Error: {e}")
    return jsonify(error="Internal server error"), 500

@app.route('/')
def home():
    return "<h1>Threat Intelligence API</h1><p>Use /api/threats to fetch data.</p>"

@app.route('/api/threats', methods=['GET'])
@protected
def get_threats():
    try:
        limit = request.args.get('limit', 50, type=int)
        limit = max(1, min(limit, 100))
        severity = request.args.get('severity')
        
        anomalies = db.get_anomalies(limit=limit)
        
        # Filter by severity if requested
        if severity:
            anomalies = [a for a in anomalies if a['severity'] == severity]
        
        # Map DB schema to API schema for backward compatibility
        formatted_data = []
        for a in anomalies:
            formatted_data.append({
                "id": a['id'],
                "type": a['type'] or "Unknown",
                "severity": a['severity'] or "MEDIUM",
                "ip_address": a['src_ip'],
                "detected_at": a['timestamp'],
                "description": a['description']
            })

        return jsonify({
            'status': 'success',
            'count': len(formatted_data),
            'data': formatted_data
        })
    except Exception as e:
        logger.error(f"Error fetching threats: {e}")
        abort(500)

@app.route('/api/threats/stats', methods=['GET'])
@protected
def get_stats():
    try:
        db_stats = db.get_stats()
        anomalies = db.get_anomalies(limit=1000)
        
        severity_dist = {
            'CRITICAL': len([a for a in anomalies if a['severity'] == 'CRITICAL']),
            'HIGH': len([a for a in anomalies if a['severity'] == 'HIGH']),
            'MEDIUM': len([a for a in anomalies if a['severity'] == 'MEDIUM']),
            'LOW': len([a for a in anomalies if a['severity'] == 'LOW'])
        }
        
        return jsonify({
            'total_incidents': db_stats['total_anomalies'],
            'active_blocks': db_stats['active_blocks'],
            'severity_distribution': severity_dist
        })
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        abort(500)

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'version': '1.2-hardened',
        'timestamp': datetime.now().isoformat()
    })

# Max file size: 5MB
MAX_CONTENT_LENGTH = 5 * 1024 * 1024
MAX_ROWS = 2000

def get_db_connection():
    """Returns a standalone SQLite connection"""
    conn = sqlite3.connect(db.db_path)
    conn.row_factory = sqlite3.Row
    return conn

# ─── Honeypot scoring constants ─────────────────────────────────────────────
# When IP is in honeypot AND has external feed data → boost risk level.
HONEYPOT_SCORE_BOOST = 0.15       # added to ti_score if also in feeds
HONEYPOT_MIN_RISK_LEVEL = "high"  # minimum risk_level when seen in honeypot

_RISK_ORDER = ["none", "low", "medium", "high", "critical"]

def _elevate_risk(current: str, minimum: str) -> str:
    """Returns the higher of two risk levels."""
    try:
        return current if _RISK_ORDER.index(current) >= _RISK_ORDER.index(minimum) else minimum
    except ValueError:
        return current


def lookup_ip_internal(ip_addr: str) -> dict:
    """Internal business logic for IP lookup without HTTP overhead."""
    try:
        import ipaddress
        ipaddress.ip_address(ip_addr)
    except ValueError:
        return {'ti_score': 0, 'risk_level': 'invalid', 'sources': '', 'seen_in_honeypot': 0}

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM anomalies WHERE src_ip = ?", (ip_addr,))
            matches = [dict(row) for row in cursor.fetchall()]

        severity_map = {"CRITICAL": 100, "HIGH": 80, "MEDIUM": 50, "LOW": 20}
        reverse_map = {100: "critical", 80: "high", 50: "medium", 20: "low"}

        max_val = 0
        scores = []
        sources = set()

        for m in matches:
            val = severity_map.get(str(m.get('severity', '')).upper(), 20)
            if val > max_val:
                max_val = val
            scores.append(float(m.get('score') or 0))
            if m.get('type'):
                sources.add(str(m['type']))

        base_score    = max(scores) if scores else 0.0
        base_risk     = reverse_map.get(max_val, 'none') if matches else 'none'

        # ── Honeypot enrichment ──────────────────────────────────────────────
        in_honeypot = is_ip_in_honeypot(ip_addr)
        if in_honeypot:
            sources.add('cybershield-honeypot')
            # Boost score if ALSO in external feeds, cap at 1.0
            if matches:
                base_score = min(1.0, base_score + HONEYPOT_SCORE_BOOST)
            # Enforce minimum risk level
            base_risk = _elevate_risk(base_risk, HONEYPOT_MIN_RISK_LEVEL)

        return {
            'ti_score':         int(base_score * 10000) / 10000,
            'risk_level':       base_risk,
            'sources':          ";".join(sorted(sources)),
            'seen_in_honeypot': 1 if in_honeypot else 0,
        }
    except Exception as e:
        logger.error(f"Internal IP lookup failed for {ip_addr}: {e}")
        return {'ti_score': 0, 'risk_level': 'error', 'sources': '', 'seen_in_honeypot': 0}

@app.route('/api/check/<ip_addr>', methods=['GET'])
@protected
def check_ip(ip_addr):
    res = lookup_ip_internal(ip_addr)
    details = get_honeypot_details(ip_addr) if res['seen_in_honeypot'] else {}
    return jsonify({
        'ip':               ip_addr,
        'is_malicious':     res['risk_level'] not in ['none', 'invalid'],
        'ti_score':         res['ti_score'],
        'risk_level':       res['risk_level'],
        'sources':          res['sources'],
        'seen_in_honeypot': res['seen_in_honeypot'],
        'honeypot_details': details,
    })


@app.route('/api/honeypot-feed', methods=['GET'])
@protected
def honeypot_feed():
    """Returns list of all IPs observed by the Cyber Shield honeypot."""
    limit = request.args.get('limit', 200, type=int)
    limit = max(1, min(limit, 1000))
    ips = get_all_honeypot_ips(limit=limit)
    return jsonify({
        'status': 'success',
        'count':  len(ips),
        'data':   ips,
    })

@app.route('/api/bulk-ip-csv', methods=['POST'])
@protected
def bulk_enrich_csv():
    """Upload CSV, enrich with threat intel, and return as download"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    if not file or not file.filename.endswith('.csv'):
        return jsonify({'error': 'Invalid file format. Upload .csv'}), 400

    # Size validation
    file_bytes = file.read()
    if len(file_bytes) > MAX_CONTENT_LENGTH:
        return jsonify({'error': f'File too large. Max {MAX_CONTENT_LENGTH/1024/1024}MB'}), 413
    
    try:
        processor = BulkIPProcessor(lookup_func=lookup_ip_internal, max_rows=MAX_ROWS)
        enriched_csv = processor.process_csv(file_bytes)
        
        # Return as downloadable file
        return Response(
            enriched_csv,
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=enriched_ips.csv"}
        )
    except ValueError as val_err:
        return jsonify({'error': str(val_err)}), 400
    except Exception as err:
        logger.error(f"Bulk CSV error: {err}")
        abort(500)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    # Prod warning check
    if os.environ.get("FLASK_ENV") == "production":
        logger.info("Running in PRODUCTION mode")
    else:
        logger.info("Running in DEVELOPMENT mode")
        
    app.run(host='0.0.0.0', port=port)

