from flask import Flask, jsonify, request, abort, Response
from flask_cors import CORS
from datetime import datetime
import os
import logging
import sqlite3
from db_manager import DBManager
from security import require_api_key, rate_limited
from bulk_processor import BulkIPProcessor

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

# RapidAPI Security Secret
RAPIDAPI_SECRET = os.environ.get("RAPIDAPI_PROXY_SECRET")

@app.before_request
def check_rapidapi_header():
    """Strictly enforce RapidAPI secret if configured"""
    if RAPIDAPI_SECRET:
        proxy_secret = request.headers.get("X-RapidAPI-Proxy-Secret")
        if proxy_secret != RAPIDAPI_SECRET:
            logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
            return jsonify({"error": "Unauthorized. RapidAPI Proxy only."}), 401

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
@require_api_key
@rate_limited
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
@require_api_key
@rate_limited
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

def lookup_ip_internal(ip_addr: str) -> dict:
    """Internal business logic for IP lookup without HTTP overhead"""
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
        
        if not matches:
            return {'ti_score': 0, 'risk_level': 'none', 'sources': '', 'seen_in_honeypot': 0}
        
        # Aggregate results
        severity_map = {"CRITICAL": 100, "HIGH": 80, "MEDIUM": 50, "LOW": 20}
        reverse_map = {100: "CRITICAL", 80: "HIGH", 50: "MEDIUM", 20: "LOW"}
        
        max_val = 0
        scores = []
        sources = set()
        honeypot = 0
        
        for m in matches:
            val = severity_map.get(m['severity'], 20)
            if val > max_val: max_val = val
            scores.append(m['score'])
            if m['type']: sources.add(m['type'])
            if m['type'] == 'HONEYPOT_HIT' or 'honeypot' in (m['description'] or '').lower():
                honeypot = 1
                
        return {
            'ti_score': max(scores) if scores else 0,
            'risk_level': reverse_map.get(max_val, 'LOW').lower(),
            'sources': ";".join(sources),
            'seen_in_honeypot': honeypot
        }
    except Exception as e:
        logger.error(f"Internal IP lookup failed for {ip_addr}: {e}")
        return {'ti_score': 0, 'risk_level': 'error', 'sources': '', 'seen_in_honeypot': 0}

@app.route('/api/check/<ip_addr>', methods=['GET'])
@require_api_key
@rate_limited
def check_ip(ip_addr):
    res = lookup_ip_internal(ip_addr)
    return jsonify({
        'ip': ip_addr,
        'is_malicious': res['risk_level'] not in ['none', 'invalid'],
        'ti_score': res['ti_score'],
        'risk_level': res['risk_level'],
        'sources': res['sources'],
        'seen_in_honeypot': res['seen_in_honeypot']
    })

@app.route('/api/bulk-ip-csv', methods=['POST'])
@require_api_key
@rate_limited
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

