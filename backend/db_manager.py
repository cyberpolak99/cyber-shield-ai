import sqlite3
from datetime import datetime
import os
import re

class DBManager:
    def __init__(self, db_path="data/cyber_shield.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()
        self._enable_security()

    def _get_conn(self):
        """Helper for getting connection - backward compatibility"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Tabela anomalii
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    type TEXT,
                    severity TEXT,
                    score REAL,
                    bytes_transferred INTEGER,
                    description TEXT,
                    label INTEGER DEFAULT 0 -- 0=unknown/normal, 1=confirmed_attack
                )
            ''')
            # Tabela blokad
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE,
                    reason TEXT,
                    blocked_at DATETIME,
                    expires_at DATETIME,
                    status TEXT DEFAULT 'active'
                )
            ''')
            # Dodaj indeksy dla performance i security (UNIQUE constraint)
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalies_src ON anomalies(src_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks(ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocks_status ON blocks(status)')
            conn.commit()

    def _enable_security(self):
        """Enable SQLite security features"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Enable WAL mode for better concurrency and integrity
            cursor.execute('PRAGMA journal_mode = WAL')
            # Enable foreign keys
            cursor.execute('PRAGMA foreign_keys = ON')
            # Set synchronous to NORMAL for balance between safety and performance
            cursor.execute('PRAGMA synchronous = NORMAL')
            conn.commit()

    def _validate_ip(self, ip):
        """Validate IPv4 address"""
        if not ip or not isinstance(ip, str):
            return None
        # Basic IPv4 validation
        pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(pattern, ip)
        if match:
            # Check if each octet is valid
            for octet in match.groups():
                if not 0 <= int(octet) <= 255:
                    return None
            return ip
        return None

    def _sanitize_string(self, text, max_length=1000):
        """Sanitize string input"""
        if not text:
            return ""
        if not isinstance(text, str):
            text = str(text)
        # Trim to max length
        text = text[:max_length]
        # Remove null bytes and control characters
        text = text.replace('\x00', '')
        text = ''.join(char for char in text if char.isprintable() or char in ['\n', '\t'])
        return text

    def _validate_score(self, score):
        """Validate anomaly score"""
        try:
            score = float(score)
            if -1.0 <= score <= 1.0:
                return score
            return None
        except (ValueError, TypeError):
            return None

    def _validate_bytes(self, bytes_val):
        """Validate bytes value"""
        try:
            value = int(bytes_val)
            if value >= 0:
                return value
            return None
        except (ValueError, TypeError):
            return None

    def _validate_label(self, label):
        """Validate label"""
        try:
            value = int(label)
            if value in [-1, 0, 1]:
                return value
            return 0  # Default to unknown
        except (ValueError, TypeError):
            return 0

    def log_anomaly(self, src_ip, dst_ip, protocol, threat_type, severity, score, bytes_val, desc, label=0):
        """Log anomaly with input validation and SQL injection protection"""
        # Validate inputs
        src_ip = self._validate_ip(src_ip)
        if not src_ip:
            return False  # Invalid IP

        dst_ip = self._validate_ip(dst_ip)
        if not dst_ip:
            dst_ip = ""  # Optional field, allow empty

        # Sanitize threat type and severity
        threat_type = self._sanitize_string(threat_type, max_length=100)
        severity = self._sanitize_string(severity, max_length=20)

        # Convert protocol to string safely
        try:
            protocol = str(int(protocol))
        except (ValueError, TypeError):
            protocol = "unknown"

        # Validate score
        score = self._validate_score(score)
        if score is None:
            score = 0.0

        # Validate bytes
        bytes_val = self._validate_bytes(bytes_val)
        if bytes_val is None:
            bytes_val = 0

        # Sanitize description
        desc = self._sanitize_string(desc, max_length=1000)

        # Validate label
        label = self._validate_label(label)

        # Insert with parameterized query (SQL injection protected)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR IGNORE INTO anomalies
                    (timestamp, src_ip, dst_ip, protocol, type, severity, score, bytes_transferred, description, label)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (datetime.now(), src_ip, dst_ip, protocol, threat_type, severity, score, bytes_val, desc, label))
                conn.commit()
                return True
        except Exception as e:
            # Log error but don't crash
            print(f"[DB ERROR] Failed to log anomaly: {e}")
            return False

    def add_block(self, ip, reason, duration_sec):
        """Add IP block with input validation"""
        # Validate IP
        ip = self._validate_ip(ip)
        if not ip:
            return False

        # Sanitize reason
        reason = self._sanitize_string(reason, max_length=500)

        # Validate duration
        try:
            duration_sec = int(duration_sec)
            if duration_sec < 0:
                duration_sec = 86400  # Default to 24 hours
        except (ValueError, TypeError):
            duration_sec = 86400

        # Insert with parameterized query
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                blocked_at = datetime.now()
                cursor.execute('''
                    INSERT OR REPLACE INTO blocks (ip, reason, blocked_at, status)
                    VALUES (?, ?, ?, 'active')
                ''', (ip, reason, blocked_at))
                conn.commit()
                return True
        except Exception as e:
            print(f"[DB ERROR] Failed to add block: {e}")
            return False

    def get_stats(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM anomalies")
            total_anomalies = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM blocks WHERE status='active'")
            active_blocks = cursor.fetchone()[0]
            return {"total_anomalies": total_anomalies, "active_blocks": active_blocks}

    def get_anomalies(self, limit=50):
        """Get anomalies with correct schema names for API compatibility"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, src_ip, dst_ip, protocol, type, severity, score, bytes_transferred, description, label
                FROM anomalies
                ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_anomalies_with_geo(self, limit=20, use_geo=False):
        """Get anomalies with optional geolocation information

        Args:
            limit (int): Maximum number of anomalies to return
            use_geo (bool): If True, attempt to add geolocation data

        Returns:
            list: List of anomaly dictionaries with optional geo data
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT timestamp, src_ip, dst_ip, description as explanation, score as iso_score, label
                FROM anomalies
                ORDER BY timestamp DESC LIMIT ?
            """, (limit,))

            anomalies = []
            geo_db_enabled = False
            geo_reader = None

            # Try to enable geolocation
            if use_geo:
                try:
                    import geoip2.database

                    db_path = os.path.join(os.path.dirname(self.db_path), "GeoLite2-City.mmdb")
                    if os.path.exists(db_path):
                        geo_db_enabled = True
                        geo_reader = geoip2.database.Reader(db_path)
                except ImportError:
                    # geoip2 not installed
                    pass
                except Exception:
                    # Geolocation error
                    pass

            for row in cursor.fetchall():
                anomaly = dict(row)

                # Add geolocation if enabled
                if geo_db_enabled and geo_reader and anomaly['src_ip']:
                    try:
                        response = geo_reader.city(anomaly['src_ip'])
                        anomaly['country_code'] = response.country.iso_code
                        anomaly['country_name'] = response.country.name
                        anomaly['city'] = response.city.name
                    except Exception:
                        # Geolocation failed for this IP
                        anomaly['country_code'] = None
                        anomaly['country_name'] = 'Unknown'
                        anomaly['city'] = 'Unknown'
                else:
                    # Geolocation not enabled or failed
                    anomaly['country_code'] = None
                    anomaly['country_name'] = 'Unknown'
                    anomaly['city'] = 'Unknown'

                anomalies.append(anomaly)

            # Close geo reader if opened
            if geo_reader:
                try:
                    geo_reader.close()
                except Exception:
                    pass

            return anomalies
