import sqlite3
from datetime import datetime, timedelta
import os
import re

class DBManager:
    """
    Unified Database Manager for CyberShield AI
    Supports anomalies logging, IP blocking, and threat intelligence.
    """
    def __init__(self, db_path='data/cyber_shield.db'):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            # Enable WAL mode for better concurrency
            conn.execute('PRAGMA journal_mode=WAL')
            cursor = conn.cursor()
            
            # Anomalies table (combined from all sensors and APIs)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol INTEGER,
                    score REAL,
                    bytes_transferred INTEGER,
                    description TEXT,
                    type TEXT DEFAULT 'GENERAL',
                    severity INTEGER DEFAULT 5,
                    label INTEGER DEFAULT 0
                )
            ''')
            
            # Monitoring blocks table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocks (
                    ip TEXT PRIMARY KEY,
                    reason TEXT,
                    blocked_at DATETIME,
                    expires_at DATETIME,
                    status TEXT DEFAULT 'active'
                )
            ''')
            
            # Threat Intel table (reputation cache)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intel (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE,
                    score INTEGER,
                    type TEXT,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON anomalies(src_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocks_status ON blocks(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_intel_ip ON threat_intel(ip)')
            conn.commit()

    def log_anomaly(self, src_ip, dst_ip, protocol, score, bytes_val, desc, type_val='GENERAL', severity=5, label=0):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO anomalies (src_ip, dst_ip, protocol, score, bytes_transferred, description, type, severity, label)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (src_ip, dst_ip, protocol, score, bytes_val, desc, type_val, severity, label))
        except Exception as e:
            print(f"[DB ERROR] Failed to log anomaly: {e}")

    def add_block(self, ip, reason, duration_sec=3600):
        try:
            with sqlite3.connect(self.db_path) as conn:
                blocked_at = datetime.now()
                expires_at = blocked_at + timedelta(seconds=duration_sec)
                conn.execute('''
                    INSERT OR REPLACE INTO blocks (ip, reason, blocked_at, expires_at, status)
                    VALUES (?, ?, ?, ?, 'active')
                ''', (ip, reason, blocked_at, expires_at))
                return True
        except Exception as e:
            print(f"[DB ERROR] Failed to add block: {e}")
            return False

    def get_active_blocks(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM blocks WHERE status='active'")
            return [dict(row) for row in cursor.fetchall()]

    def cleanup_expired_blocks(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                now = datetime.now()
                cursor = conn.cursor()
                cursor.execute("UPDATE blocks SET status='expired' WHERE status='active' AND expires_at < ?", (now,))
                return cursor.rowcount
        except Exception as e:
            print(f"[DB ERROR] Cleanup failed: {e}")
            return 0

    def get_stats(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM anomalies")
            total_anomalies = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM blocks WHERE status='active'")
            active_blocks = cursor.fetchone()[0]
            return {"total_anomalies": total_anomalies, "active_blocks": active_blocks}

    def get_anomalies(self, limit=50):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM anomalies ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]
