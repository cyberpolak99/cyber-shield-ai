"""
seed_anomalies.py – Seed the SQLite DB with realistic honeypot attack data.
Run: py seed_anomalies.py
"""
import sqlite3
import os
import random
from datetime import datetime, timedelta

DB_PATH = os.environ.get("DATABASE_URL",
    r"c:\Users\Tata\Desktop\czyszczenie danych\threat-intelligence-api\data\cyber_shield.db")

ATTACKER_IPS = [
    # Real known malicious IPs (from public blocklists)
    "45.133.1.20",
    "185.220.101.5",
    "89.248.165.59",
    "193.32.162.87",
    "171.25.193.78",
    "162.247.74.27",
    "185.243.218.50",
    "45.155.205.233",
    "103.251.167.20",
    "37.120.247.199",
    "94.102.49.190",
    "212.70.149.150",
    "45.95.169.11",
    "80.82.77.139",
    "198.98.51.189",
]

ATTACK_TYPES = [
    ("SSH_BRUTE_FORCE", "SSH brute force login attempt", "HIGH", 0.85),
    ("PORT_SCAN",       "Aggressive port scan detected", "MEDIUM", 0.55),
    ("HONEYPOT_HIT",    "Honeypot interaction triggered", "HIGH", 0.90),
    ("MALWARE_C2",      "Known malware C2 callback detected", "CRITICAL", 1.0),
    ("WEB_EXPLOIT",     "Web application exploit attempt (SQLi/XSS)", "HIGH", 0.80),
    ("CREDENTIAL_STUFF","Credential stuffing on login page", "HIGH", 0.75),
    ("DNS_TUNNEL",      "DNS tunneling activity detected", "MEDIUM", 0.60),
    ("SMB_SCAN",        "SMB/EternalBlue scan attempt", "CRITICAL", 0.95),
    ("TELNET_BRUTE",    "Telnet brute force (IoT-style)", "MEDIUM", 0.65),
    ("RDP_BRUTE_FORCE", "RDP brute force login attempt", "HIGH", 0.82),
]

DST_IPS = ["10.0.0.1", "10.0.0.5", "10.0.0.10", "192.168.1.100", "172.16.0.50"]
PROTOCOLS = ["TCP", "UDP", "TCP", "TCP", "TCP"]  # mostly TCP


def seed():
    print(f"Seeding database: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check count before
    try:
        before = cursor.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
    except Exception:
        before = 0
    print(f"  Current anomalies: {before}")

    if before > 0:
        print("  DB already has data — skipping seed to avoid duplicates.")
        print("  (Delete rows or pass --force to re-seed)")
        if "--force" not in __import__("sys").argv:
            conn.close()
            return

    now = datetime.now()
    records = []
    for ip in ATTACKER_IPS:
        # Each IP gets 2–12 random events over last 7 days
        num_events = random.randint(2, 12)
        for _ in range(num_events):
            attack = random.choice(ATTACK_TYPES)
            ts = now - timedelta(
                days=random.uniform(0, 7),
                hours=random.uniform(0, 24),
                minutes=random.uniform(0, 60)
            )
            score_jitter = random.uniform(-0.05, 0.05)
            score = max(0.0, min(1.0, attack[3] + score_jitter))
            bytes_tx = random.randint(100, 500000)
            records.append((
                ts.strftime("%Y-%m-%d %H:%M:%S"),
                ip,
                random.choice(DST_IPS),
                random.choice(PROTOCOLS),
                attack[0],           # type
                attack[2],           # severity
                round(score, 4),     # score
                bytes_tx,
                attack[1],           # description
                1,                   # label (anomaly=1)
            ))

    cursor.executemany("""
        INSERT INTO anomalies
            (timestamp, src_ip, dst_ip, protocol, type, severity, score, bytes_transferred, description, label)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, records)

    conn.commit()
    after = cursor.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
    distinct = cursor.execute("SELECT COUNT(DISTINCT src_ip) FROM anomalies").fetchone()[0]
    conn.close()

    print(f"  ✅ Inserted {len(records)} events for {len(ATTACKER_IPS)} attacker IPs")
    print(f"  Total anomalies now: {after}")
    print(f"  Distinct attacker IPs: {distinct}")
    print("  Done!")


if __name__ == "__main__":
    seed()
