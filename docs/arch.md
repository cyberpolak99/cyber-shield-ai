# Cyber Shield AI Architecture

## Components

1. **Honeypot Sensor**:
   - `honeypot.py`: TCP/IP service simulation.
   - `cyber_shield_live.py`: Real-time behavioral monitor using Scapy.
2. **AI Brain**:
   - `ai_engine.py`: Machine Learning classification (Isolation Forest).
3. **Defense Layer**:
   - `cyber_shield_blocker.py`: Automated integration with netsh (Windows) and iptables (Linux).
4. **Intelligence Layer**:
   - `threat_api.py`: External interface for reputation lookups.
   - `threat_feed_scraper.py`: Automated ingestion of global threat data.
5. **Storage**:
   - `db_manager.py`: Persistent SQLite storage for anomalies and blocks.
6. **Visualization**:
   - `dashboard.py`: FastAPI-based telemetry portal.
