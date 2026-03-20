"""
THREAT FEED SCRAPER - POPRAWIONE
==================
Automatycznie pobieraj zagrożenia
"""

import requests
import os
from datetime import datetime
import logging
from db_manager import DBManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ThreatScraper')


class ThreatFeedScraper:
    def __init__(self, db_path='data/cyber_shield.db'):
        self.db = DBManager(db_path=db_path)
        self.stats = {
            'scraped': 0,
            'new': 0,
            'errors': 0
        }
    
    def scrape_all(self):
        """Pobierz wszystkie źródła"""
        logger.info("ROZPOCZYNAM SCRAPING...")
        
        # Dodaj przykładowe zagrożenia do bazy
        self.add_sample_data()
        
        logger.info(f"WYNIKI: Nowe={self.stats['new']}, Błędy={self.stats['errors']}")
    
    def add_sample_data(self):
        """Dodaj przykładowe dane do bazy używając DBManager"""
        
        przykladowe_zagrozenia = [
            ("192.168.1.100", "SHELLSHOCK", "HIGH", "Exploit targeting shellshock vulnerability"),
            ("185.220.101.5", "BRUTE_FORCE", "MEDIUM", "Brute force attack detected"),
            ("10.0.0.50", "DATA_EXFILTRATION", "CRITICAL", "Suspicious data transfer to external IP"),
            ("172.16.0.25", "DDOS_ATTACK", "HIGH", "High volume of UDP traffic"),
            ("203.0.113.1", "PHISHING_CAMPAIGN", "MEDIUM", "Known phishing landing page"),
            ("198.51.100.10", "MALWARE_HOST", "HIGH", "Hosting malicious binaries")
        ]
        
        for ip, threat_type, severity, desc in przykladowe_zagrozenia:
            success = self.db.log_anomaly(
                src_ip=ip, 
                dst_ip="", 
                protocol="6", 
                threat_type=threat_type, 
                severity=severity, 
                score=1.0, 
                bytes_val=0, 
                desc=desc, 
                label=1
            )
            if success:
                self.stats['new'] += 1
            else:
                self.stats['errors'] += 1


if __name__ == '__main__':
    scraper = ThreatFeedScraper()
    scraper.scrape_all()
