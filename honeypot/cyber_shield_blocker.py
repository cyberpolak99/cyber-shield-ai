import subprocess
import platform
import json
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict

class CyberShieldBlocker:
    """
    PolskiCyberShield - Automatyczne blokowanie ataków cybernetycznych
    Dla bezpieczeństwa Polski 🇵🇱
    """
    
    def __init__(self, config_file='config.json', db_manager=None):
        self.os_type = platform.system()
        self.blocked_ips = {}
        self.blocked_ports = {}
        self.block_duration = 3600  # 1h default
        self.config = self.load_config(config_file)
        self.setup_logging()
        self.db = db_manager
        
        # Inicjalizacja: załaduj aktywne blokady z bazy
        if self.db:
            self._load_active_blocks_from_db()
    
    def _load_active_blocks_from_db(self):
        """Synchronizuje stan pamięci i firewall'a z bazą danych"""
        self.logger.info("Synchronizacja blokad z bazą danych...")
        try:
            active_blocks = self.db.get_active_blocks()
            for block in active_blocks:
                ip = block['ip']
                self.blocked_ips[ip] = {
                    'timestamp': block['blocked_at'],
                    'reason': block['reason'],
                    'duration': self.block_duration
                }
        except Exception as e:
            self.logger.error(f"Błąd ładowania blokad z DB: {e}")
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - [%(levelname)s] - %(message)s',
            handlers=[
                logging.FileHandler('cyber_shield.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_config(self, config_file):
        """Załaduj konfigurację"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except:
            return {
                'auto_block': True,
                'block_duration': 3600,
                'whitelist_ips': ['127.0.0.1', 'localhost', '::1'],
                'target_ports': [22, 80, 443, 3306, 5432]
            }

    def _apply_firewall_block(self, ip: str) -> bool:
        """Niskopoziomowa aplikacja reguły firewall"""
        try:
            if self.os_type == "Linux":
                # Sprawdź czy już istnieje, żeby nie dublować
                check_cmd = f"sudo iptables -C INPUT -s {ip} -j DROP"
                if subprocess.run(check_cmd.split(), capture_output=True).returncode != 0:
                    cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
                    subprocess.run(cmd.split(), check=True)
            
            elif self.os_type == "Windows":
                cmd = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
                subprocess.run(cmd, shell=False, check=True)
            return True
        except Exception as e:
            self.logger.debug(f"Firewall block skip/error for {ip}: {e}")
            return False

    def _remove_firewall_block(self, ip: str) -> bool:
        """Niskopoziomowe usunięcie reguły firewall"""
        try:
            if self.os_type == "Linux":
                cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
                subprocess.run(cmd.split(), check=True)
            elif self.os_type == "Windows":
                cmd = f'netsh advfirewall firewall delete rule name="Block {ip}"'
                subprocess.run(cmd, shell=False, check=True)
            return True
        except Exception as e:
            self.logger.debug(f"Firewall unblock error for {ip}: {e}")
            return False
    
    def block_ip(self, ip: str, reason: str = "Attack detected", duration_sec: int = None) -> bool:
        """Blokuje IP na firewall'u i zapisuje w DB"""
        
        # Sprawdź whitelist
        if ip in self.config.get('whitelist_ips', []):
            return False
        
        duration = duration_sec or self.block_duration
        
        # 1. Aplikuj firewall
        success = self._apply_firewall_block(ip)
        
        # 2. Zapisz w pamięci
        self.blocked_ips[ip] = {
            'timestamp': datetime.now().isoformat(),
            'reason': reason,
            'duration': duration
        }
        
        # 3. Zapisz do bazy
        if self.db:
            self.db.add_block(ip, reason, duration)
        
        self.logger.critical(f"ZABLOKOWANO IP: {ip} ({reason})")
        return success
    
    def unblock_ip(self, ip: str) -> bool:
        """Odblokowuje IP i aktualizuje DB"""
        try:
            # 1. Usuń z firewall
            self._remove_firewall_block(ip)
            
            # 2. Usuń z pamięci
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
            
            # 3. Aktualizuj DB
            if self.db:
                with sqlite3.connect(self.db.db_path) as conn:
                    conn.execute("UPDATE blocks SET status='expired' WHERE ip=?", (ip,))
            
            self.logger.info(f"ODBLOKOWANO IP: {ip}")
            return True
        except Exception as e:
            self.logger.error(f"Blad odblokowywania {ip}: {e}")
            return False
    
    def auto_unblock_expired(self):
        """Automatycznie odblokowuje wygasłe IP"""
        if self.db:
            count = self.db.cleanup_expired_blocks()
            if count > 0:
                self.logger.info(f"Wyczyszczono {count} wygasłych blokad w DB")

        now = datetime.now()
        expired = []
        for ip, data in list(self.blocked_ips.items()):
            try:
                ts = data['timestamp']
                blocked_time = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
                if (now - blocked_time).total_seconds() > float(data.get('duration', self.block_duration)):
                    expired.append(ip)
            except Exception as e:
                expired.append(ip)
        
        for ip in expired:
            self.unblock_ip(ip)

    def get_blocked_ips(self) -> Dict:
        return self.blocked_ips

    def send_alert(self, alert_type: str, message: str):
        self.logger.info(f"ALERT: {alert_type} - {message}")
