import requests
import logging
import socket

class ThreatIntel:
    """
    Integracja z zewnętrznymi bazami danych o zagrożeniach.
    Używa AbuseIPDB do sprawdzania reputacji adresów IP.
    """
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2/check"
        self.headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }

    def check_ip_reputation(self, ip):
        """
        Zwraca wynik procentowy (abuseConfidenceScore) dla danego IP.
        Jeśli brak klucza API, zwraca neutralne 0.
        """
        if not self.api_key:
            return 0
        
        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }

        try:
            response = requests.get(self.base_url, headers=self.headers, params=querystring, timeout=5)
            if response.status_code == 200:
                data = response.json()
                score = data['data']['abuseConfidenceScore']
                return score
            else:
                return 0
        except Exception as e:
            logging.error(f"Blad ThreatIntel: {e}")
            return 0

    def check_dnsbl(self, ip):
        """
        Bardzo szybki i darmowy fallback: Sprawdza IP w listach DNSBL (Spamhaus/Abuse.ch).
        Nie wymaga klucza API.
        """
        try:
            # Odwróć oktety adresu IP (wymagane dla DNSBL)
            reverse_ip = ".".join(reversed(ip.split(".")))
            # Sprawdzamy w sbl.spamhaus.org (przykładowo)
            query = f"{reverse_ip}.sbl.spamhaus.org"
            socket.gethostbyname(query)
            return 100 # Jeśli zapytanie się powiodło, IP jest na czarnej liście
        except socket.gaierror:
            return 0 # IP czyste
        except Exception:
            return 0

    def is_known_attacker(self, ip, threshold=50):
        """
        Sprawdza czy IP ma wynik powyżej progu zaufania do nadużyć.
        """
        score = self.check_ip_reputation(ip)
        
        # Fallback do DNSBL jeśli AbuseIPDB nie dało wyniku
        if score == 0:
            score = self.check_dnsbl(ip)
            
        return score >= threshold, score
