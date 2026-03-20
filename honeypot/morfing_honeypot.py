"""
Morfing Honeypot - Unikalne Pułapki z Dynamicznymi Sygnaturami

Każda pułapka ma unikalne cechy = trudne dla atakujących do identyfikacji
"""

import socket
import threading
import time
import random
import string
import hashlib
from datetime import datetime
from typing import Dict, List, Callable, Optional
import logging

from hunter_base import HunterBase


class MorfingHoneypot:
    """
    Pułapki z Morfing - unikalne sygnatury dla każdego deployment

    Dlaczego to innowacyjne:
    - Każda pułapka wygląda inaczej dla skanerów
    - Atakujący myślą że to prawdziwy serwer
    - Unikalne fingerprinting za każdym razem
    - Moralne: tylko obserwacja, nie obrona/agresja
    """

    # Morfing components (to się zmienia dla każdej pułapki)
    MORFING_COMPONENTS = {
        'ssh_version': ['6.2p1', '7.2p2', '8.0p1', '8.4p1', '8.9p1'],
        'hostname_prefix': ['server', 'host', 'node', 'vm', 'container'],
        'hostname_suffix': ['pl', 'warszawa', 'krakow', 'gdansk', 'poznan'],
        'random_digits': [4, 5, 6, 7, 8],
        'banner_delay': [0.1, 0.2, 0.3, 0.4, 0.5],  # sekundy
        'encryption_algos': ['bcrypt', 'SHA512', 'SHA256', 'pbkdf2'],
    }

    def __init__(self, hunter_base: HunterBase, logger=None):
        self.hunter = hunter_base
        self.logger = logger or logging.getLogger(__name__)

        # Konfiguracja pułapki (generowana losowo)
        self.config = self._generate_morphing_config()

        # Sygnatura pułapki
        self.fingerprint = self.hunter.generate_honeypot_fingerprint(self.config)

        # Aktywne pułapki (port -> service)
        self.active_services = {}

        # Callback dla incoming connections
        self.on_connection = None

    def _generate_morphing_config(self) -> Dict:
        """Generuje losową konfigurację pułapki"""
        config = {
            'ssh_version': random.choice(self.MORFING_COMPONENTS['ssh_version']),
            'hostname': self._generate_hostname(),
            'ssh_banner': None,
            'banner_delay': random.choice(self.MORFING_COMPONENTS['banner_delay']),
            'encryption_algo': random.choice(self.MORFING_COMPONENTS['encryption_algos']),
            'ssh_port': random.randint(2222, 22999),  # Losowy SSH port
            'http_port': random.randint(8080, 8999),  # Losowy HTTP port
        }

        # Generuj SSH banner z hostname i version
        config['ssh_banner'] = f"OpenSSH_{config['ssh_version']} {config['hostname']}"

        return config

    def _generate_hostname(self) -> str:
        """Generuje losowy hostname"""
        prefix = random.choice(self.MORFING_COMPONENTS['hostname_prefix'])
        suffix = random.choice(self.MORFING_COMPONENTS['hostname_suffix'])
        digits = random.choice(self.MORFING_COMPONENTS['random_digits'])
        random_part = ''.join(random.choices(string.digits, k=digits))

        return f"{prefix}-{suffix}-{random_part}"

    def get_services(self) -> Dict:
        """Zwróć dostępne services"""
        services = {
            'ssh': {
                'port': self.config['ssh_port'],
                'type': 'ssh',
                'banner': self.config['ssh_banner'],
                'delay': self.config['banner_delay']
            },
            'http': {
                'port': self.config['http_port'],
                'type': 'http',
                'banner': f"Apache/2.4.41 (Ubuntu) Server at {self.config['hostname']}",
                'delay': 0.1
            }
        }
        return services

    def start_ssh_honeypot(self, callback: Callable = None):
        """Uruchom SSH pułapkę na random portu"""
        ssh_config = self.config

        def handle_ssh_connection(client_sock, client_address):
            try:
                # Morfing: delay przed banner
                time.sleep(ssh_config['banner_delay'])

                # Wysyła banner
                banner = f"{ssh_config['ssh_banner']}"
                client_sock.send(banner.encode())

                # Log incoming connection
                attack_data = {
                    'ip': client_address[0],
                    'port': client_address[1],
                    'type': 'ssh_honeypot',
                    'technique': 'initial_connection',
                    'payload_sample': banner,
                    'headers': {'user_agent': None},
                    'data': {'service': 'ssh', 'port': ssh_config['ssh_port']}
                }

                # Walidacja moralna
                if self.hunter.validate_moral_compliance(attack_data):
                    self.hunter.record_attack(attack_data)

                    # Callback jeśli dostępny
                    if callback:
                        callback(attack_data)

                # Czekaj na payload (timeout 2s)
                client_sock.settimeout(2)
                try:
                    payload = client_sock.recv(1024)

                    # Log payload
                    attack_data['payload_sample'] = payload.decode(errors='ignore')
                    attack_data['technique'] = 'ssh_post_connection'
                    self.hunter.record_attack(attack_data)

                except socket.timeout:
                    pass  # Normalne dla honeypotu

            except Exception as e:
                self.logger.error(f"SSH honeypot error: {e}")
            finally:
                client_sock.close()

        # Start SSH listener
        thread = threading.Thread(
            target=self._start_listener,
            args=(ssh_config['ssh_port'], handle_ssh_connection),
            daemon=True
        )
        thread.start()

        self.active_services['ssh'] = {
            'port': ssh_config['ssh_port'],
            'config': ssh_config,
            'thread': thread
        }

        self.logger.info(f"Morfing SSH honeypot started on port {ssh_config['ssh_port']}")

    def start_http_honeypot(self, callback: Callable = None):
        """Uruchom HTTP pułapkę"""
        http_config = self.config

        def handle_http_connection(client_sock, client_address):
            try:
                # Odbierz request
                request = client_sock.recv(4096).decode(errors='ignore')

                if not request:
                    client_sock.close()
                    return

                # Parse request
                lines = request.split('\n')
                request_line = lines[0] if lines else ''
                method, path, version = request_line.split() if len(request_line.split()) == 3 else (None, None, None)

                # Extract headers
                headers = {}
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()

                # Log incoming connection
                attack_data = {
                    'ip': client_address[0],
                    'port': client_address[1],
                    'type': 'http_honeypot',
                    'technique': f'http_{method.lower()}' if method else 'http_unknown',
                    'payload_sample': request[:500],  # First 500 chars
                    'headers': {'user_agent': headers.get('user-agent', None)},
                    'data': {'path': path, 'method': method, 'http_version': version}
                }

                # Walidacja moralna
                if self.hunter.validate_moral_compliance(attack_data):
                    self.hunter.record_attack(attack_data)

                    # Callback jeśli dostępny
                    if callback:
                        callback(attack_data)

                # Send response
                response = f"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n"
                client_sock.send(response.encode())

            except Exception as e:
                self.logger.error(f"HTTP honeypot error: {e}")
            finally:
                client_sock.close()

        # Start HTTP listener
        thread = threading.Thread(
            target=self._start_listener,
            args=(http_config['http_port'], handle_http_connection),
            daemon=True
        )
        thread.start()

        self.active_services['http'] = {
            'port': http_config['http_port'],
            'config': http_config,
            'thread': thread
        }

        self.logger.info(f"Morfing HTTP honeypot started on port {http_config['http_port']}")

    def _start_listener(self, port: int, handle_func: Callable):
        """Generic listener"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind(('0.0.0.0', int(port)))
            server.listen(5)

            while True:
                client_sock, addr = server.accept()
                handler = threading.Thread(
                    target=handle_func,
                    args=(client_sock, addr),
                    daemon=True
                )
                handler.start()

        except Exception as e:
            self.logger.error(f"Listener error on port {port}: {e}")

    def stop_all(self):
        """Zatrzymaj wszystkie pułapki"""
        for service_name, service in self.active_services.items():
            self.logger.info(f"Stopping {service_name} honeypot on port {service['port']}")
        self.active_services.clear()

    def set_connection_callback(self, callback: Callable):
        """Ustaw callback dla incoming connections"""
        self.on_connection = callback

    def generate_configuration_report(self) -> Dict:
        """Generuje raport konfiguracji pułapki"""
        return {
            'hunter_id': self.hunter.hunter_id,
            'fingerprint': self.fingerprint,
            'config': self.config,
            'services': {name: {'port': svc['port']} for name, svc in self.active_services.items()},
            'uniqueness_factors': [
                'Unique SSH version',
                'Random hostname',
                'Random ports',
                'Variable banner delay',
                'Unique encryption algo'
            ],
            'timestamp': datetime.now().isoformat()
        }


__all__ = ['MorfingHoneypot']
