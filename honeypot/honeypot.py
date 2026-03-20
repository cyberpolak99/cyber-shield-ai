import socket
import threading
import logging
import time
from datetime import datetime

class CyberShieldHoneypot:
    """
    Moduł HONEYPOT - Wirtualna pułapka na hakerów.
    Otwiera pozorne usługi (SSH, Telnet, HTTP, SMB), aby przyciągać boty
    i uczyć AI na realnych atakach z internetu.
    """
    def __init__(self, callback=None):
        self.callback = callback  # Funkcja do przesyłania danych o ataku do AI
        self.ports = {
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3389: "RDP",
            8080: "HTTP-Proxy"
        }
        self.running = False
        self.threads = []
        
        # Konfiguracja logowania
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - [HONEYPOT] - %(message)s'
        )
        self.logger = logging.getLogger("CyberShieldHoneypot")

    def handle_connection(self, client_socket, port, service_name):
        """Obsługuje połączenie z 'hakerem' i zbiera dane o nim."""
        try:
            ip_src, port_src = client_socket.getpeername()
            self.logger.warning(f"PRÓBA ATAKU! IP: {ip_src} uderza w port {port} ({service_name})")
            
            # Zbieraj dane dla AI
            attack_data = {
                'timestamp': time.time(),
                'src_ip': ip_src,
                'dst_port': port,
                'service': service_name,
                'type': 'HONEYPOT_HIT'
            }
            
            if self.callback:
                self.callback(attack_data)

            # Symuluj odpowiedź usługi (podstawowy baner)
            if port == 22:
                client_socket.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n")
            elif port == 80:
                client_socket.send(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n")
            
            # Czekaj chwilę na ewentualny payload (np. próba logowania)
            client_socket.settimeout(2)
            try:
                payload = client_socket.recv(1024)
                if payload:
                    attack_data['payload_sample'] = payload.hex()
                    self.logger.info(f"Przechwycono payload od {ip_src}: {payload[:50]}...")
            except:
                pass
                
        except Exception as e:
            self.logger.error(f"Błąd obsługi połączenia: {e}")
        finally:
            client_socket.close()

    def start_listener(self, port, service_name):
        """Uruchamia nasłuchiwanie na konkretnym porcie."""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.listen(5)
            self.logger.info(f"Pułapka aktywna: Port {port} ({service_name})")
            
            while self.running:
                client_sock, addr = server.accept()
                handler = threading.Thread(
                    target=self.handle_connection, 
                    args=(client_sock, port, service_name)
                )
                handler.daemon = True
                handler.start()
        except Exception as e:
            self.logger.error(f"Nie można otworzyć portu {port}: {e}")

    def start(self):
        self.running = True
        for port, name in self.ports.items():
            t = threading.Thread(target=self.start_listener, args=(port, name))
            t.daemon = True
            t.start()
            self.threads.append(t)
        self.logger.warning("SYSTEM HONEYPOT URUCHOMIONY - Czekam na intruzów...")

    def stop(self):
        self.running = False
        self.logger.info("System Honeypot zatrzymany.")

if __name__ == "__main__":
    # Testowy start
    hp = CyberShieldHoneypot()
    hp.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        hp.stop()
