import sys
import time
import pandas as pd
import numpy as np
import requests
from collections import defaultdict
import logging
import threading
from scapy.all import sniff, IP, TCP, UDP, Raw

# Importy komponentów PolskiCyberShield
sys.stdout.reconfigure(encoding='utf-8')
try:
    from cyber_shield_blocker import CyberShieldBlocker
    from db_manager import DBManager
    from threat_intel import ThreatIntel
    from ai_engine import CyberShieldBrain
    from honeypot import CyberShieldHoneypot
except ImportError as e:
    print(f"Blad: Brak modulow! {e}")
    sys.exit(1)

# --- KONFIGURACJA ---
LEARNING_PACKETS = 100
RETRAIN_INTERVAL = 1000
AUTONOMOUS_MODE = True  # Tryb bezobsługowy
STRICT_THRESHOLD = -0.45 # Próg natychmiastowej blokady
HEARTBEAT_FILE = "data/heartbeat.txt"

db = DBManager()
intel = ThreatIntel()

def honeypot_callback(attack_data):
    """Otrzymuje info od Honeypota i natychmiast uczy AI"""
    global pkt_counter, collected_data
    ip = attack_data['src_ip']
    reason = f"Honeypot Trigger: Attempted access to {attack_data['service']}"

    # Zapis do bazy anomalii (z obsługą błędów)
    try:
        db.log_anomaly(ip, 'HONEYPOT', 6, 1.0, 0, f"Honeypot hit: {attack_data.get('service','?')} port {attack_data.get('dst_port',0)}", label=1)
    except Exception as db_err:
        print(f"\n[ERROR] DB write failed: {db_err}")

    # 1. Zasilanie AI "żywym" materiałem (Skill Gain)
    # Tworzymy uproszczony rekord cech dla AI
    skill_feat = {
        'src_ip': ip, 'dst_ip': 'HONEYPOT', 'protocol': 6,
        'packet_len': 0, 'tcp_flags': 0, 'entropy': 7.5, # Wysoka entropia dla pułapki
        'avg_iat': 0, 'std_iat': 0, 'pps': 1, 'bps': 1,
        'src_bytes': 0, 'label': 1 # POTWIERDZONY ATAK
    }
    collected_data.append(skill_feat)
    pkt_counter += 1

    # 2. Natychmiastowa blokada
    if blocker.block_ip(ip, reason=reason):
        db.add_block(ip, reason, 604800)
        print(f"\n[HONEYPOT] ZŁAPANO INTRUZA: {ip} | Cel: {attack_data['service']} | BLOKADA NAŁOŻONA")

# Inicjalizacja
brain = CyberShieldBrain()
blocker = CyberShieldBlocker()
hp = CyberShieldHoneypot(callback=honeypot_callback)
hp.start() # Start pułapki

# Parametry dynamiczne
current_threshold = -0.25
scores_history = []

def hunt_global_threats():
    """Wątek Proaktywnej Nauki: Pobiera najnowsze wzorce ataków z internetu"""
    global collected_data, pkt_counter
    while True:
        try:
            # Pobieranie listy 'Bad Guys' z CINS Score (darmowa lista)
            url = "http://cinsscore.com/list/ci-badguys.txt"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                bad_ips = response.text.splitlines()[:100] # Bierzemy TOP 100 hakerów
                print(f"\n[AI-HUNT] Pobrano {len(bad_ips)} wzorcow hakerskich z internetu (Proactive Skill Gain)")
                
                for ip in bad_ips:
                    if ip.strip():
                        # Symulujemy cechy hakerskie dla bazy treningowej
                        skill_feat = {
                            'src_ip': ip, 'dst_ip': 'HUNT', 'protocol': 6,
                            'packet_len': 1500, 'tcp_flags': 2, 'entropy': 7.8,
                            'avg_iat': 0.0001, 'std_iat': 0.0, 'pps': 2000, 'bps': 50000,
                            'src_bytes': 100000, 'label': 1 # POTWIERDZONY ATAK
                        }
                        collected_data.append(skill_feat)
                        pkt_counter += 1
                
                # Jeśli mamy dużo danych, wymuś trening
                if len(collected_data) > 200:
                    brain.train_hybrid(collected_data)
                    
        except Exception as e:
            print(f"\n[AI-HUNT] Blad pobierania wzorcow: {e}")
            
        time.sleep(21600) # Szukaj nowych wzorców co 6 h

# Uruchomienie łowcy
threading.Thread(target=hunt_global_threats, daemon=True).start()

# Pamięć przepływów
flows = defaultdict(lambda: {
    'start_time': time.time(), 'last_time': time.time(),
    'src_bytes': 0, 'count': 0, 'iats': []
})

collected_data = []
pkt_counter = 0

def get_entropy(data):
    if not data: return 0
    return brain.calculate_entropy(data)

def extract_features(packet):
    if IP not in packet: return None
    src_ip, dst_ip, proto = packet[IP].src, packet[IP].dst, packet[IP].proto
    length = len(packet)
    
    tcp_flags = int(packet[TCP].flags) if TCP in packet and packet[TCP].flags else 0
    payload = bytes(packet[Raw]) if Raw in packet else b""
    entropy = get_entropy(payload)

    flow = flows[(src_ip, dst_ip, proto)]
    now = time.time()
    iat = now - flow['last_time']
    if iat > 0: flow['iats'].append(iat)
    
    flow['last_time'] = now
    flow['src_bytes'] += length
    
    # Naprawa błędu mutowalności liczników wewnątrz słownika
    count = flow['count']
    flow['count'] = count + 1
    
    tail_iats = flow['iats'][-10:] if flow['iats'] else [0.0]
    
    # Obliczanie PPS/BPS z zabezpieczeniem przed zerem
    dur = max(0.0001, now - flow['start_time'])
    pps = float(flow['count']) / dur
    bps = float(flow['src_bytes']) / dur

    return {
        'src_ip': src_ip, 'dst_ip': dst_ip, 'protocol': proto,
        'packet_len': int(length), 'tcp_flags': int(tcp_flags), 'entropy': float(entropy),
        'avg_iat': float(np.mean(tail_iats)),
        'std_iat': float(np.std(tail_iats)) if len(tail_iats) > 1 else 0.0,
        'pps': pps, 'bps': bps,
        'src_bytes': int(flow['src_bytes']), 'label': 0
    }

def process_packet(packet):
    global pkt_counter, collected_data
    
    if IP not in packet or packet[IP].src == '127.0.0.1': return
    feat = extract_features(packet)
    if not feat: return

    # 1. ZBIERANIE DANYCH
    collected_data.append(feat)
    pkt_counter += 1

    # 2. NAUKA (jeśli brak modelu)
    if not brain.is_ready:
        sys.stdout.write(f"\r📡 Pierwszy trening: {len(collected_data)}/{LEARNING_PACKETS}")
        sys.stdout.flush()
        if len(collected_data) >= LEARNING_PACKETS:
            brain.train_hybrid(collected_data)
        return

    # 3. ANALIZA HYBRYDOWA
    res = brain.predict(feat)
    if res:
        scores_history.append(res['iso_score'])
        if len(scores_history) > 100: scores_history.pop(0)
        
        # Dynamiczny próg: średnia - 2 * odchylenie std (ale nie więcej niż -0.15)
        if len(scores_history) > 50:
            avg_score = np.mean(scores_history)
            std_score = np.std(scores_history)
            current_threshold = min(-0.15, avg_score - 2 * std_score)

    if res and res['is_attack'] and res['iso_score'] < current_threshold:
        ip_src = str(feat['src_ip'])
        if ip_src.startswith(("192.168.", "10.", "127.")): return

        # Weryfikacja ThreatIntel przed decyzją
        is_hacker, intel_score = intel.is_known_attacker(ip_src)
        
        # Decyzja autonomiczna (AI Score + Reputation)
        is_high_risk = res['iso_score'] < STRICT_THRESHOLD or intel_score > 60
        
        # Interpretacja AI - Bielik
        bielik_comment = brain.interpret_bielik(res)
        
        if AUTONOMOUS_MODE or is_high_risk:
            reason = f"{res['explanation']} (Rep: {intel_score}) | Auto-Blocked by ACP"
            if blocker.block_ip(ip_src, reason=reason):
                db.add_block(ip_src, reason, 86400) # Blokada na 24h
                print(f"\n[ACP] AUTONOMICZNA BLOKADA: {ip_src} | Wynik: {res['iso_score']:.3f} | Intel: {intel_score}")
                print(f"[XAI] {bielik_comment}")
        else:
            print(f"\n[!!!] WYKRYTO ANOMALIĘ: {ip_src} | Wynik: {res['iso_score']:.3f} | Intel: {intel_score} (Obserwacja)")
        
        # Auto-Labelling (Feedback Loop)
        if res['iso_score'] < -0.2 and (intel_score > 30 or is_high_risk):
            feat['label'] = 1 # Potwierdzony atak

        print(f"\n🚨 [CyberShield] DETEKCJA: {ip_src}")
        print(f"   Powod: {res['explanation']}")
        print(f"   Pewnosc AI: {res['class_prob']:.1%} | Intel: {intel_score}%")

        db.log_anomaly(ip_src, feat['dst_ip'], feat['protocol'], res['iso_score'], 
                      feat['src_bytes'], res['explanation'], label=feat['label'])

        if res['iso_score'] < -0.25 or res['class_prob'] > 0.8 or intel_score > 60:
            reason = f"XAI Block: {res['explanation']}"
            if blocker.block_ip(ip_src, reason=reason):
                db.add_block(ip_src, reason, 7200)

    # Heartbeat dla Watchdoga
    if pkt_counter % 50 == 0:
        with open(HEARTBEAT_FILE, "w") as f:
            f.write(str(time.time()))
        print(f"\r[ACP] Pakietow: {pkt_counter} | Threshold: {current_threshold:.3f} | System: CHRONIONY", end="", flush=True)

    # 4. CIĄGŁY RETRAINING (w osobnym wątku)
    if pkt_counter >= RETRAIN_INTERVAL:
        pkt_counter = 0
        print(f"\n[AI] Rozpoczynanie cyklu retrainingu (bufor: {len(collected_data)})...")
        if len(collected_data) > 5000: collected_data = collected_data[-5000:]
        threading.Thread(target=brain.train_hybrid, args=(collected_data,), daemon=True).start()

if __name__ == "__main__":
    print("=" * 70)
    print("PolskiCyberShield v6.0 PROF - Explainable Hybrid AI")
    print("Analizuje behawioralnie kazdy pakiet i uczy sie Zero-Day.")
    print("=" * 70)
    
    threading.Thread(target=lambda: [time.sleep(60), blocker.auto_unblock_expired()] or None, daemon=True).start()
    sniff(prn=process_packet, store=0)
