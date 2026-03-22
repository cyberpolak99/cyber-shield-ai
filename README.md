# 🛡️ Cyber Shield AI v6.0 PROF [Autonomous Defense System]

**Cyber Shield AI** to kompleksowy, autonomiczny system wykrywania i reagowania na włamania (IDS/IPS), zaprojektowany specjalnie pod system Windows. Projekt łączy w sobie aktywną detekcję zagrożeń (Honeypoty), analizę geolokalizacyjną oraz automatyczną obronę za pomocą Windows Firewall.

---

## 💰 Monetization: Threat Intelligence API (RapidAPI)

Nasz system to nie tylko lokalna obrona, ale również potężne źródło danych o zagrożeniach. Udostępniamy publiczne API oparte na danych z naszych Honeypotów:

- **RapidAPI Link**: [Cyber Shield Threat Intelligence API](https://rapidapi.com/darro2323/api/threat-intelligence-api1)
- **Status Bazy**: 135,000+ unikalnych anomalii, 2,500+ aktywnych blokad.
- **Dla kogo?**: Deweloperzy SaaS, Sysadmini, researchers (Darmowy plan FREE dostępny).

---

## 🚀 Kluczowe Funkcjonalności

1.  **Honeypot Sensor (Live Detection)**:
    - Wielowątkowy sensor nasłuchujący na krytycznych portach: 22 (SSH), 23 (Telnet), 80 (HTTP), 445 (SMB), 3389 (RDP).
    - Serwuje przekonujące banery (np. OpenSSH 8.2p1, Apache 2.4.41), aby zidentyfikować boty.
2.  **Smart Auto-Defend (Autonomous Response)**:
    - Automatyczne blokowanie adresów IP w Windows Firewall na podstawie scoringu AI (>0.98).
    - Inteligentny system sprawdzania **Białych List (Whitelisting)** — chroni Twoje własne urządzenia przed przypadkową blokadą.
3.  **Analityczny Dashboard (Real-time Monitoring)**:
    - **Global Threat Map**: Heatmapa ataków na mapie świata (Leaflet.js).
    - **Port Analysis**: Wykres kołowy (Pie Chart) najczęściej atakowanych usług (SSH vs RDP vs HTTP).
    - **Live Logs Browser**: Podgląd logów każdego modułu bezpośrednio w Dashboardzie (Console-style).
4.  **Desktop Alerts**:
    - System powiadomień systemowych oraz alerty dźwiękowe przy każdorazowej nowej blokadzie IP.
5.  **Cleanup Manager (Maintenance)**:
    - Automatyczne wygaszanie blokad po 24 godzinach (TTL), utrzymujące firewall w wysokiej wydajności.
6.  **System Orchestrator**:
    - Skrypt `start_cyber_shield.py`, który zarządza wszystkimi 4 procesami, monitoruje ich stan i automatycznie restartuje usługi w przypadku awarii.

---

## 🛠️ Architektura Projektu

- `dashboard/`: Interfejs użytkownika (FastAPI, Chart.js, Leaflet).
- `backend/`:
    - `honeypot_sensor.py`: Detekcja i logowanie prób połączeń.
    - `autodefend_mgr.py`: Mózg systemu — podejmuje decyzje o blokadach.
    - `firewall_mgr.py`: Integracja z `netsh advfirewall` (zarządzanie regułami).
    - `cleanup_mgr.py`: Higiena bazy i firewalla.
    - `db_manager.py`: Zarządzanie bazą SQLite (`cyber_shield.db`).
- `logs/`: Centralny folder diagnostyczny (tail -n 100).
- `data/`: Baza danych i pliki GeoIP.

---

## ⚡ Szybki Start (Instalacja)

### 1. Wymagania
Wymagany Python 3.8+ oraz uprawnienia Administratora (do zarządzania Firewallem).

### 2. Instalacja zależności
```powershell
pip install fastapi uvicorn geoip2 pandas requests
```

### 3. Uruchomienie (Orchestrator)
Otwórz terminal jako **Administrator** i wpisz:
```powershell
python start_cyber_shield.py
```
System uruchomi się automatycznie. Dashboard będzie dostępny pod adresem: [http://localhost:8000](http://localhost:8000) (Login: admin / Hasło: PolskiCyber2026).

---

## 🛡️ Bezpieczeństwo
Pamiętaj o dodaniu swojego głównego adresu IP do **Białej Listy** w zakładce **⚙️ Ustawienia**, aby uniknąć przypadkowej blokady podczas testowania Twojego własnego Honeypota.

---
*Autor: Antigravity AI (Google Deepmind) | PolskiCyber 2026*
