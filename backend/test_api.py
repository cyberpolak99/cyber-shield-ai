import requests

BASE = "http://localhost:10000"

def test_threats():
    r = requests.get(f"{BASE}/api/threats?limit=5")
    assert r.status_code == 200
    assert r.json()['count'] == 5
    print("✅ /api/threats OK")

def test_severity_filter():
    r = requests.get(f"{BASE}/api/threats?severity=CRITICAL")
    assert r.status_code == 200
    assert all(t['severity'] == 'CRITICAL' for t in r.json()['data'])
    print("✅ severity filter OK")

def test_check_ip_malicious():
    r = requests.get(f"{BASE}/api/check/185.220.101.5")
    assert r.status_code == 200
    assert r.json()['is_malicious'] == True
    print("✅ /api/check malicious IP OK")

def test_check_ip_clean():
    r = requests.get(f"{BASE}/api/check/8.8.8.8")
    assert r.status_code == 200
    assert r.json()['is_malicious'] == False
    print("✅ /api/check clean IP OK")

def test_check_ip_invalid():
    r = requests.get(f"{BASE}/api/check/not-an-ip")
    assert r.status_code == 400
    print("✅ /api/check invalid IP 400 OK")

def test_health():
    r = requests.get(f"{BASE}/api/health")
    assert r.status_code == 200
    assert r.json()['status'] == 'healthy'
    print("✅ /api/health OK")

if __name__ == '__main__':
    test_threats()
    test_severity_filter()
    test_check_ip_malicious()
    test_check_ip_clean()
    test_check_ip_invalid()
    test_health()
    print("\n✅ WSZYSTKIE TESTY PRZESZŁY")
