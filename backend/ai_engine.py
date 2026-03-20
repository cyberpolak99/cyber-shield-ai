import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import joblib
import os
import threading
import math

class CyberShieldBrain:
    def __init__(self, model_dir="models"):
        self.model_dir = model_dir
        self.lock = threading.Lock()
        self.scaler = StandardScaler()

        # Modele
        self.iso_forest = None    # Detekcja anomalii punktowych
        self.classifier = None    # Klasyfikator nadzorowany (wiedza o hakerach)
        self.clusterer = None     # DBSCAN dla Zero-Day

        self.is_ready = False
        self.has_classifier = False
        self.feature_cols = ['packet_len', 'avg_iat', 'std_iat', 'pps', 'bps', 'entropy', 'tcp_flags']

        os.makedirs(model_dir, exist_ok=True)
        self.load_all()

    def calculate_entropy(self, data):
        """Oblicza entropię Shannona dla ładunku pakietu"""
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def load_all(self):
        try:
            if os.path.exists(f"{self.model_dir}/isolation_forest.joblib"):
                self.iso_forest = joblib.load(f"{self.model_dir}/isolation_forest.joblib")
                self.scaler = joblib.load(f"{self.model_dir}/scaler.joblib")
                self.is_ready = True
                print(f"[AI] Models loaded from {self.model_dir}/")
            if os.path.exists(f"{self.model_dir}/classifier.joblib"):
                self.classifier = joblib.load(f"{self.model_dir}/classifier.joblib")
                self.has_classifier = True
        except Exception as e:
            print(f"[AI] Error loading models: {e}")

    def save_all(self):
        with self.lock:
            if self.iso_forest:
                joblib.dump(self.iso_forest, f"{self.model_dir}/isolation_forest.joblib")
            if self.scaler:
                joblib.dump(self.scaler, f"{self.model_dir}/scaler.joblib")
            if self.classifier:
                joblib.dump(self.classifier, f"{self.model_dir}/classifier.joblib")
            print(f"[AI] Models saved to {self.model_dir}/")

    def train_hybrid(self, data_buffer):
        """Głęboki trening hybrydowy"""
        with self.lock:
            df = pd.DataFrame(data_buffer)
            X = df[self.feature_cols].fillna(0)
            X_scaled = self.scaler.fit_transform(X)
            
            # 1. Isolation Forest (Anomaly)
            self.iso_forest = IsolationForest(contamination=0.03, n_estimators=200, random_state=42)
            self.iso_forest.fit(X_scaled)
            
            # 2. DBSCAN (Zero-Day Discovery)
            # Uczymy go rozpoznawać kształt "normalności"
            self.clusterer = DBSCAN(eps=0.5, min_samples=10).fit(X_scaled)
            
            # 3. Supervised (jeśli są etykiety)
            if 'label' in df.columns and df[df['label'] == 1].shape[0] >= 10:
                y = df['label']
                self.classifier = RandomForestClassifier(n_estimators=100)
                self.classifier.fit(X, y)
                self.has_classifier = True
            
            self.is_ready = True
            self.save_all()

    def analyze_behavior(self, features):
        """XAI: Wyjaśnia dlaczego dany ruch jest podejrzany"""
        reasons = []
        if features['std_iat'] < 0.001 and features.get('pps', 0) > 100:
            reasons.append("Bardzo wysoka regularność (rytmiczne pakiety sugerują automat/bota)")
        if features.get('entropy', 0) > 7.2:
            reasons.append("Wysoka entropia danych (podejrzenie zaszyfrowanego ładunku malware/shellcode)")
        if features.get('pps', 0) > 800:
            reasons.append("Gwałtowny wzrost liczby pakietów (typowy dla flood/DDoS)")
        if features.get('packet_len', 0) > 1400 and features.get('pps', 0) > 500:
            reasons.append("Nienaturalnie duże pakiety przy dużym natężeniu (możliwy exfiltration)")
        
        return " + ".join(reasons) if reasons else "Nietypowa korelacja cech sieciowych"

    def interpret_bielik(self, anomaly_data):
        """Symulacja interpretacji przez model Bielik AI (wersja tekstowa)"""
        desc = anomaly_data.get('explanation', 'Nieznana anomalia')
        score = anomaly_data.get('iso_score', 0)
        
        advice = "Zalecana obserwacja"
        if score < -0.2:
            advice = "NATYCHMIASTOWA BLOKADA - wzorzec wysoce szkodliwy"
        elif "BOT" in desc:
            advice = "Blokada tymczasowa - prawdopodobny skrypt automatyczny"
            
        return f"Interpretacja Bielik AI: Wykryto wzorzec '{desc}'. {advice}. Prawdopodobieństwo trafności: {abs(score)*100:.1f}%."

    def predict(self, features_dict):
        if not self.is_ready: return None
        
        df = pd.DataFrame([features_dict])
        X_raw = df[self.feature_cols].fillna(0)
        X_sc = self.scaler.transform(X_raw)
        
        iso_score = self.iso_forest.decision_function(X_sc)[0]
        class_prob = self.classifier.predict_proba(X_raw)[0][1] if self.has_classifier else 0.0
        
        # Wyjaśnienie behawioralne
        explanation = self.analyze_behavior(features_dict)
        
        # Meta-score
        is_attack = (iso_score < -0.15) or (class_prob > 0.8)
        
        return {
            'is_attack': is_attack,
            'iso_score': iso_score,
            'class_prob': class_prob,
            'explanation': explanation
        }
