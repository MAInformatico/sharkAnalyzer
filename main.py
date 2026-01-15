import time
from config import *
from parser import parse_pcap
from baseline import load_baseline, save_baseline
from anomaly import detect_anomalies
from anomaly_agent import AnomalyAgent, extract_features_from_records
import os
import pandas as pd

def stats_to_records(stats):
    """Convierte el dict de stats en una lista de registros para el agente."""
    records = []
    for ip, data in stats.items():
        record = {
            'ip': ip,
            'total': data['total'],
            'tcp': data['tcp'],
            'udp': data['udp'],
            'port_count': len(data['ports']),
            'avg_port_traffic': sum(data['ports'].values()) / max(len(data['ports']), 1)
        }
        records.append(record)
    return records

def main():
    baseline = load_baseline(BASELINE_FILE)
    agent_path = 'models/anomaly_agent.pkl'
    agent = AnomalyAgent(model_path=agent_path)
    
    # Cargar agente entrenado si existe
    if os.path.exists(agent_path):
        agent.load(agent_path)
        print(f"Agente cargado desde {agent_path}")

    for pcap in sorted(os.listdir(PCAP_DIR)):
        stats = parse_pcap(f"{PCAP_DIR}/{pcap}", MI_IP)

        if not baseline:
            save_baseline(stats, BASELINE_FILE)
            print("Baseline created")
            return

        alerts = detect_anomalies(stats, baseline, globals())
        
        # Usar el agente de IA para detectar anomalías
        records = stats_to_records(stats)
        if records:
            features = extract_features_from_records(records)
            if not features.empty:
                try:
                    ai_predictions = agent.predict(features)
                    anomaly_ips = [records[i]['ip'] for i, pred in enumerate(ai_predictions) if pred == 1]
                    if anomaly_ips:
                        ai_alert = f"[AGENTE-IA] Anomalías detectadas en IPs: {', '.join(anomaly_ips)}"
                        alerts.append(ai_alert)
                        print(ai_alert)
                except:
                    # Si el agente aún no está entrenado, continuar con detección tradicional
                    pass

        if alerts:
            with open("data/alerts.log", "a") as f:
                for alert in alerts:
                    print(alert)
                    f.write(alert + "\n")

def train_agent():
    """Entrena el agente con datos históricos de todos los pcaps disponibles."""
    agent = AnomalyAgent(n_estimators=100, contamination=0.05)
    agent_path = 'models/anomaly_agent.pkl'
    
    all_records = []
    for pcap in sorted(os.listdir(PCAP_DIR)):
        filepath = f"{PCAP_DIR}/{pcap}"
        if os.path.isfile(filepath):
            try:
                stats = parse_pcap(filepath, MI_IP)
                records = stats_to_records(stats)
                all_records.extend(records)
            except Exception as e:
                print(f"Error procesando {pcap}: {e}")
                continue
    
    if not all_records:
        print("No hay datos para entrenar el agente.")
        return
    
    features = extract_features_from_records(all_records)
    if features.shape[0] < 10:
        print(f"Datos insuficientes ({features.shape[0]} registros). Se requieren al menos 10.")
        return
    
    agent.fit(features)
    agent.save(agent_path)
    print(f"Agente entrenado y guardado en {agent_path}. Registros usados: {features.shape[0]}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'train':
        train_agent()
    else:
        main()