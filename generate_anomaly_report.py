#!/usr/bin/env python3
"""
Script para generar un reporte detallado de anomalías detectadas.

USO:
    python generate_anomaly_report.py [carpeta_pcap] [max_archivos] [output_file]

EJEMPLOS:
    python generate_anomaly_report.py                           # usa defaults
    python generate_anomaly_report.py data/pcaps 5              # especificar max archivos
    python generate_anomaly_report.py data/pcaps 5 anomaly_report.txt
"""

import numpy as np
import pandas as pd
import os
import sys
from datetime import datetime
from anomaly_agent import AnomalyAgent, extract_features_from_records
from config import MI_IP
from scapy.all import PcapReader, IP, TCP, UDP
from collections import defaultdict

def load_pcap_data(pcap_dir, max_files=None, max_packets=10000):
    """Carga datos de archivos .pcap con información detallada."""
    all_records = []
    all_ips_data = {}
    file_count = 0
    
    if not os.path.isdir(pcap_dir):
        print(f"Error: La carpeta '{pcap_dir}' no existe.")
        return all_records, all_ips_data, file_count
    
    pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith('.pcap')]
    
    if not pcap_files:
        print(f"No se encontraron archivos .pcap en '{pcap_dir}'")
        return all_records, all_ips_data, file_count
    
    if max_files and len(pcap_files) > max_files:
        pcap_files = sorted(pcap_files)[:max_files]
    
    print(f"Procesando {len(pcap_files)} archivos .pcap...")
    
    for pcap_file in sorted(pcap_files):
        filepath = os.path.join(pcap_dir, pcap_file)
        try:
            print(f"  {pcap_file}...", end=" ", flush=True)
            
            stats = defaultdict(lambda: {
                "total": 0,
                "tcp": 0,
                "udp": 0,
                "ports": defaultdict(int)
            })
            
            pkt_count = 0
            with PcapReader(filepath) as pcap:
                for pkt in pcap:
                    if pkt_count >= max_packets:
                        break
                    pkt_count += 1
                    
                    if IP not in pkt:
                        continue
                    
                    ip = None
                    if pkt[IP].src == MI_IP:
                        ip = pkt[IP].dst
                    elif pkt[IP].dst == MI_IP:
                        ip = pkt[IP].src
                    else:
                        continue
                    
                    stats[ip]["total"] += 1
                    
                    if TCP in pkt:
                        stats[ip]["tcp"] += 1
                        stats[ip]["ports"][pkt[TCP].dport] += 1
                    elif UDP in pkt:
                        stats[ip]["udp"] += 1
                        stats[ip]["ports"][pkt[UDP].dport] += 1
            
            if stats:
                for ip, data in stats.items():
                    record = {
                        'ip': ip,
                        'total': data['total'],
                        'tcp': data['tcp'],
                        'udp': data['udp'],
                        'port_count': len(data['ports']),
                        'avg_port_traffic': sum(data['ports'].values()) / max(len(data['ports']), 1),
                        'top_ports': sorted(data['ports'].items(), key=lambda x: x[1], reverse=True)[:5]
                    }
                    all_records.append(record)
                    all_ips_data[ip] = record
                
                file_count += 1
                print(f"✓")
            else:
                print("(sin datos)")
        
        except Exception as e:
            print(f"✗ Error: {str(e)[:50]}")
            continue
    
    return all_records, all_ips_data, file_count

def generate_report(pcap_dir, max_files=5, output_file=None):
    """Genera un reporte detallado de anomalías."""
    
    if not output_file:
        output_file = f"anomaly_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    print(f"\n[1] Cargando archivos .pcap...")
    all_records, all_ips_data, file_count = load_pcap_data(pcap_dir, max_files=max_files)
    
    if not all_records:
        print("No se extrajeron datos.")
        return
    
    print(f"[2] Extrayendo features...")
    features = extract_features_from_records(all_records)
    
    print(f"[3] Cargando agente entrenado...")
    agent_path = 'models/anomaly_agent.pkl'
    
    if not os.path.exists(agent_path):
        print(f"Error: No se encontró modelo en {agent_path}")
        print("Ejecuta primero: python demo_agent_training.py data/pcaps")
        return
    
    agent = AnomalyAgent()
    agent.load(agent_path)
    
    print(f"[4] Detectando anomalías...")
    predictions = agent.predict(features)
    scores = agent.score_samples(features)
    
    # Crear reporte
    print(f"[5] Generando reporte en {output_file}...")
    
    with open(output_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write(f"REPORTE DE DETECCIÓN DE ANOMALÍAS\n")
        f.write(f"Generado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        
        # Resumen general
        f.write(f"RESUMEN GENERAL\n")
        f.write("-" * 80 + "\n")
        f.write(f"Archivos procesados: {file_count}\n")
        f.write(f"Total IPs analizadas: {len(all_records)}\n")
        f.write(f"Anomalías detectadas: {(predictions == 1).sum()}\n")
        f.write(f"Porcentaje anómalo: {100 * (predictions == 1).sum() / len(predictions):.1f}%\n\n")
        
        # Estadísticas de features
        f.write(f"ESTADÍSTICAS DE TRÁFICO\n")
        f.write("-" * 80 + "\n")
        f.write(features.describe().to_string())
        f.write("\n\n")
        
        # IPs ANÓMALAS
        anomaly_indices = np.where(predictions == 1)[0]
        
        if len(anomaly_indices) > 0:
            f.write(f"IPs DETECTADAS COMO ANÓMALAS ({len(anomaly_indices)})\n")
            f.write("-" * 80 + "\n\n")
            
            # Ordenar por anomaly score
            anomaly_data = []
            for idx in anomaly_indices:
                anomaly_data.append({
                    'index': idx,
                    'ip': all_records[idx]['ip'],
                    'score': scores[idx],
                    'total': all_records[idx]['total'],
                    'tcp': all_records[idx]['tcp'],
                    'udp': all_records[idx]['udp'],
                    'port_count': all_records[idx]['port_count'],
                    'avg_port_traffic': all_records[idx]['avg_port_traffic']
                })
            
            anomaly_data.sort(key=lambda x: x['score'])  # Mayor anomalía primero
            
            for i, anom in enumerate(anomaly_data, 1):
                ip = anom['ip']
                record = all_ips_data[ip]
                
                f.write(f"{i}. IP: {ip}\n")
                f.write(f"   Anomalía Score: {anom['score']:.4f}\n")
                f.write(f"   Total paquetes: {anom['total']}\n")
                f.write(f"   TCP: {anom['tcp']}, UDP: {anom['udp']}\n")
                f.write(f"   Puertos únicos: {anom['port_count']}\n")
                f.write(f"   Tráfico promedio por puerto: {anom['avg_port_traffic']:.2f}\n")
                
                if record['top_ports']:
                    f.write(f"   Top 5 puertos:\n")
                    for port, count in record['top_ports']:
                        f.write(f"     - Puerto {port}: {count} paquetes\n")
                
                # Razón probable de anomalía
                reasons = []
                if anom['total'] > features['total'].quantile(0.75) * 2:
                    reasons.append("Tráfico excesivamente alto")
                if anom['port_count'] > features['port_count'].quantile(0.75) * 2:
                    reasons.append("Escaneo de múltiples puertos")
                if anom['udp'] > anom['tcp'] and anom['udp'] > features['udp'].quantile(0.75):
                    reasons.append("Tráfico UDP anómalo")
                
                if reasons:
                    f.write(f"   Razones probables:\n")
                    for reason in reasons:
                        f.write(f"     - {reason}\n")
                
                f.write("\n")
        else:
            f.write(f"NO SE DETECTARON ANOMALÍAS\n")
            f.write("-" * 80 + "\n")
            f.write("Todas las IPs presentan patrones normales de tráfico.\n\n")
        
        # IPs NORMALES (resumen)
        normal_indices = np.where(predictions == 0)[0]
        if len(normal_indices) > 0:
            f.write(f"\nIPs NORMALES ({len(normal_indices)})\n")
            f.write("-" * 80 + "\n")
            f.write("Top 10 IPs por tráfico total:\n\n")
            
            normal_data = [(all_records[idx]['ip'], all_records[idx]['total']) 
                          for idx in normal_indices]
            normal_data.sort(key=lambda x: x[1], reverse=True)
            
            for i, (ip, total) in enumerate(normal_data[:10], 1):
                record = all_ips_data[ip]
                f.write(f"{i}. {ip:18} | Total: {total:6d} | TCP: {record['tcp']:4d} | ")
                f.write(f"UDP: {record['udp']:4d} | Puertos: {record['port_count']:3d}\n")
        
        f.write("\n" + "=" * 80 + "\n")
        f.write("FIN DEL REPORTE\n")
        f.write("=" * 80 + "\n")
    
    print(f"\n✓ Reporte guardado en: {output_file}")
    
    # Mostrar resumen en pantalla
    print(f"\nRESUMEN:")
    print(f"  - IPs analizadas: {len(all_records)}")
    print(f"  - Anomalías detectadas: {(predictions == 1).sum()}")
    print(f"  - Porcentaje: {100 * (predictions == 1).sum() / len(predictions):.1f}%")

if __name__ == '__main__':
    pcap_dir = sys.argv[1] if len(sys.argv) > 1 else 'data/pcaps'
    max_files = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    generate_report(pcap_dir, max_files=max_files, output_file=output_file)
