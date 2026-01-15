#!/usr/bin/env python3
"""
Generate a CSV report of anomalies detected in .pcap files using a trained AnomalyAgent.

USO:
    python generate_csv_report.py [pcap folder] [max_files] [output_file]

Examples:
    python generate_csv_report.py                           # genera anomalies.csv
    python generate_csv_report.py data/pcaps 5 my_report.csv
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
    """Loading .pcap files"""
    all_records = []
    file_count = 0
    
    if not os.path.isdir(pcap_dir):
        return all_records, file_count
    
    pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith('.pcap')]
    
    if max_files and len(pcap_files) > max_files:
        pcap_files = sorted(pcap_files)[:max_files]
    
    for pcap_file in sorted(pcap_files):
        filepath = os.path.join(pcap_dir, pcap_file)
        try:
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
                        'avg_port_traffic': sum(data['ports'].values()) / max(len(data['ports']), 1)
                    }
                    all_records.append(record)
                
                file_count += 1
        except:
            continue
    
    return all_records, file_count

def generate_csv_report(pcap_dir, max_files=5, output_file=None):
    """Generate a CSV report with anomalies detected."""
    
    if not output_file:
        output_file = f"anomalies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    print(f"[1] Loading .pcap files...")
    all_records, file_count = load_pcap_data(pcap_dir, max_files=max_files)
    
    if not all_records:
        print("No data extracted.")
        return

    print(f"[2] Extracting features...")
    features = extract_features_from_records(all_records)

    print(f"[3] Loading trained agent...")
    agent_path = 'models/anomaly_agent.pkl'
    
    if not os.path.exists(agent_path):
        print(f"Error: No model found at {agent_path}")
        return
    
    agent = AnomalyAgent()
    agent.load(agent_path)

    print(f"[4] Detecting anomalies...")
    predictions = agent.predict(features)
    scores = agent.score_samples(features)

    print(f"[5] Generating CSV...")
    # Create DataFrame with results
    df = pd.DataFrame(all_records)
    df['anomaly_score'] = scores
    df['is_anomaly'] = predictions
    df['anomaly_label'] = df['is_anomaly'].map({1: 'ANÓMALO', 0: 'NORMAL'})
    
    # Reorder columns
    df = df[['ip', 'total', 'tcp', 'udp', 'port_count', 'avg_port_traffic', 
             'anomaly_score', 'is_anomaly', 'anomaly_label']]
    
    # Order by anomaly score (most anomalous first)
    df = df.sort_values('anomaly_score')
    
    # Save CSV
    df.to_csv(output_file, index=False)
    
    print(f"\n✓ CSV saved in: {output_file}")
    
    # Show summary
    print(f"\nSUMMARY:")
    print(f"  - Total IPs: {len(df)}")
    print(f"  - Anomalies: {(df['is_anomaly'] == 1).sum()}")
    print(f"  - Normal: {(df['is_anomaly'] == 0).sum()}")
    
    # Show first anomalies
    anomalies = df[df['is_anomaly'] == 1]
    if len(anomalies) > 0:
        print(f"\nTOP ANOMALIES:")
        print(anomalies[['ip', 'total', 'port_count', 'anomaly_score', 'anomaly_label']].to_string(index=False))

if __name__ == '__main__':
    pcap_dir = sys.argv[1] if len(sys.argv) > 1 else 'data/pcaps'
    max_files = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    generate_csv_report(pcap_dir, max_files=max_files, output_file=output_file)
