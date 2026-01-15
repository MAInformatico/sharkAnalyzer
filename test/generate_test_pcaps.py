#!/usr/bin/env python3

from scapy.all import IP, TCP, UDP, wrpcap
import random

def generate_test_pcaps(output_dir='data/pcaps', num_files=3):
    """
    Generate .pcap test files with traffic patterns.
    
    Args:
        output_dir: folder to store pcaps
        num_files: number of files to generate
    """
    print(f"Generating {num_files} .pcap test files in '{output_dir}'...\n")
    
    local_ip = "192.168.1.100"  # Your IP (MI_IP in config)
    
    for file_num in range(num_files):
        packets = []
        filename = f"{output_dir}/test_traffic_{file_num + 1:02d}.pcap"
                
        normal_ips = [f"192.168.1.{i}" for i in range(10, 20)]
        for ip in normal_ips:
            for port in [80, 443, 22, 53]:
                for _ in range(random.randint(5, 15)):
                    pkt = IP(src=local_ip, dst=ip)
                    if port in [80, 443, 22]:
                        pkt = pkt / TCP(dport=port)
                    else:
                        pkt = pkt / UDP(dport=port)
                    packets.append(pkt)
        
        # anormal traffic: suspicious IP with many ports and packets
        if file_num == 1:  
            anomaly_ip = "10.0.0.100"
            for port in range(1000, 1050):  # multiple ports
                for _ in range(random.randint(20, 30)):  # many packets
                    pkt = IP(src=local_ip, dst=anomaly_ip) / TCP(dport=port)
                    packets.append(pkt)
        
        # Store file
        wrpcap(filename, packets)
        print(f"✓ Created: {filename} ({len(packets)} packets)")
    
    print(f"\nFiles generated in '{output_dir}'")
    print("Now you can run: python demo_agent_training.py data/pcaps")

if __name__ == '__main__':
    generate_test_pcaps()
