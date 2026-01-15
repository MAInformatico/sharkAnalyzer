from scapy.all import PcapReader, IP, TCP, UDP
from collections import defaultdict

def parse_pcap(filepath, my_ip):
    stats = defaultdict(lambda: {
        "total": 0,
        "tcp": 0,
        "udp": 0,
        "ports": defaultdict(int)
    })

    with PcapReader(filepath) as pcap:
        for pkt in pcap:
            if IP not in pkt:
                continue

            ip = None
            if pkt[IP].src == my_ip:
                ip = pkt[IP].dst
            elif pkt[IP].dst == my_ip:
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

    return stats