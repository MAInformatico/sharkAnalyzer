import time
from config import *
from parser import parse_pcap
from baseline import load_baseline, save_baseline
from anomaly import detect_anomalies

def main():
    baseline = load_baseline(BASELINE_FILE)

    for pcap in sorted(os.listdir(PCAP_DIR)):
        stats = parse_pcap(f"{PCAP_DIR}/{pcap}", MI_IP)

        if not baseline:
            save_baseline(stats, BASELINE_FILE)
            print("Baseline created")
            return

        alerts = detect_anomalies(stats, baseline, globals())

        if alerts:
            with open("data/alerts.log", "a") as f:
                for alert in alerts:
                    print(alert)
                    f.write(alert + "\n")

if __name__ == "__main__":
    main()