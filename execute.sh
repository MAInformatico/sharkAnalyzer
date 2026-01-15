python3 -m venv venv;
echo 'activamos venv';
source venv/bin/activate;
echo 'actualizamos';
pip install -r requirements.txt
#After that, just execute: python3 generate_anomaly_report.py pcap 3