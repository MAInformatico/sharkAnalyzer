# sharkAnalyzer

Advanced network traffic analysis tool with anomaly detection using:

- **Traditional detection**: Comparison against a baseline of normal traffic
- **AI detection**: Agent based on Isolation Forest for complex patterns

## Installation

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```
## Usage
### 1. Create baseline and run basic analysis
```bash
# First analysis (creates baseline automatically)
python main.py

# Subsequent analyses will detect anomalies against the baseline
python main.py
```
### 2. Generate test .pcap files (optional)
```bash
# Creates 3 .pcap files with normal and anomalous traffic in data/pcaps/
python generate_test_pcaps.py
```
### 3. Train AI agent with .pcap files
```bash
# Train the agent by reading .pcap files from a folder
python demo_agent_training.py data/pcaps

# Optionally limit to N files (default: 5)
python demo_agent_training.py data/pcaps 10

# Or use the default folder (PCAP_DIR in config.py)
python demo_agent_training.py
# The model is saved to: models/anomaly_agent.pkl
```
Note: For very large .pcap files, the script processes a maximum of 10,000 packets per file to avoid memory exhaustion.

### 4. Use trained agent in real-time analysis
```bash
# Analyze new pcaps using the trained agent
python main.py train  # Retrain with new data if needed
```
## Example Output
### Fragment from data/alerts.log after running python main.py:
```
[2026-01-15 10:23:41] ANOMALY DETECTED (baseline): IP 192.168.1.47 — packet count 4820 (baseline avg: 320)
[2026-01-15 10:23:41] ANOMALY DETECTED (AI agent): IP 192.168.1.47 — port_count 187 (unusual scanning pattern)
[2026-01-15 10:23:42] ANOMALY DETECTED (AI agent): IP 10.0.0.12 — avg_port_traffic 0.03 (low-volume probing)
[2026-01-15 10:23:42] No anomalies detected for 192.168.1.10 (normal traffic)
```
### Fragment from data/anomaly_report.csv:
```csv
ip,total,tcp,udp,port_count,avg_port_traffic,is_anomaly
192.168.1.47,4820,4700,120,187,25.8,1
10.0.0.12,340,300,40,95,3.6,1
192.168.1.10,318,290,28,12,26.5,0
```
## How the AnomalyAgent works
The agent uses Isolation Forest (an unsupervised algorithm) to detect anomalies based on statistical patterns:

### Features used:
- total: Total packets per IP
- tcp: Number of TCP packets
- udp: Number of UDP packets
- port_count: Number of unique ports contacted
- avg_port_traffic: Average traffic per port

### Flow in main.py:
1. **Parse PCAP**: parse_pcap() extracts traffic statistics
2. **Convert to records**: stats_to_records() generates dicts with features
3. **Extract features**: extract_features_from_records() creates a numeric DataFrame
4. **Predict**: agent.predict() returns 1 (anomalous) or 0 (normal)
5. **Log alerts**: Anomalies are written to data/alerts.log

### Key files:
- anomaly_agent.py: AnomalyAgent class with fit/predict/save/load methods
- main.py: Main flow integrating traditional detection + AI
- demo_agent_training.py: Reads .pcap files from a folder and trains the agent
- generate_test_pcaps.py: Generates test .pcap files with normal + anomalous traffic
- config.py: Configuration with paths (MI_IP, PCAP_DIR, BASELINE_FILE)
- models/anomaly_agent.pkl: Trained model (created after running demo_agent_training.py)
- test/: Unit tests for parser, feature extraction, and agent prediction. Run with pytest.

**Evaluation**: See Results for detection metrics on synthetic test data.

## Design Decisions

**Isolation Forest over autoencoders or clustering**
Isolation Forest was chosen because it works unsupervised, scales well with small datasets, has low training cost, and produces interpretable results. Autoencoders require more data and tuning; DBSCAN is sensitive to density parameters and does not scale as cleanly.

**Dual detection: baseline + AI**
The baseline catches obvious deviations from normal traffic (e.g., a new IP with unusually high packet count). The Isolation Forest agent catches complex patterns that the baseline misses (e.g., port scanning behavior distributed across multiple IPs). Combining both reduces false negatives without flooding alerts.

**Feature selection**
Features (total, tcp, udp, port_count, avg_port_traffic) were chosen to capture both volume anomalies and behavioral anomalies (port scanning, unusual protocol mix). port_count is a strong signal for scanning activity; avg_port_traffic helps distinguish heavy legitimate traffic from targeted probing.

**Model persistence**
The trained model is saved as models/anomaly_agent.pkl to avoid retraining on every run. Retraining can be triggered manually with python main.py train.

**Memory limit for large PCAPs**
Processing is capped at 10,000 packets per file to avoid memory exhaustion. For production use, streaming ingestion (e.g., Kafka/Kinesis) with windowed feature aggregation would be the natural next step.

## Results
Evaluated on 3 synthetic PCAP files generated with generate_test_pcaps.py (1 normal baseline, 2 anomalous):

| Metric | Value |
| :----------- | :----------: |
| Anomalous IPs detected | 2 / 2 |
| False positives | 0 |
| Precision | 1.00 |
| Recall | 1.00 |
| F1 Score | 1.00 |

**Note**: This is a small synthetic sample intended to validate the pipeline, not a statistically significant benchmark. Real-world evaluation would require labeled production traffic and cross-validation across time windows.

## Typical workflow

1. Place .pcap files → data/pcaps/
2. Run: python demo_agent_training.py data/pcaps [max_files]
3. Verify model at: models/anomaly_agent.pkl
4. Use in real time: python main.py

The agent automatically:

- Reads .pcap files from the specified folder
- Extracts IPs and traffic statistics (total, TCP, UDP, unique ports)
- Detects anomalous patterns (IPs with unusual traffic, port scanning, etc.)
- Generates combined alerts with traditional detection

## Configuration
Edit `config.py`:

- **MI_IP**: Your network IP address (must match the one in the pcaps)
- **PCAP_DIR**: Folder with .pcap files (default: `data/pcaps`)
- **BASELINE_FILE**: JSON file with normal traffic (default: `data/baseline.json`)
