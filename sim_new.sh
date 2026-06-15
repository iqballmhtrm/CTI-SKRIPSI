#!/usr/bin/env bash
set -euo pipefail
LOG_FILE="/var/log/suricata/eve.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%6N+0000")
echo "{\"timestamp\":\"$TIMESTAMP\",\"event_type\":\"alert\",\"src_ip\":\"192.168.56.1\",\"dest_ip\":\"192.168.56.10\",\"alert\":{\"signature_id\":1000010,\"signature\":\"[CTI] Nmap SYN Stealth Scan Detected\"}}" | sudo tee -a "$LOG_FILE" > /dev/null
echo "{\"timestamp\":\"$TIMESTAMP\",\"event_type\":\"alert\",\"src_ip\":\"192.168.56.1\",\"dest_ip\":\"192.168.56.10\",\"alert\":{\"signature_id\":1000020,\"signature\":\"[CTI] Hydra SSH Brute Force Attempt\"}}" | sudo tee -a "$LOG_FILE" > /dev/null
echo "{\"timestamp\":\"$TIMESTAMP\",\"event_type\":\"alert\",\"src_ip\":\"192.168.56.1\",\"dest_ip\":\"192.168.56.10\",\"alert\":{\"signature_id\":1000030,\"signature\":\"[CTI] Nikto Web Scanner User-Agent Detected\"}}" | sudo tee -a "$LOG_FILE" > /dev/null
