#!/usr/bin/env bash
set -euo pipefail

# Skrip Injeksi Serangan Massal (Nmap, Hydra, Nikto)


LOG_FILE="/var/log/suricata/eve.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%6N+0000")

echo "[+] Menginjeksi 3 serangan simulasi CTI-LAB ke Suricata..."

# 1. Nmap (9000001) - T1046
echo "{\"timestamp\":\"$TIMESTAMP\",\"event_type\":\"alert\",\"src_ip\":\"10.10.10.99\",\"dest_ip\":\"192.168.56.10\",\"alert\":{\"signature_id\":9000001,\"signature\":\"CTI-LAB Port Scan SYN\"}}" | sudo tee -a "$LOG_FILE" > /dev/null

# 2. Hydra (9000002) - T1110.001
echo "{\"timestamp\":\"$TIMESTAMP\",\"event_type\":\"alert\",\"src_ip\":\"10.10.10.99\",\"dest_ip\":\"192.168.56.10\",\"alert\":{\"signature_id\":9000002,\"signature\":\"CTI-LAB SSH Connection Attempt\"}}" | sudo tee -a "$LOG_FILE" > /dev/null

# 3. Nikto (9000004) - T1595
echo "{\"timestamp\":\"$TIMESTAMP\",\"event_type\":\"alert\",\"src_ip\":\"10.10.10.99\",\"dest_ip\":\"192.168.56.10\",\"alert\":{\"signature_id\":9000004,\"signature\":\"CTI-LAB Nikto Web Scan\"}}" | sudo tee -a "$LOG_FILE" > /dev/null

echo "[+] Berhasil diinjeksi! Menunggu 5 detik agar Logstash bekerja..."
sleep 5

echo "[+] Selesai. Silakan buka Dashboard Anda dan atur filter waktu ke 'Last 15 minutes' atau 'Today'."