#!/usr/bin/env bash
set -euo pipefail

# Skrip Simulasi Serangan / Injeksi Log Suricata
# Menguji pemetaan MITRE di Logstash secara real-time

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <elastic_password>" >&2
  exit 1
fi

ES_PASS="$1"
LOG_FILE="/var/log/suricata/eve.json"
SID="2013504"
# Format timestamp Suricata ISO8601
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%6N+0000")

echo "[+] Menginjeksi mock log Suricata (SID: $SID) ke $LOG_FILE..."

# Membuat payload JSON yang menyerupai log asli Suricata (eve.json)
MOCK_LOG="{\"timestamp\":\"$TIMESTAMP\",\"event_type\":\"alert\",\"src_ip\":\"10.10.10.99\",\"src_port\":4444,\"dest_ip\":\"192.168.56.10\",\"dest_port\":80,\"proto\":\"TCP\",\"alert\":{\"action\":\"allowed\",\"gid\":1,\"signature_id\":$SID,\"rev\":1,\"signature\":\"Simulasi Serangan - CTI Skripsi (SID $SID)\",\"category\":\"Misc activity\",\"severity\":1}}"

echo "$MOCK_LOG" | sudo tee -a "$LOG_FILE" > /dev/null

echo "[+] Log berhasil ditulis. Menunggu 5 detik agar Logstash memproses data..."
sleep 5

echo "[+] Meminta hasil langsung dari Elasticsearch..."
curl -s -k -u "elastic:$ES_PASS" "https://localhost:9200/cti-logs-iqbal-*/_search" \
  -H 'Content-Type: application/json' \
  -d "{
    \"size\": 1,
    \"query\": {
      \"bool\": {
        \"must\": [
          { \"term\": { \"alert.signature_id\": $SID } }
        ],
        \"filter\": [ { \"range\": { \"@timestamp\": { \"gte\": \"now-1m\" } } } ]
      }
    },
    \"_source\": [\"@timestamp\", \"alert.signature_id\", \"alert.signature\", \"mitre\"]
  }" | jq .

echo "[+] Simulasi Selesai."