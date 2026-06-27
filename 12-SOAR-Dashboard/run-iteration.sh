#!/bin/bash
# Script pengujian MTTD/MTTR - 1 iterasi
# Usage: ./run-iteration.sh <nomor_iterasi> <mode: manual|dashboard> <attack_type>
ITER=$1
MODE=$2
ATTACK=$3
ES_PASS=$(cat ~/.elastic_password)

echo "============================================"
echo " ITERASI ${ITER} | Mode: ${MODE} | Attack: ${ATTACK}"
echo "============================================"

T0=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
echo "[T0] Attack dimulai: ${T0}"

echo "[*] Menjalankan attack dari Kali (192.168.56.110)..."
if [ "$ATTACK" = "hydra" ]; then
    sshpass -p 'kali' ssh -o StrictHostKeyChecking=no kali@192.168.56.110 "timeout 30 hydra -I -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.56.106" &>/dev/null &
    ATTACK_PID=$!
    sleep 30
    kill $ATTACK_PID 2>/dev/null
elif [ "$ATTACK" = "nmap" ]; then
    sshpass -p 'kali' ssh -o StrictHostKeyChecking=no kali@192.168.56.110 "nmap -sS -T4 -p 1-200 192.168.56.106" &>/dev/null
fi
echo "[*] Attack selesai"

echo "[*] Menunggu pipeline (45 detik)..."
sleep 45

T1=$(curl -sk -u elastic:${ES_PASS} \
  "https://localhost:9200/cti-logs-iqbal-*/_search" \
  -H 'Content-Type: application/json' \
  -d "{\"size\":1,\"sort\":[{\"@timestamp\":\"asc\"}],\"query\":{\"bool\":{\"must\":[{\"range\":{\"@timestamp\":{\"gte\":\"${T0}\"}}},{\"match\":{\"event_type\":\"alert\"}}]}}}" | \
  python3 -c "import json,sys; d=json.load(sys.stdin); hits=d.get('hits',{}).get('hits',[]); print(hits[0]['_source']['@timestamp'] if hits else 'NOT_FOUND')")
echo "[T1] Alert pertama: ${T1}"

if [ "$MODE" = "dashboard" ]; then
    echo "[*] Mitigasi via SOAR Dashboard API..."
    # Get the latest New incident for this IP
    INC_ID=$(curl -s http://127.0.0.1:5000/api/incidents | python3 -c "
import sys, json
data = json.load(sys.stdin)
for inc in data.get('incidents', []):
    if inc['status'] == 'New' and inc['src_ip'] == '192.168.56.110':
        print(inc['id'])
        sys.exit(0)
print('NOT_FOUND')
")
    
    if [ "$INC_ID" != "NOT_FOUND" ] && [ ! -z "$INC_ID" ]; then
        echo "    Ditemukan Incident ID: $INC_ID"
        curl -s -X POST http://127.0.0.1:5000/action/block-ip -H "Content-Type: application/json" -d "{\"incident_id\": $INC_ID, \"src_ip\": \"192.168.56.110\"}" > /dev/null
    else
        echo "    GAGAL: Incident tidak ditemukan di SOAR!"
    fi
else
    echo "[*] Mitigasi Manual via SSH..."
    ssh -o BatchMode=yes iqbal@192.168.56.10 "ssh -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o BatchMode=yes korban@192.168.56.106 'echo 123123 | sudo -S iptables -A INPUT -s 192.168.56.110 -j DROP'" 2>/dev/null
fi
T2=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
echo "[T2] Mitigasi selesai: ${T2}"

echo ""
echo "=== HASIL ==="
python3 -c "
from datetime import datetime
fmt = '%Y-%m-%dT%H:%M:%S.%f'
t0 = datetime.strptime('${T0}'.rstrip('Z'), fmt)
t1_str = '${T1}'
t2 = datetime.strptime('${T2}'.rstrip('Z'), fmt)
if t1_str != 'NOT_FOUND':
    t1 = datetime.strptime(t1_str[:26], fmt)
    mttd = (t1 - t0).total_seconds()
else:
    mttd = -1
mttr = (t2 - t0).total_seconds()
print(f'  MTTD: {mttd:.2f} detik')
print(f'  MTTR: {mttr:.2f} detik')
"

echo "[*] Menyimpan hasil ke cti-mttd-mttr-iqbal..."
curl -sk -u elastic:${ES_PASS} \
  -X POST "https://localhost:9200/cti-mttd-mttr-iqbal/_doc" \
  -H 'Content-Type: application/json' \
  -d "{\"iteration\":${ITER},\"mode\":\"${MODE}\",\"attack_type\":\"${ATTACK}\",\"t0\":\"${T0}\",\"t1\":\"${T1}\",\"t2\":\"${T2}\",\"timestamp\":\"${T0}\"}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  Saved: {d.get(\"result\",\"?\")}')"

echo "[*] Cleanup iptables..."
ssh -o BatchMode=yes iqbal@192.168.56.10 "ssh -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o BatchMode=yes korban@192.168.56.106 'echo 123123 | sudo -S iptables -D INPUT -s 192.168.56.110 -j DROP'" 2>/dev/null
echo "=== ITERASI ${ITER} SELESAI ==="
