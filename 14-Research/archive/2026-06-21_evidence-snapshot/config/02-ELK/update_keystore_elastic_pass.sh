#!/bin/bash
# ============================================================
# Script: update_keystore_elastic_pass.sh
# Tujuan: Update ELASTIC_PASS di Logstash keystore (step 29/30)
# Jalankan di SOC-SERVER via SSH sebagai user dengan sudo
# ============================================================

set -e
echo "=================================================="
echo " [1/4] Tambah ELASTIC_PASS ke Logstash keystore"
echo "=================================================="
echo ""
echo "Pilihan A - Interaktif (masukkan password saat diminta):"
echo "  sudo /usr/share/logstash/bin/logstash-keystore add --path.settings /etc/logstash ELASTIC_PASS"
echo ""
echo "Pilihan B - Non-interaktif (ganti NEW_ELASTIC_PASSWORD dengan password asli):"
echo "  printf '%s' 'NEW_ELASTIC_PASSWORD' | sudo /usr/share/logstash/bin/logstash-keystore add --path.settings /etc/logstash --stdin ELASTIC_PASS"
echo ""
read -p "Tekan ENTER setelah selesai menambah keystore..."

echo ""
echo "=================================================="
echo " [2/4] Set ownership & permission keystore"
echo "=================================================="
sudo chown logstash:logstash /etc/logstash/logstash.keystore
sudo chmod 660 /etc/logstash/logstash.keystore
echo "OK: /etc/logstash/logstash.keystore => logstash:logstash 660"

echo ""
echo "=================================================="
echo " [3/4] Test konfigurasi Logstash"
echo "=================================================="
sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash --config.test_and_exit
echo ""
echo "Restart Logstash..."
sudo systemctl restart logstash
echo "Menunggu 10 detik agar Logstash startup..."
sleep 10
echo ""
echo "--- journalctl tail (80 baris terakhir) ---"
sudo journalctl -u logstash -n 120 --no-pager | tail -n 80

echo ""
echo "=================================================="
echo " [4/4] Verifikasi koneksi ke Elasticsearch"
echo "=================================================="
read -s -p "Masukkan password user 'elastic' untuk verifikasi cURL: " VERIFY_PASS
echo ""

echo ">> _authenticate:"
curl -s -k -u elastic:"$VERIFY_PASS" 'https://localhost:9200/_security/_authenticate?pretty'

echo ""
echo ">> Count alert tanpa mitre.technique_id:"
curl -s -k -u elastic:"$VERIFY_PASS" \
  'https://localhost:9200/cti-logs-iqbal-*/_count' \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"must":[{"match":{"event_type":"alert"}}],"must_not":[{"exists":{"field":"mitre.technique_id"}}]}}}' \
  | python3 -m json.tool 2>/dev/null || \
  curl -s -k -u elastic:"$VERIFY_PASS" \
  'https://localhost:9200/cti-logs-iqbal-*/_count' \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"must":[{"match":{"event_type":"alert"}}],"must_not":[{"exists":{"field":"mitre.technique_id"}}]}}}'

echo ""
echo "=================================================="
echo " SELESAI - Step 29/30 Update Keystore ELASTIC_PASS"
echo "=================================================="
