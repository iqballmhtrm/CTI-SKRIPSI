#!/usr/bin/env bash
# =====================================================================
# system_readiness_check.sh — CHECKLIST KESIAPAN MASTER Lab CTI-ELK
# Jalankan DI SOC: bash system_readiness_check.sh <ELASTIC_PASSWORD>
# Lapisan: Topologi -> Layanan SOC -> Layanan Victim -> Attacker ->
#          Infrastruktur Respons -> ES/Pipeline/Deteksi -> Artefak hasil.
# Output [ OK ]/[FAIL] per item + ringkasan. READ-ONLY.
# =====================================================================
ESPASS="${1:-}"
VIC=192.168.56.106
ATK=192.168.56.110
ES="https://localhost:9200"
INDEX="cti-logs-iqbal-*"
PASS=0; FAIL=0; SKIP=0
SSHO="-o BatchMode=yes -o ConnectTimeout=6 -o StrictHostKeyChecking=no"
CT='Content-Type: application/json'

chk(){ if eval "$2" >/dev/null 2>&1; then echo "  [ OK ] $1"; PASS=$((PASS+1)); else echo "  [FAIL] $1"; FAIL=$((FAIL+1)); fi; }
esq(){ curl -s -k --connect-timeout 5 --max-time 20 -u "elastic:$ESPASS" "$@"; }
es_sid(){ esq "$ES/$INDEX/_count" -H "$CT" -d "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"data.alert.signature_id\":$1}},{\"range\":{\"@timestamp\":{\"gte\":\"now-24h\"}}}]}}}" | grep -qE '"count":[1-9]'; }
es_phrase(){ esq "$ES/$INDEX/_count" -H "$CT" -d "{\"query\":{\"match_phrase\":{\"rule.description\":\"$1\"}}}" | grep -qE '"count":[1-9]'; }
es_exists(){ esq "$ES/$INDEX/_count" -H "$CT" -d "{\"query\":{\"exists\":{\"field\":\"$1\"}}}" | grep -qE '"count":[1-9]'; }

echo "================ CHECKLIST KESIAPAN SISTEM CTI-ELK ================"
date

echo; echo "== 1. TOPOLOGI & KONEKTIVITAS =="
chk "Ping victim ($VIC)"   "ping -c1 -W2 $VIC"
chk "Ping attacker ($ATK)" "ping -c1 -W2 $ATK"
chk "SSH key SOC->victim"   "ssh $SSHO korban@$VIC true"
chk "SSH key SOC->attacker" "ssh $SSHO kali@$ATK true"

echo; echo "== 2. LAYANAN SOC =="
for s in elasticsearch kibana logstash soar-dashboard wazuh-manager filebeat; do
  chk "SOC: $s" "systemctl is-active --quiet $s"
done

echo; echo "== 3. LAYANAN VICTIM =="
for s in suricata filebeat wazuh-agent; do
  chk "Victim: $s" "ssh $SSHO korban@$VIC systemctl is-active --quiet $s"
done

echo; echo "== 4. ATTACKER TOOLS =="
chk "nmap"  "ssh $SSHO kali@$ATK command -v nmap"
chk "hydra" "ssh $SSHO kali@$ATK command -v hydra"
chk "nikto" "ssh $SSHO kali@$ATK command -v nikto"
chk "wordlist cti_small.txt" "ssh $SSHO kali@$ATK test -f /home/kali/cti_small.txt"

echo; echo "== 5. INFRASTRUKTUR RESPONS =="
chk "unblock script executable" "ssh $SSHO korban@$VIC test -x /usr/local/sbin/cti-unblock.sh"
chk "unblock NOPASSWD jalan"     "ssh $SSHO korban@$VIC sudo -n /usr/local/sbin/cti-unblock.sh"
chk "SOAR webhook hidup (:5000)" "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5000/ | grep -qE '200|302|401|404'"

echo; echo "== 6. ELASTICSEARCH / PIPELINE / DETEKSI (operasional) =="
if [ -z "$ESPASS" ]; then
  echo "  [SKIP] cek ES dilewati (tanpa password)."; SKIP=$((SKIP+7))
else
  chk "ES cluster green/yellow"          "esq $ES/_cluster/health | grep -qE 'green|yellow'"
  chk "Index $INDEX ada dokumen"          "esq \"$ES/$INDEX/_count\" | grep -qE '\"count\":[1-9]'"
  chk "Deteksi Nmap  (sid 1000010, 24j)"  "es_sid 1000010"
  chk "Deteksi Hydra (sid 1000020, 24j)"  "es_sid 1000020"
  chk "Deteksi Nikto (sid 1000030, 24j)"  "es_sid 1000030"
  chk "Respons firewall-drop (T2)"        "es_phrase 'Host Blocked by firewall-drop Active Response'"
  chk "Enrichment MITRE (technique_id)"   "es_exists 'mitre.technique_id'"
fi

echo; echo "== 7. ARTEFAK HASIL RISET =="
CSVF=/home/iqbal/research-archive/2026-06-21_controlled-run/iterations.csv
chk "iterations.csv ada"        "test -f $CSVF"
chk "data >= 30 iterasi"        "test \$(wc -l < $CSVF) -ge 31"

echo; echo "================ RINGKASAN: $PASS OK / $FAIL FAIL / $SKIP SKIP ================"
if [ "$FAIL" -eq 0 ]; then echo ">>> SISTEM SIAP DIOPERASIKAN <<<"; else echo ">>> ADA $FAIL ITEM PERLU DIPERIKSA <<<"; fi
