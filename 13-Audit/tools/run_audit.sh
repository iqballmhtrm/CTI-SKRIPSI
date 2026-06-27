#!/bin/bash
echo "=== BAGIAN A: JARINGAN DAN TOPOLOGI ==="
echo "--- SOC-SERVER ---"
ip addr show
hostname
uptime
ping -c 1 192.168.56.106 || echo "192.168.56.106 Host Unreachable"
ping -c 1 192.168.56.105 || echo "192.168.56.105 Host Unreachable"

echo "--- VICTIM-NODE (192.168.56.106) ---"
ssh -o BatchMode=yes -o StrictHostKeyChecking=no iqbal@192.168.56.106 "ip addr show; hostname; uptime" || echo "Failed to SSH to 192.168.56.106"

echo "--- ATTACKER-NODE (192.168.56.105) ---"
ssh -o BatchMode=yes -o StrictHostKeyChecking=no iqbal@192.168.56.105 "ip addr show; hostname; uptime" || echo "Failed to SSH to 192.168.56.105"

echo "=== BAGIAN B: ELASTICSEARCH GROUND TRUTH ==="
PASS=$(sudo grep "elasticsearch.password" /etc/kibana/kibana.yml | grep -o '\"[^\"]*\"' | tr -d '"' || echo "")
if [ -z "$PASS" ]; then
    PASS="iqbal"
fi

echo "[1] Indices List:"
curl -s -X GET "http://localhost:9200/_cat/indices?v" || curl -k -s -X GET "https://localhost:9200/_cat/indices?v" -u elastic:$PASS

echo "[2] CTI/SOC Index Count:"
curl -s -X GET "http://localhost:9200/cti-logs-*/_count" || curl -k -s -X GET "https://localhost:9200/cti-logs-*/_count" -u elastic:$PASS
echo ""
echo "[3] CTI/SOC Index Mapping:"
curl -s -X GET "http://localhost:9200/cti-logs-*/_mapping?pretty" || curl -k -s -X GET "https://localhost:9200/cti-logs-*/_mapping?pretty" -u elastic:$PASS

echo "[4] ILM Policy:"
curl -s -X GET "http://localhost:9200/_ilm/policy?pretty" || curl -k -s -X GET "https://localhost:9200/_ilm/policy?pretty" -u elastic:$PASS

echo "[5] Transform:"
curl -s -X GET "http://localhost:9200/_transform?pretty" || curl -k -s -X GET "https://localhost:9200/_transform?pretty" -u elastic:$PASS

echo "=== BAGIAN C: LOGSTASH GROUND TRUTH ==="
echo "[1] Contents of /etc/logstash/conf.d/*.conf:"
sudo cat /etc/logstash/conf.d/*.conf || echo "No conf files"

echo "[2] Check GeoIP:"
sudo grep -i geoip /etc/logstash/conf.d/*.conf

echo "[3] Check MITRE:"
sudo grep -i mitre /etc/logstash/conf.d/*.conf

echo "[4] Check Pyramid of Pain:"
sudo grep -ri "pyramid" /etc/logstash/conf.d/ /etc/logstash/ || echo "No pyramid found"

echo "[5] Check Ruby:"
sudo grep -i "ruby" /etc/logstash/conf.d/*.conf

echo "[6] Systemctl status logstash:"
systemctl status logstash --no-pager || echo "Logstash service check failed"

echo "=== BAGIAN D: SOAR APP GROUND TRUTH ==="
echo "[1] SOAR process path:"
ps aux | grep soar_app | grep -v grep

echo "[2] soar_app.py contents:"
cat /home/iqbal/soar-dashboard/app/soar_app.py || echo "soar_app.py not found"

echo "[3] SQLite Schema:"
python3 -c "import sqlite3; c=sqlite3.connect('/home/iqbal/soar-dashboard/app/incidents.db'); print(list(c.execute(\"SELECT sql FROM sqlite_master WHERE type='table'\")))" || echo "Schema failed"

echo "[4] SQLite Count:"
python3 -c "import sqlite3; c=sqlite3.connect('/home/iqbal/soar-dashboard/app/incidents.db'); print(c.execute('SELECT COUNT(*) FROM incidents').fetchone()[0])" || echo "Count failed"

echo "[5] Execution method:"
cat /etc/systemd/system/soar.service 2>/dev/null || echo "No SOAR service file"

echo "=== BAGIAN E: SURICATA & WAZUH ==="
echo "[1] Custom rules on VICTIM-NODE:"
ssh -o BatchMode=yes -o StrictHostKeyChecking=no iqbal@192.168.56.106 "sudo cat /etc/suricata/rules/custom.rules" || echo "Failed to read custom.rules"

echo "[2] Suricata test on VICTIM-NODE:"
ssh -o BatchMode=yes -o StrictHostKeyChecking=no iqbal@192.168.56.106 "sudo suricata -T -c /etc/suricata/suricata.yaml" || echo "Failed Suricata test"

echo "[3] Wazuh agent status:"
sudo /var/ossec/bin/agent_control -l || echo "Wazuh control failed"

echo "[4] mitre-mapping.yml contents:"
sudo cat /etc/logstash/mitre-mapping.yml || echo "mitre-mapping.yml not found"
