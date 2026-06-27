#!/bin/bash
echo "=== BAGIAN C: LOGSTASH GROUND TRUTH ==="
echo "[1] Contents of /etc/logstash/conf.d/*.conf:"
echo "iqbal" | sudo -S cat /etc/logstash/conf.d/*.conf || echo "No conf files"

echo "[2] Check GeoIP:"
echo "iqbal" | sudo -S grep -i geoip /etc/logstash/conf.d/*.conf

echo "[3] Check MITRE:"
echo "iqbal" | sudo -S grep -i mitre /etc/logstash/conf.d/*.conf

echo "[4] Check Pyramid of Pain:"
echo "iqbal" | sudo -S grep -ri "pyramid" /etc/logstash/conf.d/ /etc/logstash/ || echo "No pyramid found"

echo "[5] Check Ruby:"
echo "iqbal" | sudo -S grep -i "ruby" /etc/logstash/conf.d/*.conf

echo "=== BAGIAN E: SURICATA & WAZUH ==="
echo "[1] Custom rules on VICTIM-NODE:"
sshpass -p "iqbal" ssh -o StrictHostKeyChecking=no iqbal@192.168.56.106 "echo 'iqbal' | sudo -S cat /etc/suricata/rules/custom.rules" || echo "Failed to read custom.rules"

echo "[2] Suricata test on VICTIM-NODE:"
sshpass -p "iqbal" ssh -o StrictHostKeyChecking=no iqbal@192.168.56.106 "echo 'iqbal' | sudo -S suricata -T -c /etc/suricata/suricata.yaml" || echo "Failed Suricata test"

echo "[3] Wazuh agent status:"
echo "iqbal" | sudo -S /var/ossec/bin/agent_control -l || echo "Wazuh control failed"

echo "[4] mitre-mapping.yml contents:"
echo "iqbal" | sudo -S cat /etc/logstash/mitre-mapping.yml || echo "mitre-mapping.yml not found"
