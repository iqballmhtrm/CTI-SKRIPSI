echo '--- Phase 1: Backup ---'
cp /etc/suricata/suricata.yaml /home/iqbal/suricata.yaml.bak
cp /etc/suricata/rules/custom.rules /home/iqbal/custom.rules.bak 2>/dev/null || echo 'No custom.rules to backup'
cp /etc/logstash/dictionaries/mitre-mapping.yml /home/iqbal/mitre-mapping.yml.bak
cp /etc/logstash/dictionaries/mitre-id-to-name.yml /home/iqbal/mitre-id-to-name.yml.bak

echo '--- Phase 2: Inject custom.rules ---'
cat << 'RULE' > /etc/suricata/rules/custom.rules
alert tcp any any -> \ any (msg:"LOCAL NMAP SYN Scan Detected"; flags:S,12; threshold:type both, track by_src, count 50, seconds 5; classtype:attempted-recon; sid:1000010; rev:1; metadata: mitre_tactic_name Discovery, mitre_technique_name Network_Service_Scanning, mitre_technique_id T1046;)
alert tcp any any -> \ 22 (msg:"LOCAL HYDRA SSH Brute Force Attempt"; flags:S,12; threshold:type both, track by_src, count 10, seconds 10; classtype:attempted-admin; sid:1000020; rev:1; metadata: mitre_tactic_name Credential_Access, mitre_technique_name Brute_Force, mitre_technique_id T1110;)
alert http any any -> \ any (msg:"LOCAL NIKTO Web Scanner Detected"; flow:established,to_server; content:"Nikto"; http_user_agent; nocase; classtype:web-application-attack; sid:1000030; rev:1; metadata: mitre_tactic_name Reconnaissance, mitre_technique_name Active_Scanning, mitre_technique_id T1595;)
RULE

echo '--- Phase 3: Add to suricata.yaml ---'
if ! grep -q 'custom.rules' /etc/suricata/suricata.yaml; then
  sed -i '/rule-files:/a \ \ - custom.rules' /etc/suricata/suricata.yaml
fi

echo '--- Phase 4: Add MITRE mappings ---'
if ! grep -q '1000010' /etc/logstash/dictionaries/mitre-mapping.yml; then
  echo '"1000010": "T1046"' >> /etc/logstash/dictionaries/mitre-mapping.yml
  echo '"1000020": "T1110"' >> /etc/logstash/dictionaries/mitre-mapping.yml
  echo '"1000030": "T1595"' >> /etc/logstash/dictionaries/mitre-mapping.yml
fi

echo '--- Phase 5: Add MITRE names ---'
if ! grep -q 'T1046' /etc/logstash/dictionaries/mitre-id-to-name.yml; then
  echo '"T1046": "Network Service Scanning"' >> /etc/logstash/dictionaries/mitre-id-to-name.yml
  echo '"T1110": "Brute Force"' >> /etc/logstash/dictionaries/mitre-id-to-name.yml
  echo '"T1595": "Active Scanning"' >> /etc/logstash/dictionaries/mitre-id-to-name.yml
fi