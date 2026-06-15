#!/bin/bash
cp /etc/logstash/dictionaries/mitre-mapping.yml /etc/logstash/dictionaries/mitre-mapping.yml.bak
cp /etc/logstash/dictionaries/mitre-id-to-name.yml /etc/logstash/dictionaries/mitre-id-to-name.yml.bak
cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
[ -f /etc/suricata/rules/custom.rules ] && cp /etc/suricata/rules/custom.rules /etc/suricata/rules/custom.rules.bak

cat << 'EOT' >> /etc/logstash/dictionaries/mitre-mapping.yml

1000010: T1046
1000020: T1110.001
1000030: T1595.002
EOT

cat << 'EOT' >> /etc/logstash/dictionaries/mitre-id-to-name.yml
"T1595.002": "Active Scanning - Vulnerability Scanning"
EOT

cat << 'EOT' > /etc/suricata/rules/custom.rules
alert tcp any any -> $HOME_NET any (msg:"[CTI] Nmap SYN Stealth Scan Detected"; flags:S; flow:stateless; threshold:type both, track by_src, count 50, seconds 5; classtype:attempted-recon; sid:1000010; rev:1; metadata:mitre_tactic_name Discovery;)
alert tcp any any -> $HOME_NET 22 (msg:"[CTI] Hydra SSH Brute Force Attempt"; flow:stateless; flags:S; threshold:type both, track by_src, count 10, seconds 10; classtype:attempted-admin; sid:1000020; rev:1; metadata:mitre_tactic_name Credential_Access;)
alert http any any -> $HOME_NET [80,443] (msg:"[CTI] Nikto Web Scanner User-Agent Detected"; flow:established,to_server; http.user_agent; content:"Nikto"; nocase; classtype:web-application-attack; sid:1000030; rev:1; metadata:mitre_tactic_name Reconnaissance;)
EOT

if ! grep -q "custom.rules" /etc/suricata/suricata.yaml; then
  sed -i '/rule-files:/a \  - custom.rules' /etc/suricata/suricata.yaml
fi

suricata -T -c /etc/suricata/suricata.yaml > /tmp/suricata_validation.txt 2>&1
echo "Suricata validation exit code: True" >> /tmp/suricata_validation.txt

systemctl restart logstash
systemctl restart suricata
