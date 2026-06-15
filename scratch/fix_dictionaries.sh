#!/bin/bash
# Fix mitre-mapping.yml — remove duplicates, keep correct values

cat > /etc/logstash/dictionaries/mitre-mapping.yml << 'ENDOFFILE'
# MITRE mapping for Logstash translate plugin
# SID -> MITRE Technique ID
# Deployed: 2026-06-16

# Emerging Threats built-in rules
"2013504": "T1105"
"2033966": "T1102"
"2033967": "T1102"

# Suricata built-in protocol decode rules mapped to Nmap
"2200121": "T1046"
"2200025": "T1046"

# CTI-LAB Custom Rules
"1000010": "T1046"
"1000020": "T1110.001"
"1000030": "T1595.002"
ENDOFFILE

echo "[OK] mitre-mapping.yml fixed"

# Fix mitre-id-to-name.yml — ensure sub-techniques are mapped
cat > /etc/logstash/dictionaries/mitre-id-to-name.yml << 'ENDOFFILE'
# MITRE Technique ID -> Human-readable name
# Deployed: 2026-06-16

"T1046": "Network Service Discovery"
"T1105": "Ingress Tool Transfer"
"T1102": "Web Service"
"T1110": "Brute Force"
"T1110.001": "Brute Force - Password Guessing"
"T1595": "Active Scanning"
"T1595.002": "Gather Victim Host Information - Hardware"
"T1071.001": "Application Layer Protocol - Web Protocols"
"T1095": "Non-Application Layer Protocol"
"T1041": "Exfiltration Over C2 Channel"
"T1027": "Obfuscated Files or Information"
"T1592.001": "Gather Victim Host Information - Hardware"
ENDOFFILE

echo "[OK] mitre-id-to-name.yml fixed"

systemctl restart logstash
echo "[OK] Logstash restarted"
