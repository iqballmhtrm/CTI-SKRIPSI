echo '123123' | sudo -S -s << 'EOF'
cat << 'RULE' > /var/lib/suricata/rules/custom.rules
alert tcp any any -> $HOME_NET any (msg:"LOCAL NMAP SYN Scan Detected"; flags:S,12; threshold:type both, track by_src, count 50, seconds 5; classtype:attempted-recon; sid:1000010; rev:1; metadata: mitre_tactic_name Discovery, mitre_technique_name Network_Service_Scanning, mitre_technique_id T1046;)
alert tcp any any -> $HOME_NET 22 (msg:"LOCAL HYDRA SSH Brute Force Attempt"; flags:S,12; threshold:type both, track by_src, count 10, seconds 10; classtype:attempted-admin; sid:1000020; rev:1; metadata: mitre_tactic_name Credential_Access, mitre_technique_name Brute_Force, mitre_technique_id T1110;)
alert http any any -> $HOME_NET any (msg:"LOCAL NIKTO Web Scanner Detected"; flow:established,to_server; content:"Nikto"; http_user_agent; nocase; classtype:web-application-attack; sid:1000030; rev:1; metadata: mitre_tactic_name Reconnaissance, mitre_technique_name Active_Scanning, mitre_technique_id T1595;)
RULE
EOF