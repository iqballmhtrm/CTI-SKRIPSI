# BAB 3 - METODOLOGI PENELITIAN

## 3.1 Skenario Topologi
Penelitian ini membangun Cyber Threat Intelligence berbasis ELK Stack, Suricata, dan Wazuh.
- **SOC-SERVER**: IP 192.168.56.10 (enp0s8). Tempat berjalannya semua core engine (Elasticsearch, Logstash, Kibana, Suricata, Wazuh).
- **ATTACKER-NODE**: Menyederhanakan penyerangan melalui Host maupun Node lain pada subnet 192.168.56.0/24.

## 3.2 Desain Deteksi dan Rule (Suricata)
Suricata didesain dengan custom rules spesifik pada `/var/lib/suricata/rules/custom.rules` untuk mendeteksi:
1. **Nmap Scan**: Mendeteksi 50 paket SYN dalam 5 detik.
2. **Hydra SSH Brute Force**: Mendeteksi 10 percobaan koneksi SSH dalam 10 detik.
3. **Nikto Web Scan**: Mendeteksi string `Nikto` pada User-Agent.

## 3.3 Integrasi MITRE ATT&CK 
Setiap rule di-mapping ke metadata logstash:
- **T1046 (Network Service Scanning)** untuk Nmap.
- **T1110 (Brute Force)** untuk Hydra.
- **T1595 (Active Scanning)** untuk Nikto.
Pemrosesan dilakukan di Logstash menggunakan file dictionary YAML.
