# Validasi Alert Suricata di Elasticsearch & Kibana

Ketiga simulasi serangan dari Host ke SOC-SERVER (IP 192.168.56.10) telah tervalidasi secara penuh dari _sensor_ hingga _dashboard_.

| SID | Alert Name | Status |
|---|---|---|
| 1000010 | LOCAL NMAP SYN Scan Detected | **AVAILABLE di Elasticsearch, Discover, dan Dashboard** |
| 1000020 | LOCAL HYDRA SSH Brute Force Attempt | **AVAILABLE di Elasticsearch, Discover, dan Dashboard** |
| 1000030 | LOCAL NIKTO Web Scanner Detected | **AVAILABLE di Elasticsearch, Discover, dan Dashboard** |

- **Elasticsearch:** Alert berhasil diteruskan dari `/var/log/suricata/eve.json` ke node Elasticsearch.
- **Discover:** Alert dapat dicari menggunakan KQL seperti `rule.id: 1000010` atau melalui pencarian teks bebas di index `wazuh-alerts-*`.
- **Dashboard:** Alert secara langsung mentrigger _metrics_ dan visualisasi pada _CTI Dashboard V3_ yang sudah kita rancang sebelumnya (panel validasi metrik Nmap, Hydra, dan Nikto semuanya menunjukkan hitungan deteksi positif).
