# CTI-Skripsi

Repositori ini berisi seluruh artefak konfigurasi, skrip otomatisasi, dan bukti pengujian (evidence) untuk penelitian Skripsi tentang implementasi **Cyber Threat Intelligence (CTI)** menggunakan **Suricata, Elastic Stack (ELK), dan MITRE ATT&CK**.

## Struktur Repositori

- **01-Suricata/**: Aturan (*rules*) kustom Suricata untuk deteksi serangan spesifik.
- **02-Logstash/**: Konfigurasi *pipeline* Logstash (`soc-pipeline.conf`) dan kamus pemetaan MITRE ATT&CK.
- **03-Elasticsearch/**: Struktur *mapping* (Indeks) dan contoh *query* investigasi.
- **04-Kibana/**: Konfigurasi dan *export file* dari CTI Dashboard V3 (Visualisasi).
- **07-Testing/** & **09-Evidence/**: Data tangkapan Elasticsearch JSON murni yang memvalidasi bahwa serangan (Nmap, Hydra, Nikto) berhasil dipetakan ke MITRE ATT&CK.
- **10-Scripts_and_Dumps/**: Kumpulan skrip pengujian, injeksi *alert* simulasi, dan generator otomatisasi yang digunakan selama penyusunan sistem SOC.

## Skenario Serangan yang Divalidasi

1. **Nmap Reconnaissance** -> MITRE `T1046` (Network Service Discovery)
2. **Hydra SSH Brute Force** -> MITRE `T1110.001` (Brute Force - Password Guessing)
3. **Nikto Web Vulnerability Scan** -> MITRE `T1595.002` (Gather Victim Host Information - Hardware)

---
*Generated as part of SOC validation and configuration.*
