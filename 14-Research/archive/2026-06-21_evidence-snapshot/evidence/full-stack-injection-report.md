# Full Stack Injection Report

## 1. Konfigurasi Suricata Rules (custom.rules)
Tiga rules berhasil diinjeksi dan diaktifkan di `/var/lib/suricata/rules/custom.rules`:
* SID 1000010 (Nmap) -> T1046
* SID 1000020 (Hydra) -> T1110
* SID 1000030 (Nikto) -> T1595

## 2. Modifikasi Pipeline Logstash
MITRE ATT&CK metadata mappings telah berhasil diintegrasikan ke dictionary Logstash (`/etc/logstash/dictionaries/`):
* `mitre-mapping.yml` telah diisi dengan mapping SID ke Technique ID.
* `mitre-id-to-name.yml` telah diisi dengan mapping Technique ID ke Technique Name.
Logstash berhasil direstart dan memproses event dari file `eve.json` dengan pengkayaan MITRE ATT&CK.

## 3. Eksekusi Pengujian (Evidence Collection)
Penelitian ini memvalidasi tiga serangan dari jaringan lokal (Windows Host) ke SOC-SERVER. Berikut adalah bukti alert yang telah terekam dan sukses diperkaya oleh Pipeline ke format Kibana:

### A. Nmap
* Target: 192.168.56.10
* Command: `nmap -sS -p- -T4 192.168.56.10`
* Evidence File: `final-nmap-suricata-alert.json`
* Status: **BERHASIL** (Mendeteksi `LOCAL NMAP SYN Scan Detected`)
* MITRE: Discovery / Network Service Scanning (T1046)

### B. Hydra
* Target: 192.168.56.10:22 (SSH)
* Simulation: 15 TCP SYN packets to port 22 in <13 seconds
* Evidence File: `final-hydra-suricata-alert.json`
* Status: **BERHASIL** (Mendeteksi `LOCAL HYDRA SSH Brute Force Attempt`)
* MITRE: Credential Access / Brute Force (T1110)

### C. Nikto
* Target: 192.168.56.10:5601 (HTTP)
* Command: `Invoke-WebRequest -Uri "http://192.168.56.10:5601/login" -UserAgent "Nikto/2.1.6"`
* Evidence File: `final-nikto-suricata-alert.json`
* Status: **BERHASIL** (Mendeteksi `LOCAL NIKTO Web Scanner Detected`)
* MITRE: Reconnaissance / Active Scanning (T1595)

## 4. Kesimpulan
Seluruh tahapan Safe Full Stack Injection berjalan lancar tanpa merusak dependensi ELK maupun Suricata. Integrasi telah sempurna dengan interface `enp0s8`, memastikan deteksi serangan internal maupun eksternal terpusat dan tampil di Dashboard Kibana sebagai evidence valid untuk Skripsi.
