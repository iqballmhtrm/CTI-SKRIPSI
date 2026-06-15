# BAB 4 - IMPLEMENTASI DAN PENGUJIAN

## 4.1 Root Cause Analysis & Implementasi Konfigurasi
Penemuan awal menunjukkan Suricata pada SOC-SERVER default menggunakan interface `enp0s3` yang tidak menerima traffik. Masalah berhasil diselesaikan dengan:
- Merubah konfigurasi `/etc/suricata/suricata.yaml` untuk mengawasi `enp0s8`.
- Mendaftarkan `- custom.rules` agar dapat memuat rules khusus deteksi.

## 4.2 Hasil Pengujian Skenario Serangan
Pengujian dilakukan untuk membuktikan integrasi antara Deteksi (Suricata), Pemrosesan (Logstash), dan Visualisasi (Kibana). Seluruh file JSON asli dari `eve.json` telah disimpan di direktori `09-Evidence/`.

### 4.2.1 Pengujian Nmap
Nmap dieksekusi dengan `nmap -sS -p- -T4 192.168.56.10`.
**Hasil:**
Suricata berhasil mencatat event `LOCAL NMAP SYN Scan Detected` sebanyak puluhan kali pada `eve.json` dengan teknik MITRE ATT&CK **T1046**. Event berhasil diteruskan dan terlihat di Kibana.

### 4.2.2 Pengujian Hydra
Simulasi Brute Force SSH dijalankan menggunakan loop koneksi SYN TCP port 22 berturut-turut.
**Hasil:**
Threshold Suricata mendeteksi 10 paket dalam 10 detik dan memicu `LOCAL HYDRA SSH Brute Force Attempt`. Di-mapping sempurna dengan **T1110**.

### 4.2.3 Pengujian Nikto
Simulasi pemindaian aplikasi web menggunakan HTTP GET terhadap port 5601 dengan User-Agent `Nikto/2.1.6`.
**Hasil:**
Suricata sukses membaca Application Layer (HTTP) dan menghasilkan alert `LOCAL NIKTO Web Scanner Detected` yang di-mapping dengan **T1595**.

## 4.3 Visualisasi Akhir
Semua pengujian berjalan 100% dan menghasilkan JSON artifacts. Bukti integrasi ke Kibana Dashboard telah tervalidasi dan siap untuk didemonstrasikan di persidangan. File Kibana export final (`cti-dashboard-v3-combined.ndjson`) disalin menjadi `dashboard-final.ndjson` di folder `06-Dashboard/`.
