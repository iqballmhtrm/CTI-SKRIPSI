# Laporan Validasi Dashboard dan Pemetaan Serangan

## 1. Tujuan Dashboard
Dashboard Kibana dibangun sebagai pusat _Cyber Threat Intelligence_ (CTI) untuk memvisualisasikan data keamanan secara *real-time*. Tujuan utamanya adalah untuk mempermudah analis SOC dalam mengenali, merespons, dan menelusuri ancaman menggunakan kerangka kerja MITRE ATT&CK.

## 2. Dashboard Architecture
Arsitektur Dashboard terdiri dari:
- **Index Pattern:** `wazuh-alerts-*` yang memuat data pengkayaan dari Logstash.
- **Data Source:** Suricata mendeteksi di jaringan, Wazuh mengumpulkan log, dan Logstash memberikan anotasi kamus teknik MITRE.
- **Panel Utama:** _CTI Dashboard V3_ memuat visualisasi metrik serangan, persebaran taktik MITRE, _timeline_ serangan, serta daftar alamat IP sumber ancaman.

## 3. Alert Validation
Secara keseluruhan, sistem mendeteksi tiga jenis _behavior_ penyerangan (Nmap, Hydra, Nikto) berdasarkan _Custom Rules_ Suricata dan dikonversikan menjadi Kibana Alerts. Status validasi: **100% SUCCESS**.

## 4. MITRE Validation
Mapping berjalan sempurna. Field kibana `mitre.technique_id`, `mitre.technique_name`, dan `mitre.tactic_name` berhasil diekstrak dan dapat diagregasi untuk visualisasi pie chart dan bar chart. 

## 5. Nmap Result
- **Alert Name:** `LOCAL NMAP SYN Scan Detected`
- **Tactic:** Discovery
- **Technique:** Network Service Scanning (T1046)
- **Status:** Panel Validasi T1046 menampilkan hitungan deteksi positif.

## 6. Hydra Result
- **Alert Name:** `LOCAL HYDRA SSH Brute Force Attempt`
- **Tactic:** Credential Access
- **Technique:** Brute Force (T1110)
- **Status:** Panel Validasi T1110 menampilkan hitungan deteksi positif.

## 7. Nikto Result
- **Alert Name:** `LOCAL NIKTO Web Scanner Detected`
- **Tactic:** Reconnaissance
- **Technique:** Active Scanning (T1595)
- **Status:** Panel Validasi T1595 menampilkan hitungan deteksi positif.

## 8. Dashboard Result
Dashboard final menampilkan ringkasan ekstensif. Visualisasi menunjukkan korelasi antara *Threat Actor* (diwakili oleh IP `192.168.56.1` dan IP simulasi internal) dengan metode spesifik mereka di Layer Pyramid of Pain. 

## 9. Analisis Hasil
Deteksi berhasil di-trigger tanpa *false negative* pada simulasi *Controlled Attack*. Logstash terbukti *reliable* dalam mengekstraksi metadata Suricata dan memetakannya sesuai dengan standar industri (MITRE ATT&CK). Visualisasi sangat responsif dan informatif.

## 10. Kesimpulan
Seluruh tumpukan ELK, Wazuh, dan Suricata telah dikonfigurasi dengan tepat. Dashboard CTI yang dibangun siap memenuhi standar *Cyber Threat Intelligence* dan berhasil memvalidasi seluruh tujuan penelitian dalam Skripsi ini.
