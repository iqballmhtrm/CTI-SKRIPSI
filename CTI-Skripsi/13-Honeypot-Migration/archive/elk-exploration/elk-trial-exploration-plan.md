# Rencana Eksplorasi Fitur Elastic Trial (30 Hari)

Dokumen ini berisi panduan untuk mengeksplorasi fitur-fitur berbayar Elastic (Platinum/Enterprise) yang bisa diakses gratis selama 30 hari Trial. Fitur-fitur ini sangat berguna untuk menganalisis data serangan riil dari VPS Honeypot Anda dan dapat dipetakan langsung ke tujuan penelitian skripsi Anda.

## 1. Cara Aktivasi Trial License
Setelah semua sistem di VPS B menyala dan log dari Honeypot mulai masuk, Anda bisa mengaktifkan lisensi Trial selama 30 hari.
1. Buka Kibana di `http://localhost:5601`.
2. Buka menu **Stack Management** -> **License Management**.
3. Klik tombol **Start 30-day trial** atau gunakan Dev Tools:
   ```http
   POST /_license/start_trial?acknowledge=true
   ```

## 2. Machine Learning Anomaly Detection
*Relevansi Penelitian: Memetakan pola ancaman dan deteksi anomali perilaku tanpa rule manual.*

1. Buka menu **Machine Learning** -> **Anomaly Detection**.
2. Klik **Create Job** dan pilih indeks `soc-alerts-*` atau `cti-logs-iqbal-*`.
3. Pilih **Single Metric Job** atau **Multi Metric Job**:
   - **Tujuan 1 (Volume Serangan):** Pilih metrik `count` untuk mendeteksi lonjakan trafik (misal saat *Brute Force* atau *DDoS* mendadak).
   - **Tujuan 2 (Rare IP):** Pilih metrik `rare` pada field `src_ip.keyword` untuk mendeteksi IP penyerang baru yang tidak pernah muncul sebelumnya.
4. Biarkan ML memproses data historis dan berjalan secara *real-time*. Hasil anomali akan divisualisasikan dengan *Severity Score* (0-100).

## 3. Security App - Attack Discovery & SIEM
*Relevansi Penelitian: Visualisasi Dashboard terpadu dan Analisis Taktik MITRE tingkat lanjut.*

1. Buka menu **Elastic Security** -> **Dashboards**.
2. Fitur Security ini secara otomatis memetakan field standar Elastic (ECS) ke dalam kerangka kerja MITRE ATT&CK. 
3. Anda bisa melihat **Alerts**, **Hosts**, dan **Network** secara terpusat tanpa harus membuat pie-chart manual. Ini akan sangat memperkaya *screenshot* Bab 4 Anda terkait efektivitas ELK sebagai SIEM.

## 4. Alerting (Kibana Rules & Connectors)
*Relevansi Penelitian: Menghitung MTTD dan respons proaktif.*

1. Buka menu **Stack Management** -> **Rules** (atau via Elastic Security -> Rules).
2. Buat Rule baru dengan tipe **Elasticsearch query**.
3. Kondisi: `alert.severity: 1 OR alert.severity: 2` (Serangan Kritis).
4. **Action:** Hubungkan (Connector) dengan Webhook SOAR Dashboard Anda, atau gunakan integrasi Email/Slack yang terbuka saat Trial.
5. Anda bisa melacak waktu pasti kapan *alert* terpicu di Kibana, dan membandingkannya dengan *timestamp* log asli dari Honeypot untuk mendapatkan metrik MTTD.

## 5. Reporting (PDF Export Terjadwal)
*Relevansi Penelitian: Dukungan Pengambilan Keputusan Operasional (CTI Report).*

1. Buka Dashboard kustom Anda (V3-CTI Dashboard).
2. Di pojok kanan atas, klik **Share** -> **PDF Reports**.
3. Fitur Reporting ini hanya ada di lisensi Trial/Berbayar. Anda bisa men-generate laporan PDF harian secara otomatis. PDF ini merupakan bentuk nyata penyajian intelijen ancaman siber (CTI) kepada pihak manajerial (C-Level).
