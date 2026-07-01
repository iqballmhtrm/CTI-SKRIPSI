# MASTER PROMPT — Sistem CTI ELK Stack Berbasis VirtualBox Lab
## Untuk Antigravity CLI (agy) — Dijalankan Bertahap, Konsisten Sampai Sistem Selesai

---

## KONTEKS PENELITIAN

Kamu adalah AI engineering assistant untuk proyek skripsi Cyber Threat Intelligence (CTI) berbasis ELK Stack di Politeknik Negeri Malang. Seluruh sistem berjalan di VirtualBox lokal dengan tiga VM:

- **ATTACKER-NODE** (Kali Linux, 192.168.56.110) — mesin penyerang untuk simulasi serangan
- **VICTIM-NODE** (Ubuntu, 192.168.56.106) — mesin korban, menjalankan Suricata NIDS + Wazuh HIDS
- **SOC-SERVER** (Ubuntu, 192.168.56.10) — menjalankan Elasticsearch + Logstash + Kibana + SOAR Flask

**Repository lokal:** `C:\Users\mohiq\VirtualBox VMs\CTI-Skripsi\`

**Stack teknologi yang dipakai (SEMUA GRATIS — Basic license):**
- Elasticsearch + Logstash + Kibana (ELK Stack)
- Suricata NIDS + Wazuh HIDS (Hybrid Detection)
- Filebeat (log shipper)
- MITRE ATT&CK framework
- SOAR Dashboard (Flask + Python + SQLite)
- ES|QL untuk kalkulasi MTTD/MTTR

**4 pilar penelitian yang harus dibuktikan:**
1. Visualisasi dashboard CTI yang intuitif
2. Pemetaan pola ancaman ke MITRE ATT&CK
3. Deteksi anomali berbasis hybrid NIDS+HIDS
4. Monitoring MTTD (Mean Time to Detect) dan MTTR (Mean Time to Respond)

**ATURAN KERJA:**
- JANGAN jalankan command yang langsung mengubah konfigurasi VM tanpa instruksi eksplisit
- SELALU buat file di workspace terlebih dahulu, baru instruksikan langkah manual
- JANGAN hardcode password apapun — gunakan SSH key atau placeholder variable
- Gunakan HANYA fitur Elastic Basic (gratis) kecuali disebutkan eksplisit
- Ikuti struktur folder bernomor yang sudah ada (01- sampai 11-, lanjut 12-, 13-, dst)

---

## FASE 1 — FONDASI: PULIHKAN DAN STABILKAN PIPELINE DATA

**Tujuan:** Pastikan data mengalir sempurna dari Suricata/Wazuh → Filebeat → Logstash → Elasticsearch sebelum membuat visualisasi apapun.

### Tugas 1A — Audit dan perbaiki file konfigurasi kosong

Buat script `CTI-Skripsi/scripts/restore_configs.sh` yang berisi instruksi manual untuk menyalin konfigurasi dari VM SOC-SERVER ke folder Windows:

```
File yang perlu dipulihkan dari SOC-SERVER (/etc/...):
- /etc/elasticsearch/elasticsearch.yml  → CTI-Skripsi/02-ELK/elasticsearch.yml
- /etc/kibana/kibana.yml                → CTI-Skripsi/02-ELK/kibana.yml
- /etc/logstash/conf.d/soc-pipeline.conf → CTI-Skripsi/02-ELK/logstash.conf
- /etc/filebeat/filebeat.yml            → CTI-Skripsi/02-ELK/filebeat.yml
- /etc/suricata/rules/custom.rules      → CTI-Skripsi/03-Suricata/custom.rules
- /etc/wazuh-agent/ossec.conf           → CTI-Skripsi/04-Wazuh/ossec.conf
```

Perbaiki juga bug yang sudah ditemukan:
- `apply_pipeline_patch.sh` baris 28: tambahkan kutip penutup `d"` setelah `Unmapped`
- `tmp_mitre_check_unix.sh`: ubah semua `sort -n` menjadi `sort` biasa (tanpa flag -n)
- `assemble_cti_dashboard.ps1`: ganti path absolut `d:\skripsi josjis\...` menjadi path relatif `.\`

### Tugas 1B — Setup Ingest Pipeline di Elasticsearch

Buat file `CTI-Skripsi/02-ELK/ingest_pipeline_soc.json` berisi definisi Ingest Pipeline untuk diimport via Kibana Dev Tools. Pipeline ini harus:

- Processor `geoip` pada field `src_ip` → menghasilkan `geo.country_name`, `geo.location` (lat/lon)
- Processor `user_agent` jika ada field user_agent dari log web
- Processor `date` untuk normalisasi timestamp ke format ISO8601
- Processor `set` untuk menambahkan field `ecs.version: "8.0.0"`
- Processor `rename` untuk memastikan field sesuai ECS (Elastic Common Schema)
- Handler `on_failure` yang menyimpan error ke field `pipeline_error` tanpa membuang dokumen

Sertakan instruksi cara mengimport pipeline di Dev Tools:
```
PUT _ingest/pipeline/soc-cti-pipeline
{ <isi pipeline JSON> }
```

### Tugas 1C — Setup ILM Policy dan Data Streams

Buat file `CTI-Skripsi/02-ELK/ilm_policy_soc.json` berisi:
- ILM policy bernama `soc-alerts-policy`
- Hot phase: rollover setelah 1GB atau 1 hari
- Warm phase: setelah 3 hari, set replicas=0
- Delete phase: setelah 30 hari
- Index template `soc-alerts-template` yang mengarahkan index `soc-alerts-*` ke policy ini
- Data stream definition untuk `soc-alerts`

Sertakan semua command Dev Tools untuk mengimport secara berurutan.

### Tugas 1D — Verifikasi pipeline end-to-end

Buat file `CTI-Skripsi/scripts/verify_pipeline.sh` berisi sequence verifikasi manual:
1. Cek Elasticsearch: `curl -u elastic:$ES_PASS http://192.168.56.10:9200/_cluster/health?pretty`
2. Cek index tersedia: `curl ... GET /soc-alerts/_count`
3. Cek Logstash pipeline aktif: `sudo systemctl status logstash`
4. Test Filebeat output: `filebeat test output`
5. Generate traffic test dari ATTACKER-NODE: `nmap -sS 192.168.56.106`
6. Tunggu 30 detik, cek data masuk di Kibana Discover

**Output Fase 1:** Semua file konfigurasi terisi, pipeline berjalan, data muncul di Kibana.

---

## FASE 2 — DETEKSI: SURICATA, WAZUH, DAN HYBRID DETECTION

**Tujuan:** Perkuat layer deteksi dengan rules yang lengkap dan mapping MITRE yang akurat.

### Tugas 2A — Suricata custom rules

Buat file `CTI-Skripsi/03-Suricata/custom.rules` yang berisi minimal rules berikut (dengan format Suricata yang valid):

**Kategori Reconnaissance (MITRE T1595):**
- SID deteksi Nmap SYN scan (flag SYN, threshold 10 koneksi/detik)
- SID deteksi Nmap OS fingerprinting (flag berbagai kombinasi TCP unusual)
- SID deteksi Nikto web scanner (User-Agent signature)

**Kategori Credential Access (MITRE T1110):**
- SID deteksi SSH brute force (threshold 5 attempt/10 detik ke port 22)
- SID deteksi HTTP basic auth brute force (401 response berulang)
- SID deteksi Hydra signature (User-Agent atau timing pattern)

**Kategori Lateral Movement (MITRE T1021):**
- SID deteksi SSH login dari IP baru setelah brute force berhasil

**Kategori Exfiltration (MITRE T1041):**
- SID deteksi transfer data besar tidak biasa (payload > 10MB dalam satu sesi)

Setiap rule harus mengandung field metadata: `mitre_technique`, `mitre_tactic`, `severity` (1-3), dan `description`.

### Tugas 2B — Update MITRE mapping

Update `CTI-Skripsi/05-MITRE/mitre-mapping.yml` dengan format:

```yaml
mappings:
  - sid: <nomor SID>
    rule_name: "<nama rule>"
    mitre_technique_id: "T<XXXX>"
    mitre_technique_name: "<nama teknik>"
    mitre_tactic: "<nama taktik>"
    severity: <1-3>
    detection_source: "suricata"  # atau "wazuh"
```

Petakan SEMUA SID yang ada di custom.rules dan tambahkan entri untuk alert Wazuh yang relevan (rule ID Wazuh untuk SSH brute force, file integrity, dan privilege escalation).

### Tugas 2C — Perbaiki pipeline Logstash untuk MITRE enrichment

Buat file `CTI-Skripsi/02-ELK/logstash_mitre_enrichment.conf` yang berisi filter Logstash:
- Baca `mitre-mapping.yml` menggunakan filter `translate` atau `ruby`
- Enrich setiap event dengan field `mitre.technique_id`, `mitre.tactic`, `mitre.severity`
- Normalisasi field `src_ip`, `dest_ip`, `alert.signature`, `alert.category` ke ECS
- Tambahkan field `detection.source` berisi "suricata" atau "wazuh" berdasarkan log origin
- Tambahkan field `event.ingested` dengan timestamp saat event diproses Logstash

**Output Fase 2:** Rules lengkap, semua alert ter-enrich dengan data MITRE ATT&CK.

---

## FASE 3 — VISUALISASI: DASHBOARD CTI LENGKAP (SEMUA GRATIS)

**Tujuan:** Bangun seluruh layer visualisasi menggunakan fitur Basic license Kibana.

### Tugas 3A — Dashboard utama CTI (Lens panels)

Buat file `CTI-Skripsi/06-Dashboard/dashboard_panels_spec.md` berisi spesifikasi teknis setiap panel:

**Baris 1 — Metric summary (4 panel):**
- Total Alerts (24 jam terakhir) — Lens metric, index soc-alerts-*
- Unique Attacker IPs — Lens metric, cardinality pada src_ip
- MTTD rata-rata (menit) — Lens metric, average of `mttd_minutes` field
- MTTR rata-rata (menit) — Lens metric, average of `mttr_minutes` field

**Baris 2 — Trend dan distribusi:**
- Attack Volume Timeline — Lens bar chart, date histogram per jam, breakdown by severity
- Top 10 Attacker IP — Lens horizontal bar, terms aggregation src_ip
- MITRE Tactic Distribution — Lens donut, terms aggregation mitre.tactic
- Alert Severity Gauge — Lens gauge, split by severity 1/2/3

**Baris 3 — Detail analisis:**
- MITRE ATT&CK Heatmap — Lens heatmap, x=mitre.technique_id, y=mitre.tactic, value=count
- Detection Source Comparison — Lens bar grouped, Suricata vs Wazuh per tipe serangan
- Top Target Ports — Lens treemap, terms aggregation dest_port
- MTTD Trend over Time — TSVB, moving average MTTD per jam

**Baris 4 — Geographic:**
- Attacker Origin Map — Maps layer, points dari geo.location field, colored by severity
- Country of Origin Table — Lens data table, geo.country_name + count + severity

Untuk setiap panel: sertakan query KQL yang dipakai, field yang dibutuhkan, dan tipe agregasi.

### Tugas 3B — ES|QL queries untuk MTTD dan MTTR

Buat file `CTI-Skripsi/02-ELK/esql_mttd_mttr.md` berisi query ES|QL lengkap:

**Query MTTD (waktu dari serangan terdeteksi Suricata ke alert muncul di Kibana):**
```esql
FROM soc-alerts-*
| WHERE @timestamp > NOW() - 24 hours
| STATS 
    avg_mttd = AVG(mttd_seconds),
    min_mttd = MIN(mttd_seconds),
    max_mttd = MAX(mttd_seconds),
    total_alerts = COUNT(*)
  BY mitre.tactic
| EVAL avg_mttd_minutes = ROUND(avg_mttd / 60, 2)
| SORT avg_mttd_minutes ASC
```

**Query MTTR (waktu dari alert muncul ke aksi mitigasi di SOAR):**
```esql
FROM soc-alerts-*
| WHERE response.action IS NOT NULL
| STATS
    avg_mttr = AVG(mttr_seconds),
    total_responded = COUNT(*)
  BY response.action, mitre.tactic
| EVAL avg_mttr_minutes = ROUND(avg_mttr / 60, 2)
| SORT avg_mttr_minutes DESC
```

**Query Top threat actors:**
```esql
FROM soc-alerts-*
| WHERE @timestamp > NOW() - 7 days
| STATS
    attack_count = COUNT(*),
    unique_techniques = COUNT_DISTINCT(mitre.technique_id),
    max_severity = MAX(alert.severity)
  BY src_ip, geo.country_name
| SORT attack_count DESC
| LIMIT 20
```

Sertakan minimal 10 query ES|QL yang mencakup semua 4 pilar penelitian, dengan penjelasan tiap query dalam Bahasa Indonesia.

### Tugas 3C — Vega-Lite custom visualization

Buat file `CTI-Skripsi/06-Dashboard/vega_mitre_matrix.json` berisi spesifikasi Vega-Lite untuk:
- MITRE ATT&CK matrix visualization: grid dengan tactic sebagai kolom dan technique sebagai baris
- Cell colored by alert count (color scale: putih=0, merah tua=banyak)
- Hover tooltip menampilkan: technique name, count, avg severity, last seen
- Ini adalah visualisasi yang TIDAK bisa dibuat dengan Lens biasa, sehingga menjadi kontribusi unik penelitian

### Tugas 3D — Canvas presentation workpad

Buat file `CTI-Skripsi/06-Dashboard/canvas_sidang_spec.md` berisi spesifikasi layout Canvas:

**Halaman 1 — Overview eksekutif:**
- Header: "Sistem CTI Berbasis ELK Stack" + logo/nama kampus
- 4 metric cards: Total Alerts, Unique Attackers, MTTD, MTTR
- 1 chart mini: Attack timeline 7 hari terakhir

**Halaman 2 — MITRE ATT&CK coverage:**
- Tabel tactic yang terdeteksi + jumlah technique per tactic
- Top 5 techniques dengan frekuensi tertinggi
- Detection source breakdown (Suricata vs Wazuh)

**Halaman 3 — Geographic threat map:**
- World map dengan attacker origin
- Top 10 countries table
- Waktu serangan terbanyak (heatmap jam vs hari)

**Halaman 4 — MTTD/MTTR dashboard:**
- Trend MTTD dan MTTR over time
- Comparison sebelum vs sesudah SOAR diaktifkan
- Target SLA: MTTD < 5 menit, MTTR < 2 menit

Sertakan instruksi cara membuat tiap halaman Canvas langkah demi langkah.

**Output Fase 3:** Dashboard lengkap, semua query terdokumentasi, Canvas siap untuk sidang.

---

## FASE 4 — SOAR: DASHBOARD RESPONS OTOMATIS

**Tujuan:** Bangun Flask SOAR yang terhubung ke Kibana Alerting untuk respons one-click.

### Tugas 4A — Flask SOAR Dashboard

Buat `CTI-Skripsi/12-SOAR-Dashboard/app/soar_app.py` dengan:

**Backend (Flask):**
- `POST /webhook` — menerima JSON alert dari Kibana Alerting rule (BUKAN dari Logstash langsung, agar konsisten dengan Basic license)
- `GET /` — halaman utama: tabel insiden dengan kolom Waktu, IP Penyerang, Tipe Serangan, MITRE Tactic, Severity, Status, Aksi
- `POST /action/block-ip` — SSH ke VICTIM-NODE, jalankan `sudo iptables -A INPUT -s <ip> -j DROP`
- `POST /action/lock-root` — SSH ke VICTIM-NODE, jalankan `sudo passwd -l root`
- `POST /action/forensics` — SSH ke VICTIM-NODE, kumpulkan `ps aux`, `netstat -tulnp`, `last`, simpan ke `app/forensics/<timestamp>/`
- `POST /action/unblock-ip` — SSH ke VICTIM-NODE, jalankan `sudo iptables -D INPUT -s <ip> -j DROP` (untuk undo)
- `GET /api/incidents` — JSON API untuk data insiden (dipakai oleh Kibana Canvas via Vega)
- `GET /api/metrics` — JSON API MTTD/MTTR realtime

**Keamanan wajib:**
- Validasi `src_ip` dengan `ipaddress.ip_address()` sebelum dipakai di command apapun
- Gunakan parameterized subprocess list (BUKAN shell=True atau string concatenation)
- SSH via SSH key (paramiko dengan key file), JANGAN hardcode password
- Semua SSH credentials dibaca dari `config.yaml` atau environment variable

**Frontend (Bootstrap 5, dark theme SOC-style):**
- Status indicator: hijau=sistem normal, kuning=alert aktif, merah=insiden kritis
- Auto-refresh tabel setiap 30 detik tanpa reload halaman (JavaScript fetch)
- Badge severity: merah=high, oranye=medium, kuning=low
- Tombol aksi per baris: [Block IP] [Lock Root] [Forensics] [Unblock IP]
- Panel statistik di atas: Total Incidents, Blocked IPs, Active Alerts, Last Action Time

**Database (SQLite):**
- Tabel `incidents`: id, timestamp_attack, timestamp_detected, timestamp_responded, src_ip, attack_type, mitre_technique, mitre_tactic, severity, status, action_taken, action_timestamp, notes
- Tabel `actions`: id, incident_id, action_type, executed_by, timestamp, result, output
- Field `mttd_seconds`: dihitung otomatis = `timestamp_detected - timestamp_attack`
- Field `mttr_seconds`: dihitung otomatis = `timestamp_responded - timestamp_detected`

### Tugas 4B — Kibana Alerting Rule → SOAR webhook

Buat file `CTI-Skripsi/12-SOAR-Dashboard/kibana_alerting_rule.md` berisi:
- Instruksi membuat Alerting Rule di Kibana: Management → Stack Management → Rules
- Rule type: Elasticsearch query
- Query: match alert dengan severity ≤ 2 dari index soc-alerts-*
- Connector type: Webhook (tersedia gratis di Basic)
- Webhook URL: `http://192.168.56.10:5000/webhook`
- Payload JSON yang dikirim ke SOAR
- Schedule: setiap 1 menit

### Tugas 4C — Setup SSH key untuk SOAR ke VICTIM-NODE

Buat `CTI-Skripsi/12-SOAR-Dashboard/app/setup_ssh_key.sh` (HANYA dokumentasi, jangan dieksekusi):
- Generate keypair di SOC-SERVER: `ssh-keygen -t ed25519 -f ~/.ssh/soar_key`
- Copy public key ke VICTIM-NODE: `ssh-copy-id -i ~/.ssh/soar_key.pub korban@192.168.56.106`
- Tambahkan sudoers NOPASSWD di VICTIM-NODE: `korban ALL=(root) NOPASSWD: /sbin/iptables, /usr/bin/passwd, /usr/bin/ps, /usr/bin/netstat, /usr/bin/last`
- Verifikasi: `ssh -i ~/.ssh/soar_key korban@192.168.56.106 "sudo iptables -L"`

**Output Fase 4:** SOAR berjalan, alert dari Kibana otomatis masuk ke dashboard, aksi mitigasi bisa dieksekusi one-click.

---

## FASE 5 — OPERASIONAL: ILM, SNAPSHOT, DAN STACK MONITORING

**Tujuan:** Sistem berjalan stabil jangka panjang tanpa kehabisan disk atau kehilangan data.

### Tugas 5A — ILM policy lengkap

Update `CTI-Skripsi/02-ELK/ilm_policy_soc.json` dengan policy yang lebih detail:
- Hot phase (0-1 hari): rollover 1GB/1 hari, priority 100
- Warm phase (1-7 hari): set replicas=0, shrink ke 1 shard, forcemerge 1 segment
- Cold phase (7-14 hari): freeze index (read-only)
- Delete phase (30 hari): delete permanent

### Tugas 5B — Snapshot repository dan schedule

Buat `CTI-Skripsi/02-ELK/snapshot_setup.md`:
- Setup filesystem repository di SOC-SERVER: `/var/elasticsearch/snapshots`
- Snapshot policy: daily, retain 7 snapshots, nama `soc-snapshot-{now/d}`
- Instruksi restore jika data hilang

### Tugas 5C — Stack Monitoring setup

Buat `CTI-Skripsi/02-ELK/stack_monitoring_setup.md`:
- Cara mengaktifkan Stack Monitoring di Kibana
- Metrik yang perlu dipantau: heap usage (<75%), disk usage (<80%), indexing rate, search latency
- Alert jika heap > 75%: instruksi langkah perbaikan (increase JVM heap di jvm.options)

**Output Fase 5:** Sistem stabil jangka panjang, data aman, resource terpantau.

---

## FASE 6 — DOKUMENTASI DAN PENGUJIAN

**Tujuan:** Siapkan semua dokumentasi untuk bab metodologi, implementasi, dan hasil skripsi.

### Tugas 6A — Skenario pengujian

Buat `CTI-Skripsi/07-Testing/test_scenarios.md` berisi 5 skenario pengujian lengkap:

**Skenario 1 — Port scanning (T1595):**
- Tool: Nmap dari ATTACKER-NODE
- Command: `nmap -sS -p 1-1000 192.168.56.106`
- Expected detection: Suricata alert SID reconnaissance dalam < 30 detik
- Cara ukur MTTD: catat timestamp serangan vs timestamp alert di Kibana

**Skenario 2 — SSH Brute Force (T1110):**
- Tool: Hydra dari ATTACKER-NODE
- Command: `hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.106`
- Expected detection: Suricata + Wazuh alert dalam < 60 detik
- Cara ukur MTTD: perbandingan deteksi Suricata vs Wazuh (hybrid detection value)

**Skenario 3 — Web vulnerability scan (T1190):**
- Tool: Nikto dari ATTACKER-NODE
- Command: `nikto -h http://192.168.56.106`
- Expected detection: Suricata alert web scan
- Cara ukur: jumlah unique techniques yang berhasil dipetakan ke MITRE

**Skenario 4 — SOAR response test:**
- Trigger: jalankan Skenario 2, tunggu alert muncul di SOAR dashboard
- Action: klik tombol [Block IP] di SOAR
- Expected result: koneksi dari ATTACKER-NODE ke VICTIM-NODE terputus dalam < 10 detik
- Cara ukur MTTR: timestamp alert muncul di SOAR vs timestamp Block IP diklik

**Skenario 5 — Full chain test:**
- Jalankan semua skenario berturut-turut
- Ukur MTTD dan MTTR total
- Screenshot Canvas presentation sebelum dan sesudah SOAR aktif
- Bandingkan: apakah MTTR lebih cepat dengan SOAR vs tanpa SOAR?

### Tugas 6B — Tabel hasil penelitian

Buat `CTI-Skripsi/11-Bab4/tabel_hasil_penelitian.md` berisi template tabel untuk bab hasil:

1. Tabel MTTD per tipe serangan (kolom: Tipe Serangan, MITRE Technique, Detection Source, MTTD rata-rata, MTTD min, MTTD max)
2. Tabel MTTR per aksi SOAR (kolom: Tipe Aksi, Triggered By, MTTR rata-rata, Success Rate)
3. Tabel coverage MITRE ATT&CK (kolom: Tactic, Techniques Detected, Rules Count, Detection Rate)
4. Tabel perbandingan Suricata vs Wazuh (kolom: Tipe Event, Suricata detect, Wazuh detect, Hybrid detect, False positive rate)

### Tugas 6C — SOP operasional harian

Buat `CTI-Skripsi/scripts/daily_sop.md` berisi SOP untuk operator SOC (relevan untuk bab implementasi):
- Pagi: cek Stack Monitoring health, cek alert semalam, review SOAR incident list
- Investigasi: cara pakai Kibana Discover untuk trace serangan dari awal ke akhir
- Respons: urutan aksi SOAR (Block IP dulu, baru Forensics, baru Lock Root)
- Eskalasi: kapan harus shutdown VICTIM-NODE sepenuhnya
- Akhir hari: export laporan harian dari Kibana CSV, backup snapshot

---

## INSTRUKSI PENGGUNAAN PROMPT INI

Prompt ini dirancang untuk digunakan **bertahap** — setiap kali kamu memulai sesi baru dengan Antigravity, sebutkan fase yang sedang dikerjakan:

```
"Kita sedang di Fase 1, Tugas 1B. Lanjutkan dari konteks master prompt CTI ELK."
```

Atau untuk melanjutkan dari titik tertentu:

```
"Fase 2 sudah selesai. Lanjut ke Fase 3, Tugas 3A — buat spesifikasi dashboard panels."
```

Atau untuk troubleshooting:

```
"Ada error saat menjalankan Fase 1 Tugas 1C di Kibana Dev Tools: [error message]. Bantu debug."
```

**Status tracking** — tandai progress di file ini:
- [ ] Fase 1A — Config files pulih
- [ ] Fase 1B — Ingest Pipeline aktif
- [ ] Fase 1C — ILM + Data Streams aktif
- [ ] Fase 1D — Pipeline end-to-end verified
- [ ] Fase 2A — Suricata rules lengkap
- [ ] Fase 2B — MITRE mapping update
- [ ] Fase 2C — Logstash enrichment aktif
- [ ] Fase 3A — Dashboard CTI lengkap
- [ ] Fase 3B — ES|QL queries terdokumentasi
- [ ] Fase 3C — Vega MITRE matrix
- [ ] Fase 3D — Canvas presentation
- [ ] Fase 4A — SOAR Flask berjalan
- [ ] Fase 4B — Kibana Alerting → SOAR terhubung
- [ ] Fase 4C — SSH key setup
- [ ] Fase 5A-C — ILM + Snapshot + Monitoring
- [ ] Fase 6A — Skenario pengujian selesai
- [ ] Fase 6B — Tabel hasil terisi data nyata
- [ ] Fase 6C — SOP terdokumentasi

---

*Master prompt ini dibuat untuk penelitian skripsi CTI ELK Stack, Politeknik Negeri Malang.*
*Semua fitur yang digunakan adalah Elastic Basic license — gratis selamanya.*
*Dijalankan via Antigravity CLI (agy) v1.0.8 dengan model Gemini 3.5 Flash.*
