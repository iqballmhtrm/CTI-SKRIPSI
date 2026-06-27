# MASTER PROMPT — FULL LIFECYCLE
# Sistem CTI ELK Stack: Perancangan → Setup → Implementasi → Operasional → Pendataan → Laporan & Manual Book

**Skripsi:** Optimisasi Visualisasi Data Log dan Alert Siber Melalui Dashboard ELK Stack untuk Mendukung Pengambilan Keputusan Operasional Cyber Threat Intelligence (CTI)
**Institusi:** Politeknik Negeri Malang
**Tool eksekusi:** Antigravity CLI (`agy`) — Google AI Pro
**Prinsip:** 100% Elastic Basic license (gratis), single local cluster, 3 VM VirtualBox

---

## CARA PAKAI DOKUMEN INI

Dokumen ini punya **7 BAGIAN** berurutan. Setiap bagian adalah blok prompt mandiri yang bisa langsung di-paste ke `agy`. Jangan loncat bagian — setiap bagian bergantung pada bagian sebelumnya selesai.

Format pemakaian di setiap sesi baru:
```
Baca CTI-Skripsi/MASTER_PROMPT_FULL_LIFECYCLE_CTI.md sebagai konteks kerja.
Kita sedang di BAGIAN [X]. Lanjutkan dari status terakhir.
```

Checklist status ada di paling bawah dokumen — update manual setiap kali satu bagian selesai.

---

## BAGIAN 0 — KONTEKS SISTEM (WAJIB DIBACA AGENT SETIAP SESI)

```
KONTEKS SISTEM CTI-SKRIPSI

Topologi 3 VM (VirtualBox, jaringan host-only 192.168.56.0/24):
- ATTACKER-NODE (Kali Linux)  : 192.168.56.110
- VICTIM-NODE (Ubuntu Server) : 192.168.56.106
- SOC-SERVER (Ubuntu Server)  : 192.168.56.10

Repository kerja: C:\Users\mohiq\VirtualBox VMs\CTI-Skripsi\

Stack:
- Elasticsearch + Logstash + Kibana (Basic license, gratis selamanya)
- Suricata (NIDS) di VICTIM-NODE
- Wazuh Manager di SOC-SERVER, Wazuh Agent di VICTIM-NODE (HIDS)
- Filebeat (log shipper) di VICTIM-NODE
- SOAR Dashboard custom (Flask + Python + SQLite) di SOC-SERVER
- Tools serangan: Nmap, Hydra, Nikto di ATTACKER-NODE

Pipeline data Logstash yang harus berjalan:
Suricata/Wazuh → Filebeat → Logstash (parsing, GeoIP, MITRE mapping, 
Pyramid of Pain classification, Threat Scoring) → Elasticsearch (index 
soc-alerts-*, transform cti-threat-score-transform → index cti-threat-score) 
→ Kibana (Dashboard, Cases, ES|QL, Canvas, Maps) → Webhook Connector → SOAR API

Prinsip arsitektur WAJIB:
- KIBANA = command center (semua visualisasi, investigasi, case management, analytics)
- SOAR = execution engine SAJA (bukan dashboard, hanya endpoint aksi: block-ip, 
  lock-root, forensics)
- Semua fitur yang dipakai HARUS Basic license (gratis) kecuali eksplisit disebut Trial

4 pilar awal + 4 pilar tambahan (total 8 pilar penelitian):
1. Visualisasi CTI (Dashboard, Lens, ES|QL)
2. MITRE ATT&CK mapping
3. Pyramid of Pain classification
4. Threat Intelligence (GeoIP, Maps)
5. SOC Operations (Cases, Timeline, Detection Rules)
6. SOAR Response (Block IP, Lock Root, Forensics)
7. MTTD (Mean Time to Detect) — target 30 iterasi
8. MTTR (Mean Time to Respond) — target 30 iterasi

ATURAN KERJA AGENT:
1. JANGAN jalankan command yang mengubah VM tanpa instruksi eksplisit dari saya
2. SELALU buat file/dokumentasi dulu di workspace, baru saya jalankan manual di VM
3. JANGAN hardcode password — gunakan SSH key atau placeholder variable di config.yaml
4. Gunakan HANYA fitur Elastic Basic kecuali saya minta eksplisit pakai Trial
5. Ikuti struktur folder bernomor: 01- sampai 11- (sudah ada), 12- SOAR, 13- Honeypot 
   (jika dipakai), 14- Testing-Results, 15- Manual-Book
6. Semua command destructive (DELETE, DROP, format) HARUS saya konfirmasi dulu
7. Setiap file konfigurasi yang dibuat harus disertai instruksi verifikasi
8. Gunakan Bahasa Indonesia untuk dokumentasi dan komentar kode
```

---

## BAGIAN 1 — PERANCANGAN SISTEM (SYSTEM DESIGN)

**Tujuan:** Dokumen arsitektur lengkap sebagai dasar Bab 3 (Metodologi) skripsi, sebelum instalasi apapun dimulai.

```
[PASTE BAGIAN 0 DI ATAS DULU, LALU LANJUTKAN DENGAN INI]

Buat dokumentasi perancangan sistem lengkap di folder CTI-Skripsi/00-Perancangan/

TUGAS 1.1 — Spesifikasi kebutuhan sistem
Buat file: 00-Perancangan/01-spesifikasi-kebutuhan.md
Isi:
- Kebutuhan fungsional: 10 poin (mengacu pada 8 pilar penelitian di atas, 
  ditambah requirement umum: real-time processing, dashboard accessible via 
  browser, data retention minimal 30 hari)
- Kebutuhan non-fungsional: performa (alert muncul di Kibana < 60 detik dari 
  kejadian), availability (uptime selama periode pengujian), usability 
  (dashboard dapat dibaca analis tanpa training khusus)
- Spesifikasi hardware minimum tiap VM (CPU, RAM, storage) berdasarkan 
  kebutuhan Elasticsearch (minimal 4GB RAM untuk SOC-SERVER), Suricata, 
  dan Wazuh
- Spesifikasi software: versi Ubuntu, versi Elastic Stack yang dipakai 
  (gunakan versi terbaru stabil), versi Suricata, versi Wazuh

TUGAS 1.2 — Arsitektur jaringan
Buat file: 00-Perancangan/02-arsitektur-jaringan.md
Isi:
- Diagram topologi ASCII: 3 VM dengan IP, port yang dipakai tiap service
  (Elasticsearch 9200, Kibana 5601, Logstash 5044/9600, SOAR 5000, 
  Wazuh 1514/1515/55000)
- Tabel matriks komunikasi: dari VM mana ke VM mana, port berapa, protokol apa
- Justifikasi pemilihan jaringan host-only (isolasi, keamanan, kontrol penuh 
  untuk simulasi)

TUGAS 1.3 — Arsitektur data dan pipeline
Buat file: 00-Perancangan/03-arsitektur-data-pipeline.md
Isi:
- Diagram alur data ASCII lengkap dari sumber serangan sampai dashboard 
  (gunakan diagram di BAGIAN 0 sebagai referensi)
- Penjelasan tiap tahap processing di Logstash: parsing, GeoIP enrichment, 
  MITRE mapping (dictionary-based), Pyramid of Pain classification, 
  Threat Scoring
- Skema index Elasticsearch: nama index, field mapping (timestamp, src_ip, 
  dest_ip, mitre.technique_id, mitre.tactic, pyramid_layer, threat_score, 
  severity, detection_source)
- Penjelasan transform cti-threat-score-transform: input index, agregasi 
  yang dipakai, output index

TUGAS 1.4 — Desain MITRE ATT&CK mapping dan Pyramid of Pain
Buat file: 00-Perancangan/04-desain-mitre-pyramid.md
Isi:
- Tabel mapping awal: minimal 15 Suricata SID ke MITRE Technique ID 
  (gunakan referensi resmi MITRE ATT&CK untuk teknik yang relevan dengan 
  Nmap/Hydra/Nikto: T1595 Reconnaissance, T1110 Brute Force, T1190 
  Exploit Public-Facing Application, T1059 Command Execution)
- Penjelasan 3 layer Pyramid of Pain yang dipakai dan kriteria klasifikasi:
  * IP Address layer: indikator berbasis src_ip/dest_ip
  * Tools layer: indikator berbasis signature tool (Hydra, Nikto, Nmap 
    pattern)
  * TTPs layer: indikator berbasis behavior/teknik (MITRE technique 
    terpetakan)
- Formula Threat Scoring: bagaimana severity + pyramid_layer + frequency 
  dikombinasikan menjadi skor (contoh: score = severity_weight * 0.4 + 
  pyramid_weight * 0.3 + frequency_weight * 0.3)

TUGAS 1.5 — Desain SOAR API
Buat file: 00-Perancangan/05-desain-soar-api.md
Isi:
- Diagram alur: Alert → Case → Analyst Decision → Webhook → SOAR API → Response
- Spesifikasi endpoint API: POST /webhook, POST /action/block-ip, 
  POST /action/lock-root, POST /action/forensics, GET /api/incidents, 
  GET /api/metrics
- Skema database SQLite: tabel incidents dan actions dengan semua kolom
- Definisi formal MTTD dan MTTR untuk penelitian ini (PENTING untuk bab 
  metodologi — gunakan definisi yang sudah direvisi sebelumnya: MTTD = 
  selisih waktu timestamp_alert diterima sistem ke timestamp_detected 
  tercatat SOAR; BUKAN waktu serangan nyata terjadi di jaringan)

TUGAS 1.6 — Desain skenario pengujian
Buat file: 00-Perancangan/06-desain-skenario-pengujian.md
Isi:
- 5 skenario serangan yang akan diuji (port scan, SSH brute force, web 
  vuln scan, SOAR response test, full chain test)
- Metodologi pengujian 30 iterasi untuk MTTD dan MTTR: bagaimana setiap 
  iterasi dijalankan, interval antar iterasi, kondisi yang harus sama 
  (controlled variable) di setiap iterasi
- Rencana analisis statistik: rata-rata, standar deviasi, min, max untuk 
  MTTD dan MTTR

Setelah semua file dibuat, tampilkan ringkasan struktur folder 00-Perancangan/ 
dan konfirmasi semua dokumen desain siap dipakai sebagai dasar instalasi.
```

---

## BAGIAN 2 — SETUP DAN INSTALASI (INSTALLATION)

**Tujuan:** Instalasi seluruh stack dari nol, terdokumentasi step-by-step, dapat direproduksi.

```
KONTEKS: Lanjutan dari BAGIAN 1, sekarang masuk fase instalasi. Buat SEMUA 
dokumentasi instalasi sebagai file panduan (jangan eksekusi langsung ke VM 
tanpa konfirmasi saya).

TUGAS 2.1 — Instalasi Elasticsearch, Logstash, Kibana di SOC-SERVER
Buat file: CTI-Skripsi/01-Instalasi/01-install-elk-stack.md
Isi panduan lengkap berurutan:
- Update sistem: sudo apt update && sudo apt upgrade -y
- Install Java/dependency yang dibutuhkan
- Tambahkan Elastic APT repository (GPG key, source list) untuk versi 
  terbaru stabil
- Install elasticsearch, logstash, kibana via apt
- Konfigurasi awal elasticsearch.yml: network.host, cluster.name, 
  node.name, discovery.type: single-node
- Generate password elastic superuser: 
  sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
- Generate enrollment token untuk Kibana
- Konfigurasi kibana.yml: server.host, server.port, elasticsearch.hosts, 
  elasticsearch.username, elasticsearch.password
- Start dan enable service: systemctl enable --now elasticsearch logstash kibana
- Verifikasi: curl -k https://localhost:9200 -u elastic:PASSWORD
- Troubleshooting umum: heap size (jvm.options), port conflict, 
  permission error

TUGAS 2.2 — Instalasi Suricata di VICTIM-NODE
Buat file: CTI-Skripsi/01-Instalasi/02-install-suricata.md
Isi:
- Install via PPA resmi Suricata untuk Ubuntu
- Konfigurasi suricata.yaml: HOME_NET, EXTERNAL_NET, interface yang dipantau, 
  output eve.json (enable semua relevant event types: alert, dns, http, 
  ssh, flow)
- Update rules: suricata-update
- Test konfigurasi: suricata -T -c /etc/suricata/suricata.yaml
- Start dan enable service
- Verifikasi: tail -f /var/log/suricata/eve.json saat ada traffic

TUGAS 2.3 — Instalasi Wazuh di SOC-SERVER (Manager) dan VICTIM-NODE (Agent)
Buat file: CTI-Skripsi/01-Instalasi/03-install-wazuh.md
Isi:
- Install Wazuh Manager di SOC-SERVER via script resmi atau apt repository
- Konfigurasi ossec.conf di manager: global settings, ruleset, syscheck
- Install Wazuh Agent di VICTIM-NODE, daftarkan ke manager (agent-auth)
- Konfigurasi agent: log monitoring path, syscheck interval
- Verifikasi koneksi agent-manager: /var/ossec/bin/agent_control -l (di manager)
- Restart manager dan agent service

TUGAS 2.4 — Instalasi Filebeat di VICTIM-NODE
Buat file: CTI-Skripsi/01-Instalasi/04-install-filebeat.md
Isi:
- Install filebeat via apt (Elastic repository yang sama)
- Konfigurasi filebeat.yml: input path untuk Suricata eve.json dan 
  Wazuh alerts.json, output ke Logstash (host SOC-SERVER:5044)
- Enable module suricata jika tersedia: filebeat modules enable suricata
- Test output: filebeat test config && filebeat test output
- Start dan enable service

TUGAS 2.5 — Instalasi tools serangan di ATTACKER-NODE
Buat file: CTI-Skripsi/01-Instalasi/05-install-attacker-tools.md
Isi:
- Verifikasi Nmap, Hydra, Nikto sudah tersedia di Kali Linux (biasanya 
  pre-installed), atau install jika belum: apt install nmap hydra nikto
- Setup wordlist untuk Hydra (rockyou.txt sudah ada di Kali, atau 
  download/extract jika perlu)
- Test konektivitas ke VICTIM-NODE: ping 192.168.56.106

TUGAS 2.6 — Instalasi environment SOAR Dashboard di SOC-SERVER
Buat file: CTI-Skripsi/01-Instalasi/06-install-soar-environment.md
Isi:
- Install Python3, pip, virtualenv
- Buat virtual environment: python3 -m venv /opt/soar-env
- Install dependencies: flask, paramiko (untuk SSH), atau library lain 
  yang dibutuhkan sesuai app/requirements.txt yang sudah dibuat sebelumnya
- Setup systemd service untuk SOAR Flask app agar berjalan persistent 
  (auto-restart jika crash)

TUGAS 2.7 — Verifikasi instalasi end-to-end
Buat file: CTI-Skripsi/01-Instalasi/07-verifikasi-instalasi.md
Isi checklist verifikasi lengkap:
- [ ] Elasticsearch merespons di port 9200
- [ ] Kibana dapat diakses di browser port 5601
- [ ] Logstash service aktif (systemctl status logstash)
- [ ] Suricata menghasilkan eve.json saat ada traffic test
- [ ] Wazuh agent terhubung ke manager (status: active)
- [ ] Filebeat mengirim data (filebeat test output sukses)
- [ ] SOAR Flask app berjalan dan dapat diakses port 5000
- [ ] Konektivitas jaringan antar 3 VM (ping test semua arah)
Command test traffic sederhana: nmap -sS 192.168.56.106 dari ATTACKER-NODE, 
lalu cek apakah muncul di /var/log/suricata/eve.json

Setelah semua file dibuat, tampilkan ringkasan dan urutan instalasi yang 
harus saya jalankan (VM mana dulu, lalu VM mana).
```

---

## BAGIAN 3 — IMPLEMENTASI (PIPELINE, MAPPING, DASHBOARD, SOAR)

**Tujuan:** Bangun seluruh logika sistem — Logstash pipeline, MITRE mapping, dashboard, SOAR app.

```
KONTEKS: Instalasi (BAGIAN 2) sudah selesai dan terverifikasi. Sekarang 
bangun seluruh implementasi logika sistem.

TUGAS 3.1 — Logstash pipeline lengkap
Buat file: CTI-Skripsi/02-ELK/logstash-pipeline-final.conf
Isi pipeline Logstash lengkap satu file (input-filter-output):
- Input: beats { port => 5044 }
- Filter parsing: 
  * Deteksi source (Suricata vs Wazuh) berdasarkan field yang ada
  * JSON extraction dari pesan eve.json/wazuh
  * Normalisasi field ke ECS: src_ip, dest_ip, dest_port, event.category
- Filter GeoIP: geoip { source => "src_ip" target => "geo" }
- Filter MITRE mapping: gunakan filter translate dengan dictionary 
  YAML (referensi ke file mitre-mapping.yml) mapping signature_id ke 
  mitre_technique_id, mitre_technique_name, mitre_tactic
- Filter Pyramid of Pain: gunakan filter ruby atau conditional untuk 
  menentukan pyramid_layer berdasarkan tipe alert (IP-based, tool-based, 
  atau TTP-based)
- Filter Threat Scoring: kalkulasi threat_score berdasarkan formula yang 
  sudah didesain di BAGIAN 1 Tugas 1.4
- Filter tambahan: tambahkan field event.ingested (timestamp Logstash 
  memproses), detection_source
- Output: elasticsearch { hosts => ["https://localhost:9200"] 
  index => "soc-alerts-%{+YYYY.MM.dd}" }
- Output kondisional untuk webhook (siapkan tapi nonaktifkan dulu, 
  akan diaktifkan di Tugas 3.5)

TUGAS 3.2 — File MITRE mapping dictionary
Update file: CTI-Skripsi/05-MITRE/mitre-mapping.yml
Lengkapi dengan minimal 15-20 entri mapping SID ke MITRE technique, 
mencakup signature yang akan dihasilkan oleh Nmap, Hydra, dan Nikto 
scan testing. Format sesuai yang sudah didesain di BAGIAN 1.

TUGAS 3.3 — Suricata custom rules
Update file: CTI-Skripsi/03-Suricata/custom.rules
Buat rules Suricata lengkap dan VALID secara syntax untuk:
- Deteksi Nmap SYN scan dan OS fingerprinting
- Deteksi Hydra SSH brute force (threshold-based)
- Deteksi Nikto web scan (user-agent signature)
Setiap rule harus punya SID unik, msg yang jelas, classtype yang sesuai, 
dan referensi yang bisa di-mapping ke mitre-mapping.yml

TUGAS 3.4 — Index template dan ILM policy
Buat file: CTI-Skripsi/02-ELK/index-template-and-ilm.json
Isi:
- ILM policy "soc-alerts-policy": hot phase (rollover 1GB/1hari), 
  warm phase (3 hari, replicas=0), delete phase (30 hari)
- Index template "soc-alerts-template" yang mengikat pattern soc-alerts-* 
  ke ILM policy dan field mapping yang sesuai (mttd_seconds sebagai 
  integer, mitre.technique_id sebagai keyword, geo sebagai geo_point, dll)
Sertakan command Dev Tools lengkap untuk mengimport secara berurutan.

TUGAS 3.5 — Kibana Alerting Rule dan Webhook Connector
Buat file: CTI-Skripsi/12-SOAR-Dashboard/kibana-alerting-setup.md
Isi panduan:
- Cara membuat Webhook Connector di Kibana: Management → Connectors → 
  Create connector → Webhook, isi URL http://192.168.56.10:5000/webhook
- Cara membuat Alerting Rule: Management → Rules → Create rule, 
  Elasticsearch query rule type, query untuk match alert severity tinggi 
  dari index soc-alerts-*, action: trigger webhook connector di atas
- Payload JSON yang akan dikirim, dan field apa saja yang perlu di-map 
  dari Kibana ke format yang diharapkan SOAR webhook

TUGAS 3.6 — SOAR Flask app lengkap
Buat file: CTI-Skripsi/12-SOAR-Dashboard/app/soar_app.py
(Gunakan semua spesifikasi yang sudah disepakati sebelumnya di TASK-C3: 
proteksi clock drift max(0,...), explicit status="New" saat INSERT, 
dokumentasi definisi MTTD di docstring, validasi ipaddress sebelum SSH, 
parameterized subprocess, SSH key auth)
Lengkapi dengan:
- Semua endpoint: /webhook, /, /action/block-ip, /action/lock-root, 
  /action/forensics, /action/unblock-ip, /action/mark-false-positive, 
  /api/incidents, /api/metrics
- Frontend Bootstrap dengan tabel insiden, status badge, panel statistik, 
  auto-refresh
- Database SQLite dengan schema lengkap (incidents, actions, schema_version)

TUGAS 3.7 — Dashboard Kibana — buat semua panel
Buat file: CTI-Skripsi/06-Dashboard/dashboard-panels-implementation.md
Detail teknis pembuatan setiap panel di Kibana (Lens) sesuai spesifikasi 
8 pilar penelitian: instruksi field apa yang dipilih, agregasi apa, 
tipe visualisasi apa, untuk setiap panel berikut:
- Total Alerts, Unique Attacker IPs, Avg MTTD, Avg MTTR (metric cards)
- Attack Volume Timeline, Top 10 Attacker IP, MITRE Tactic Distribution, 
  Severity Gauge
- MITRE ATT&CK Heatmap, Detection Source Comparison (Suricata vs Wazuh), 
  Top Target Ports
- Pyramid of Pain Distribution (IP/Tools/TTPs breakdown)
- Threat Score Ranking table
- Attacker Origin Map (Maps + GeoIP)

TUGAS 3.8 — ES|QL query library
Buat file: CTI-Skripsi/02-ELK/esql-query-library.md
Kumpulan lengkap query ES|QL (gunakan yang sudah dibuat sebelumnya untuk 
MTTD/MTTR, tambahkan query untuk):
- Pyramid of Pain distribution
- Threat score ranking top 20
- MITRE technique coverage (mapped vs unmapped percentage)
- Perbandingan deteksi Suricata vs Wazuh per skenario serangan

TUGAS 3.9 — Cases setup untuk SOC workflow
Buat file: CTI-Skripsi/12-SOAR-Dashboard/cases-workflow.md
Panduan setup dan penggunaan Kibana Cases:
- Cara membuat case dari alert (Security → Cases → Create case)
- Template 3 case contoh: Case-001 Nmap Scan, Case-002 Hydra Brute Force, 
  Case-003 Nikto Scan, masing-masing dengan deskripsi, severity, dan 
  field MITRE yang relevan
- Cara menghubungkan case dengan timeline investigasi

Setelah semua file dibuat, tampilkan ringkasan lengkap dan urutan 
implementasi yang harus dijalankan di VM (mulai dari Logstash pipeline 
dulu, lalu dashboard, baru SOAR).
```

---

## BAGIAN 4 — OPERASIONAL (MENJALANKAN SISTEM SECARA KONSISTEN)

**Tujuan:** SOP harian agar sistem stabil berjalan terus-menerus tanpa kehabisan resource.

```
KONTEKS: Implementasi (BAGIAN 3) sudah aktif di VM. Sekarang siapkan 
panduan operasional agar sistem bisa berjalan stabil dan konsisten.

TUGAS 4.1 — SOP operasional harian
Buat file: CTI-Skripsi/scripts/sop-operasional-harian.md
Isi:
- Pagi: cek Stack Monitoring (heap usage <75%, disk usage <80%), cek 
  service status semua komponen (systemctl status elasticsearch logstash 
  kibana suricata wazuh-agent), cek SOAR incident list
- Siang: review alert baru di Kibana Discover, investigasi jika ada 
  anomali
- Sore: backup harian (snapshot Elasticsearch jika sudah disetup), 
  export laporan harian dari Kibana

TUGAS 4.2 — Script monitoring kesehatan sistem
Buat file: CTI-Skripsi/scripts/health_check.sh
Script bash yang mengecek:
- Status semua service (systemctl is-active untuk tiap service)
- Disk usage Elasticsearch data directory
- Heap usage Elasticsearch via API (_nodes/stats)
- Jumlah dokumen di index soc-alerts-* hari ini
- Koneksi Filebeat ke Logstash (cek log filebeat untuk error)
Output dalam format laporan ringkas yang mudah dibaca.

TUGAS 4.3 — Snapshot dan backup
Buat file: CTI-Skripsi/02-ELK/snapshot-restore-setup.md
- Setup filesystem repository Elasticsearch
- Snapshot Lifecycle Management (SLM) policy: daily snapshot, retain 7
- Instruksi manual restore jika diperlukan

TUGAS 4.4 — Troubleshooting guide
Buat file: CTI-Skripsi/scripts/troubleshooting-guide.md
Daftar masalah umum dan solusinya:
- Elasticsearch tidak start (cek heap, cek permission data directory)
- Kibana tidak bisa connect ke Elasticsearch (cek password, cek SSL cert)
- Logstash tidak memproses data (cek pipeline syntax dengan --config.test_and_exit)
- Filebeat tidak mengirim data (cek registry file, restart filebeat)
- Suricata tidak generate alert (cek interface yang dipantau benar, 
  cek rules ter-load)
- Wazuh agent disconnect (cek firewall, cek waktu sinkron antar VM)
- SOAR webhook tidak diterima (cek Kibana connector test, cek firewall 
  port 5000)

TUGAS 4.5 — Resource management
Buat file: CTI-Skripsi/scripts/resource-management.md
- Cara membersihkan index lama secara manual jika ILM belum jalan optimal
- Cara mengurangi heap Elasticsearch jika VM terbatas RAM
- Cara membatasi ukuran log Suricata eve.json agar tidak membengkak

Setelah semua file dibuat, tampilkan checklist operasional yang harus 
saya jalankan setiap hari selama periode pengumpulan data.
```

---

## BAGIAN 5 — PENDATAAN (TESTING DAN PENGUMPULAN DATA 30 ITERASI)

**Tujuan:** Eksekusi sistematis skenario pengujian untuk menghasilkan data MTTD/MTTR yang valid secara statistik.

```
KONTEKS: Sistem (BAGIAN 2-4) sudah stabil beroperasi. Sekarang siapkan 
seluruh dokumentasi untuk fase pengumpulan data penelitian.

TUGAS 5.1 — Script otomasi skenario pengujian
Buat file: CTI-Skripsi/07-Testing/scenario_scripts/scenario_1_portscan.sh
Buat file: CTI-Skripsi/07-Testing/scenario_scripts/scenario_2_bruteforce.sh
Buat file: CTI-Skripsi/07-Testing/scenario_scripts/scenario_3_webscan.sh
Buat file: CTI-Skripsi/07-Testing/scenario_scripts/scenario_4_soar_response.sh
Buat file: CTI-Skripsi/07-Testing/scenario_scripts/scenario_5_fullchain.sh

Setiap script (dijalankan dari ATTACKER-NODE):
- Mencatat timestamp_start sebelum serangan dimulai (format ISO8601 UTC)
- Menjalankan command serangan (nmap/hydra/nikto sesuai skenario)
- Mencatat timestamp_end setelah selesai
- Menyimpan kedua timestamp ke file log lokal 
  (format CSV: iteration,timestamp_start,timestamp_end,scenario_type)
Sertakan komentar jelas di tiap script tentang command apa yang dijalankan.

TUGAS 5.2 — Template pencatatan 30 iterasi
Buat file: CTI-Skripsi/07-Testing/iterasi-tracking-template.csv
Header kolom: iteration_number, scenario_type, timestamp_attack_start, 
timestamp_suricata_alert, timestamp_kibana_visible, timestamp_soar_detected, 
timestamp_soar_responded, mttd_seconds, mttr_seconds, notes

Buat juga file: CTI-Skripsi/07-Testing/cara-pengisian-template.md
Panduan jelas cara mengisi tiap kolom: timestamp_suricata_alert diambil 
dari eve.json, timestamp_kibana_visible dari Kibana Discover (waktu 
dokumen pertama muncul), timestamp_soar_detected dan timestamp_soar_responded 
dari database SOAR (otomatis tercatat via app)

TUGAS 5.3 — Query ES|QL untuk ekstraksi data hasil 30 iterasi
Buat file: CTI-Skripsi/07-Testing/esql-extract-results.md
Query ES|QL untuk:
- Ekstrak semua incident dengan mttd_seconds dan mttr_seconds dari index 
  soc-alerts-* dalam rentang waktu pengujian
- Agregasi per scenario_type: AVG, MIN, MAX, STDDEV (jika tersedia) untuk 
  mttd_seconds dan mttr_seconds
- Export-ready format untuk dipindahkan ke Excel/SPSS untuk analisis 
  statistik lanjutan jika dibutuhkan

TUGAS 5.4 — Panduan eksekusi 30 iterasi per skenario
Buat file: CTI-Skripsi/07-Testing/panduan-eksekusi-30-iterasi.md
Isi:
- Jadwal: berapa iterasi per hari yang realistis (misal 6 iterasi/hari 
  selama 5 hari untuk satu skenario = 30 iterasi)
- Interval antar iterasi (minimal jeda agar tidak overlap, misal 10 menit)
- Kondisi yang harus direset antar iterasi: pastikan IP yang diblokir 
  SOAR sebelumnya di-unblock dulu (gunakan endpoint /action/unblock-ip) 
  sebelum iterasi berikutnya, agar setiap iterasi dimulai dari kondisi 
  bersih
- Checklist sebelum mulai sesi pengujian harian: cek semua service aktif, 
  cek SOAR dashboard kosong/siap, cek waktu VM tersinkron (ntpdate atau 
  chrony)

TUGAS 5.5 — Dokumentasi evidence collection
Buat file: CTI-Skripsi/09-Evidence/evidence-collection-checklist.md
Daftar screenshot/bukti yang harus diambil selama pengujian:
- Screenshot Suricata eve.json saat alert muncul (per skenario, minimal 1x)
- Screenshot Kibana Discover menampilkan alert
- Screenshot Kibana Dashboard dengan data real
- Screenshot SOAR Dashboard dengan incident list terisi
- Screenshot Kibana Cases dengan case yang sudah dibuat
- Screenshot ES|QL query dan hasilnya untuk MTTD/MTTR
- Export CSV hasil 30 iterasi dari Kibana

Setelah semua file dibuat, tampilkan ringkasan dan jadwal realistis 
berapa hari dibutuhkan untuk menyelesaikan 30 iterasi x 5 skenario.
```

---

## BAGIAN 6 — FINALISASI LAPORAN DAN MANUAL BOOK

**Tujuan:** Menyusun seluruh hasil menjadi draft bab skripsi dan manual book operasional sistem.

```
KONTEKS: Pendataan (BAGIAN 5) sudah selesai dengan data 30 iterasi 
lengkap untuk semua skenario. Sekarang susun hasil menjadi dokumen 
final untuk skripsi dan manual book.

TUGAS 6.1 — Tabel hasil penelitian (untuk Bab 4)
Buat file: CTI-Skripsi/11-Bab4/tabel-hasil-final.md
Berdasarkan data CSV hasil 30 iterasi (saya akan berikan datanya), susun:
- Tabel 4.1: Statistik MTTD per skenario serangan (rata-rata, min, max, 
  std deviasi)
- Tabel 4.2: Statistik MTTR per aksi SOAR
- Tabel 4.3: Coverage MITRE ATT&CK (tactic, jumlah technique terdeteksi, 
  detection rate)
- Tabel 4.4: Perbandingan Suricata vs Wazuh per tipe event (true positive, 
  false positive jika ada)
- Tabel 4.5: Distribusi Pyramid of Pain (jumlah indikator per layer)
- Tabel 4.6: Threat Score ranking top 10 dengan justifikasi skor

TUGAS 6.2 — Narasi hasil dan pembahasan (Bab 4)
Buat file: CTI-Skripsi/11-Bab4/narasi-pembahasan.md
Susun narasi akademik (bukan hanya angka) yang menjelaskan:
- Interpretasi hasil MTTD: apakah hybrid detection (Suricata+Wazuh) 
  terbukti mempercepat deteksi dibanding single-source?
- Interpretasi hasil MTTR: seberapa efektif SOAR mempercepat respons 
  dibanding manual?
- Analisis coverage MITRE: teknik mana yang paling sering terdeteksi, 
  gap yang ditemukan
- Analisis Pyramid of Pain: apakah klasifikasi otomatis ini memberikan 
  insight tambahan dibanding alert biasa?
- Keterbatasan penelitian: definisikan dengan jujur (lab terisolasi, 
  bukan ancaman nyata, jumlah iterasi terbatas, dll)

TUGAS 6.3 — Kesimpulan dan saran (Bab 5)
Buat file: CTI-Skripsi/kesimpulan-saran-bab5.md
- Kesimpulan yang menjawab langsung rumusan masalah dan tujuan penelitian 
  di abstrak
- Kontribusi penelitian: apa yang baru/berbeda dari penelitian CTI ELK 
  sebelumnya (sitir novelty yang sudah diidentifikasi: Pyramid of Pain 
  + MITRE mapping otomatis + Threat Scoring transform + Hybrid Detection 
  dalam satu pipeline unified)
- Saran pengembangan: roadmap dari sistem skripsi menuju SOC lebih matang 
  (sebutkan fitur Trial yang belum dieksplorasi sebagai future work: 
  ML Anomaly Detection, Attack Discovery)

TUGAS 6.4 — Manual Book operasional sistem
Buat folder: CTI-Skripsi/15-Manual-Book/ dengan struktur:

15-Manual-Book/01-pendahuluan.md
- Tujuan manual book, target pembaca (admin SOC yang akan melanjutkan 
  atau mereplikasi sistem)

15-Manual-Book/02-instalasi-cepat.md
- Ringkasan instalasi (rujuk ke BAGIAN 2, format checklist quick-start)

15-Manual-Book/03-konfigurasi-sistem.md
- Semua file konfigurasi penting dengan penjelasan tiap parameter 
  (elasticsearch.yml, kibana.yml, logstash pipeline, suricata.yaml, 
  ossec.conf, filebeat.yml)

15-Manual-Book/04-operasional-harian.md
- SOP harian (rujuk BAGIAN 4), dilengkapi dengan screenshot placeholder 
  yang perlu saya isi manual

15-Manual-Book/05-cara-investigasi-insiden.md
- Panduan step-by-step untuk analis baru: cara membaca dashboard, 
  cara membuat Case, cara investigasi via Timeline, cara mengambil 
  aksi via SOAR

15-Manual-Book/06-troubleshooting.md
- Rujuk BAGIAN 4 Tugas 4.4, format FAQ yang mudah dicari

15-Manual-Book/07-glossary.md
- Daftar istilah: MTTD, MTTR, Pyramid of Pain, MITRE ATT&CK, Threat 
  Scoring, dan istilah teknis lain yang dipakai di seluruh sistem

15-Manual-Book/08-appendix-mitre-mapping-lengkap.md
- Tabel lengkap semua MITRE mapping yang dipakai di sistem (final, 
  setelah semua testing selesai)

TUGAS 6.5 — Daftar pustaka dan referensi teknis
Buat file: CTI-Skripsi/daftar-pustaka-teknis.md
Kumpulkan referensi teknis yang relevan dengan implementasi (dokumentasi 
resmi Elastic, Suricata, Wazuh, MITRE ATT&CK framework, Pyramid of Pain 
concept oleh David Bianco) dalam format sitasi yang konsisten dengan 
gaya sitasi skripsi Anda.

Setelah semua file dibuat, tampilkan ringkasan lengkap struktur final 
folder CTI-Skripsi/ dan konfirmasi semua deliverable siap untuk proses 
penulisan skripsi final dan persiapan sidang.
```

---

## BAGIAN 7 — PERSIAPAN SIDANG (BONUS)

```
KONTEKS: Semua bagian (1-6) sudah selesai. Siapkan materi presentasi sidang.

TUGAS 7.1 — Canvas presentation untuk sidang
Rujuk spesifikasi Canvas yang sudah dibuat sebelumnya (4 halaman: 
Overview, MITRE Coverage, Geographic, MTTD/MTTR Dashboard), pastikan 
semua data sudah final dari hasil 30 iterasi.

TUGAS 7.2 — Skrip demo live sidang
Buat file: CTI-Skripsi/15-Manual-Book/09-skrip-demo-sidang.md
Skrip step-by-step untuk demo live di depan penguji:
1. Tunjukkan topologi sistem (gunakan diagram dari BAGIAN 1)
2. Jalankan satu skenario serangan ringan (misal Nmap scan) secara live
3. Tunjukkan alert muncul di Kibana real-time
4. Tunjukkan MITRE mapping dan Pyramid of Pain classification pada alert 
   tersebut
5. Tunjukkan Case dibuat dan investigasi singkat
6. Tunjukkan SOAR Dashboard menerima alert dan eksekusi Block IP
7. Tunjukkan MTTD/MTTR tercatat di dashboard
8. Tutup dengan Canvas executive summary menampilkan hasil 30 iterasi

Sertakan estimasi waktu tiap langkah (total demo idealnya 5-7 menit) 
dan rencana cadangan jika ada kegagalan teknis saat demo live (gunakan 
screenshot/recording sebagai backup).

Setelah selesai, laporkan "SISTEM CTI SIAP SIDANG — SEMUA BAGIAN COMPLETE".
```

---

## CHECKLIST STATUS GLOBAL

```
[ ] BAGIAN 1 — Perancangan Sistem (6 dokumen desain)
[ ] BAGIAN 2 — Setup dan Instalasi (7 panduan instalasi + verifikasi)
[ ] BAGIAN 3 — Implementasi (9 tugas: pipeline, mapping, dashboard, SOAR, ES|QL, Cases)
[ ] BAGIAN 4 — Operasional (5 dokumen SOP dan troubleshooting)
[ ] BAGIAN 5 — Pendataan (5 tugas: script testing, template, 30 iterasi x 5 skenario)
[ ] BAGIAN 6 — Finalisasi Laporan dan Manual Book (5 tugas: tabel, narasi, kesimpulan, manual book, pustaka)
[ ] BAGIAN 7 — Persiapan Sidang (Canvas final + skrip demo)
```

---

## CARA MEMULAI SEKARANG

Paste ke `agy`:
```
Baca CTI-Skripsi/MASTER_PROMPT_FULL_LIFECYCLE_CTI.md. Kita mulai dari 
BAGIAN 0 (konteks) dan BAGIAN 1 (Perancangan Sistem). Buat semua dokumen 
di BAGIAN 1 sekarang.
```

Setelah BAGIAN 1 selesai dan Anda review, lanjut ke BAGIAN 2 dengan cara yang sama, dan seterusnya secara berurutan sampai BAGIAN 7.

---

*Master prompt full lifecycle untuk skripsi CTI ELK Stack, Politeknik Negeri Malang.*
*Semua fitur Elastic Basic license — gratis selamanya. Antigravity CLI (agy) v1.0.8.*
