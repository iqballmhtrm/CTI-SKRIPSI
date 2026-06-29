# Draft Laporan Lengkap Implementasi
# Optimisasi Visualisasi Data Log dan Alert Siber Melalui Dashboard ELK Stack

**Penyusun:** Muhammad Iqbal Muhtaram (NIM. 2241720265)  
**Program Studi:** Teknik Informatika  


---

## 1. Pendahuluan

Dokumen ini merangkum seluruh proses implementasi dan pengujian sistem CTI Dashboard berbasis ELK Stack. Implementasi mencakup 8 task utama yang dikerjakan secara bertahap selama 4 hari kerja.

### 1.1 Topologi Lab

```
┌─────────────────────────────────────────────────────────────────┐
│                    ZONA HIJAU (SOC Server)                       │
│  IP: 192.168.56.10 | User: iqbal@soc-server                    │
│  Services: Elasticsearch 8.19.12, Logstash, Kibana, Filebeat   │
└──────────────────────────────┬──────────────────────────────────┘
                               │ Network: 192.168.56.0/24
┌──────────────────────────────┼──────────────────────────────────┐
│                    ZONA BIRU (Victim Node)                       │
│  IP: 192.168.56.106 | User: korban@victim-node                 │
│  Services: Suricata 8.0.3, Filebeat, Wazuh Agent               │
└──────────────────────────────┼──────────────────────────────────┘
                               │
┌──────────────────────────────┼──────────────────────────────────┐
│                    ZONA MERAH (Attacker)                         │
│  IP: 192.168.56.110 | User: kali@kali                          │
│  Tools: Nmap, Hydra, Metasploit                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Alur Data (Pipeline)

```
Kali (Attack) → Suricata (Victim) → eve.json → Filebeat (Victim)
    → Logstash (SOC) → [MITRE Enricher + Pyramid Classifier]
    → Elasticsearch → Kibana Dashboard
```

---

## 2. Distribusi Task dan Timeline

| Hari | Tanggal | Task | Durasi |
|------|---------|------|--------|
| 1 | 26 Mei 2026 | Task 1: Spec + Task 2: Setup Lab | ~4 jam |
| 2 | 28 Mei 2026 | Task 3: MITRE Enricher + Task 4: Pyramid Classifier + Task 5: Threat Scorer | ~5 jam |
| 3 | 29 Mei 2026 | Task 6: Visualisasi + Task 7: Pengujian MTTD/MTTR + Task 8: Alerting Rules | ~5 jam |

---

## 3. Detail Implementasi Per Task

---

### Task 1: Perencanaan (Spec)

**Tujuan:** Mendefinisikan requirements, design, dan task list secara formal sebelum implementasi.

**Proses:**
1. Analisis kebutuhan berdasarkan judul skripsi dan kerangka teori
2. Penyusunan 9 requirements (3 tier: Wajib, Direkomendasikan, Opsional)
3. Pembuatan design document dengan arsitektur komponen
4. Breakdown menjadi task list yang actionable

**Hasil:**
- 9 requirements terdokumentasi (MTTD/MTTR, MITRE ATT&CK, Pyramid of Pain, Threat Scoring, Anomaly Alerting, Geo-Threat Map, Integrasi, Dokumentasi, Protokol Pengujian)
- Design arsitektur 6 komponen utama
- Task list 8 item dengan sub-tasks

**Kerangka Teori yang Dirujuk:**
- NIST SP 800-61 Rev. 2 (Incident Handling)
- MITRE ATT&CK Framework
- Pyramid of Pain (Bianco, 2013)
- Model Kesadaran Situasional Endsley (1995)
- CVSS v3.1
- Chandola et al. (2009) — Anomaly Detection
- NIST SP 800-94 (IDPS Guide)

---

### Task 2: Setup Lab dan Infrastruktur

**Tujuan:** Memastikan semua VM terhubung, service aktif, waktu tersinkronisasi, dan akses SSH passwordless.

**Proses:**
1. Verifikasi IP dan konektivitas 3 VM
2. Konfigurasi NTP (SOC sebagai master stratum 8, Victim & Kali sync ke SOC)
3. Setup SSH key passwordless dari SOC ke Victim dan Kali
4. Fix Elasticsearch OOM dengan delay 30 detik di systemd
5. Koreksi IP Kali dari 192.168.56.101 (proposal) ke 192.168.56.110 (aktual)
6. Koreksi username Victim dari `iqbal` ke `korban`

**Konfigurasi yang Dibuat:**
| File | Lokasi | Fungsi |
|------|--------|--------|
| `delay.conf` | `/etc/systemd/system/elasticsearch.service.d/` | Delay 30s startup ES |
| `~/.elastic_password` | SOC home dir (mode 600) | Password elastic tersimpan aman |
| SSH keys | `~/.ssh/authorized_keys` di Victim & Kali | Akses passwordless |

**Hambatan yang Diatasi:**
- Elasticsearch OOM saat boot (semua service start bersamaan)
- IP Kali berbeda dari proposal (101 → 110)
- Username Victim berbeda (iqbal → korban)
- SSH Kali tidak auto-start setelah reboot

---

### Task 3: MITRE ATT&CK Enricher (Logstash Pipeline)

**Tujuan:** Memetakan setiap alert Suricata ke teknik MITRE ATT&CK melalui filter Logstash berbasis kamus YAML.

**Pijakan Teori:** MITRE ATT&CK Framework Enterprise v14

**Proses:**
1. Identifikasi format field berbeda antara Filebeat SOC (nested: `suricata.eve.alert.signature_id`) dan Filebeat Victim (flat: `alert.signature_id`)
2. Pembuatan 3 file kamus YAML:
   - `mitre-mapping.yml` — SID → technique_id (~25 entry)
   - `mitre-id-to-name.yml` — technique_id → technique_name (~12 entry)
   - `mitre-id-to-tactic.yml` — technique_id → tactic (~12 entry)
3. Implementasi filter `translate` di Logstash pipeline v3.2/v3.3
4. Handle kedua format field dengan if/else cascade

**Konfigurasi:**
```
File: /etc/logstash/conf.d/soc-pipeline.conf (v3.3)
Kamus: /etc/logstash/dictionaries/mitre-mapping.yml
        /etc/logstash/dictionaries/mitre-id-to-name.yml
        /etc/logstash/dictionaries/mitre-id-to-tactic.yml
```

**Field Output:**
- `mitre.technique_id` (contoh: "T1095", "T1110.001", "T1592.001")
- `mitre.technique_name` (contoh: "Non-Application Layer Protocol")
- `mitre.tactic` (contoh: "Command and Control")

**Mapping SID yang Diimplementasikan:**
| SID | Technique ID | Technique Name | Tactic |
|-----|-------------|----------------|--------|
| 2200121, 2200078 | T1095 | Non-Application Layer Protocol | Command and Control |
| 2228000, 2260002 | T1110.001 | Password Guessing | Credential Access |
| 2022973 | T1592.001 | Gather Victim Host Information | Reconnaissance |
| (default) | Unmapped | Unmapped | Unmapped |

**Validasi:** Field `mitre.*` muncul di event Elasticsearch ✓

---

### Task 4: Pyramid of Pain Classifier

**Tujuan:** Mengklasifikasikan setiap IOC ke salah satu dari 6 tingkatan Pyramid of Pain.

**Pijakan Teori:** David J. Bianco, "The Pyramid of Pain" (2013)

**Proses:**
1. Implementasi if/else cascade di Logstash pipeline v3.3
2. Logika klasifikasi berdasarkan ketersediaan field di event

**Logika Klasifikasi:**
```
IF mitre.technique_id != "Unmapped" → pyramid.layer = "TTPs"
ELSE IF alert.signature contains tool-specific pattern → pyramid.layer = "Tools"
ELSE IF alert.signature is protocol-specific → pyramid.layer = "Network_Artifacts"
ELSE IF dns.question.name exists → pyramid.layer = "Domain_Names"
ELSE IF source.ip exists → pyramid.layer = "IP_Address"
ELSE IF file.hash exists → pyramid.layer = "Hash_Values"
```

**Field Output:**
- `pyramid.layer` (contoh: "TTPs", "Network_Artifacts", "IP_Address")

**Validasi:** Field `pyramid.layer` muncul dengan nilai benar di event ✓

---

### Task 5: Threat Scorer (Continuous Transform)

**Tujuan:** Menghitung composite score per source IP menggunakan Elasticsearch Continuous Transform.

**Pijakan Teori:** Endsley (1995) — Situational Awareness Model (3 level: Perception, Comprehension, Projection)

**Proses:**
1. Identifikasi field IP yang bisa di-aggregasi (`src_ip.keyword`)
2. Pembuatan Continuous Transform `cti-threat-score-transform`
3. Output ke indeks dedicated `cti-threat-score-iqbal`

**Transform Configuration:**
- **Group by:** `src_ip.keyword`
- **Aggregations:**
  - `alert_count` — jumlah alert per IP (L1: Perception)
  - `unique_techniques` — jumlah unik technique_id per IP (L2: Comprehension)
  - `last_seen` — timestamp alert terakhir
- **Sync field:** `@timestamp`
- **Frequency:** 1 menit

**Output Indeks `cti-threat-score-iqbal`:**
| source_ip | alert_count | unique_techniques | last_seen |
|-----------|-------------|-------------------|-----------|
| 192.168.56.110 | 16 | 1 | 2026-05-28T16:59:39Z |
| 192.168.56.106 | 14 | 1 | 2026-05-28T16:59:39Z |
| 0.0.0.0 | 2 | 1 | 2026-05-28T17:21:11Z |

---

### Task 6: Visualisasi Dashboard Kibana

**Tujuan:** Membuat 6 visualisasi baru dan menambahkannya ke dashboard existing.

**Proses:**
1. Pembuatan 2 data view:
   - `cti-logs-iqbal-*` (ID: `7afca9a4-...`) — untuk visualisasi MITRE & Pyramid
   - `cti-threat-score-iqbal` (ID: `ba3ea9c0-...`) — untuk tabel Threat Actors
2. Pembuatan 6 visualisasi dalam format NDJSON
3. Import via Kibana Saved Objects API
4. Fix field `source_ip` → `source_ip.keyword` untuk aggregasi

**6 Visualisasi yang Dibuat:**

| # | ID | Judul | Tipe | Data View |
|---|-----|-------|------|-----------|
| 1 | v3-mitre-technique-pie | V3 - MITRE ATT&CK Technique Distribution | Pie Chart | cti-logs-iqbal-* |
| 2 | v3-mitre-tactic-bar | V3 - MITRE ATT&CK Tactic Distribution | Bar Chart | cti-logs-iqbal-* |
| 3 | v3-pyramid-layer-bar | V3 - Pyramid of Pain Layer Distribution | Bar Chart | cti-logs-iqbal-* |
| 4 | v3-threat-actors-table | V3 - Top Threat Actors Table | Table | cti-threat-score-iqbal |
| 5 | v3-mitre-mapped-count | V3 - Total Mapped MITRE Alerts | Metric | cti-logs-iqbal-* |
| 6 | v3-mitre-timeline | V3 - MITRE Alert Timeline by Tactic | Histogram | cti-logs-iqbal-* |

**File Export:** `~/eksperimen/cti-dashboard-v3-visualizations.ndjson`

**Hambatan yang Diatasi:**
- Field `source_ip` bertipe text → harus pakai `source_ip.keyword` untuk terms aggregation
- Data view threat-actors-table awalnya salah reference → fix ke ID yang benar

---

### Task 7: Pengujian MTTD/MTTR (Pilot Test + 30 Iterasi Terkontrol)

**Tujuan:** Mengukur Mean Time To Detect dan Mean Time To Respond pada skenario serangan terkontrol.

**Pijakan Teori:** NIST SP 800-61 Rev. 2; NIST SP 800-115

---

#### Fase Awal: Pilot Test (10 Iterasi, Dua Mode)

Pengujian awal (pilot) dilakukan menggunakan dua *custom rule* prototipe Suricata (SID 9000001/9000002)
dengan skrip `run-iteration.sh`. Mitigasi dilakukan secara **manual** via `iptables` (analis mengeksekusi
blokir interaktif). Pilot ini mencakup 5 iterasi mode manual dan 5 iterasi mode dashboard
(hanya skenario Nmap dan SSH).

**Custom Suricata Rules (Pilot):**
```
alert tcp any any -> $HOME_NET any (msg:"CTI-LAB Port Scan SYN"; 
    flags:S,12; threshold:type threshold, track by_src, count 5, seconds 60; 
    sid:9000001; rev:1;)

alert tcp any any -> $HOME_NET 22 (msg:"CTI-LAB SSH Connection Attempt"; 
    flags:S,12; sid:9000002; rev:1;)
```

**Hasil Pilot:**

| Iterasi | Mode | T0 (UTC) | T1 (UTC) | MTTD (detik) | MTTR (detik) |
|---------|------|----------|----------|--------------|--------------|
| 1 | Manual | 15:59:35 | 15:59:37 | 2.68 | 74.97 |
| 2 | Manual | 16:03:11 | 16:03:12 | 1.10 | 53.20 |
| 3 | Manual | 16:09:58 | 16:10:00 | 2.04 | 50.10 |
| 4 | Manual | 16:11:53 | 16:11:54 | 1.31 | 48.94 |
| 5 | Manual | 16:13:51 | 16:13:52 | 1.38 | 57.11 |
| 6 | Dashboard | 16:18:26 | 16:18:28 | 2.69 | 49.91 |
| 7 | Dashboard | 16:20:58 | 16:21:04 | 6.61 | 53.02 |
| 8 | Dashboard | 16:24:42 | 16:24:42 | 0.70 | 74.50 |
| 9 | Dashboard | 16:42:39 | 16:42:41 | 2.25 | 62.76 |
| 10 | Dashboard | 16:45:28 | 16:45:33 | 4.55 | 62.34 |

**Ringkasan Statistik Pilot:**

| Mode | Avg MTTD | Avg MTTR |
|------|----------|----------|
| **Manual** | **1.70 detik** | **56.86 detik** |
| **Dashboard** | **3.36 detik** | **60.51 detik** |

Catatan: MTTD pilot menunjukkan deteksi otomatis oleh Suricata berjalan cepat (~1–4 detik). MTTR pilot
mencerminkan waktu mitigasi **manual** (analis mengeksekusi iptables secara interaktif, termasuk waktu
input password sudo), berbeda dari eksperimen terkontrol final yang menggunakan mitigasi otomatis
Wazuh *active response*.

---

#### Fase Final: 30 Iterasi Terkontrol (Eksperimen Penelitian Utama)

Eksperimen final dilaksanakan menggunakan tiga *custom rule* penelitian (SID 1000010/1000020/1000030)
dengan mitigasi **otomatis** Wazuh *active response* dan skrip orkestrasi `run_controlled_iterations.sh`.
Independensi antar-iterasi dijamin dengan reset blokir IP penyerang (`cti-unblock.sh`) di awal setiap iterasi.
Tiga skenario: Nmap (iterasi 1–10), Hydra SSH *brute force* (iterasi 11–20), Nikto web scan (iterasi 21–30).

Hasil rekapitulasi (30 iterasi, 100% terdeteksi, 0 *false negative*):

| Skenario | MITRE | MTTD rata² (s) | MTTD min–max | MTTR rata² (s) | MTTR min–max |
|----------|-------|---------------:|:------------:|---------------:|:------------:|
| Nmap  | T1046     | 2,5 | 1 – 6 | — (tidak ada) | — |
| Hydra | T1110.001 | 1,6 | 1 – 4 | 5,3 | 2 – 9 |
| Nikto | T1595.002 | 2,2 | 1 – 4 | 3,1 | 2 – 4 |

Sumber: `~/research-archive/2026-06-21_controlled-run/iterations.csv` (dijalankan 2026-06-24).
Rincian per-iterasi dan analisis lengkap tersedia di `draft-bab5-pengujian-dan-analisis.md`.

**Penyimpanan:** Hasil tersimpan ke indeks `cti-mttd-mttr-iqbal` di Elasticsearch.

---

### Task 8: Kibana Alerting Rules

**Tujuan:** Membuat 3 aturan alerting otomatis berbasis threshold di Kibana Basic.

**Pijakan Teori:** Chandola et al. (2009); NIST SP 800-94

**Prerequisite:** Penambahan `xpack.encryptedSavedObjects.encryptionKey` ke `/etc/kibana/kibana.yml`

**3 Rules yang Dibuat:**

| # | Nama Rule | Severity | Rule Type | Trigger Condition |
|---|-----------|----------|-----------|-------------------|
| 1 | CTI - Failed Login Threshold | HIGH | .es-query | >10 alert SSH dalam 5 menit |
| 2 | CTI - Port Scan Detection | CRITICAL | .es-query | >20 alert scan dalam 1 menit |
| 3 | CTI - New Threat Actor Detected | MEDIUM | .es-query | ≥1 alert dari IP baru dalam 10 menit |

**Detail Konfigurasi Rule 1 (Failed Login):**
- Index: `cti-logs-iqbal-*`
- Query: `alert.signature` contains "SSH"
- Time window: 5 menit
- Threshold: >10 hits
- Schedule: setiap 1 menit

**Detail Konfigurasi Rule 2 (Port Scan):**
- Index: `cti-logs-iqbal-*`
- Query: `alert.signature` contains "scan" OR "Nmap" OR "SCAN"
- Time window: 1 menit
- Threshold: >20 hits
- Schedule: setiap 1 menit

**Detail Konfigurasi Rule 3 (New Entity):**
- Index: `cti-logs-iqbal-*`
- Query: event dengan `src_ip` dan `alert.signature` yang bukan dari IP known (110, 106, 0.0.0.0, broadcast)
- Time window: 10 menit
- Threshold: ≥1 hit
- Schedule: setiap 5 menit

---

## 4. Optimisasi Sistem

### 4.1 Elasticsearch Heap

| Parameter | Sebelum | Sesudah |
|-----------|---------|---------|
| Heap Min (Xms) | Default (~1 GB) | 1536 MB |
| Heap Max (Xmx) | Default (~1 GB) | 1536 MB |
| File | - | `/etc/elasticsearch/jvm.options.d/heap.options` |

**Alasan:** Mencegah OOM Killer dengan membatasi heap secara eksplisit. Xms = Xmx menghindari resize heap saat runtime.

### 4.2 Refresh Interval

| Parameter | Sebelum | Sesudah |
|-----------|---------|---------|
| Refresh interval | 1 detik (default) | 30 detik |
| Scope | - | `cti-logs-iqbal-*` |

**Alasan:** Mengurangi beban I/O dan CPU. Untuk monitoring, refresh 30 detik sudah cukup.

### 4.3 Startup Delay

| Parameter | Nilai |
|-----------|-------|
| ExecStartPre delay | 30 detik |
| File | `/etc/systemd/system/elasticsearch.service.d/delay.conf` |

**Alasan:** Mencegah ES start bersamaan dengan service lain saat boot, menghindari OOM.

---

## 5. Daftar File Konfigurasi

| File | Lokasi | Fungsi |
|------|--------|--------|
| soc-pipeline.conf | `/etc/logstash/conf.d/` | Pipeline Logstash v3.3 (MITRE + Pyramid) |
| mitre-mapping.yml | `/etc/logstash/dictionaries/` | SID → technique_id |
| mitre-id-to-name.yml | `/etc/logstash/dictionaries/` | technique_id → name |
| mitre-id-to-tactic.yml | `/etc/logstash/dictionaries/` | technique_id → tactic |
| heap.options | `/etc/elasticsearch/jvm.options.d/` | Heap 1536 MB |
| delay.conf | `/etc/systemd/system/elasticsearch.service.d/` | Delay 30s |
| kibana.yml | `/etc/kibana/` | + encryptionKey |
| custom.rules | `/var/lib/suricata/rules/` | Custom research rules SID 1000010/1000020/1000030 |
| run_controlled_iterations.sh | `~/` | Skrip orkestrasi 30 iterasi MTTD/MTTR |
| cti-dashboard-v3-visualizations.ndjson | `~/eksperimen/` | 6 visualisasi Kibana |

---

## 6. Daftar Indeks Elasticsearch

| Indeks | Dokumen | Fungsi |
|--------|---------|--------|
| `cti-logs-iqbal-YYYY.MM.DD` | ~1.2 juta+ | Event utama (Suricata + enrichment) |
| `cti-threat-score-iqbal` | 3 | Output Continuous Transform (threat score per IP) |
| `cti-mttd-mttr-iqbal` | 30 | Hasil 30 iterasi pengujian terkontrol |

---

## 7. Hambatan dan Solusi

| # | Hambatan | Penyebab | Solusi |
|---|----------|----------|--------|
| 1 | ES OOM saat boot | Semua service start bersamaan | Delay 30s via systemd override |
| 2 | IP Kali berbeda dari proposal | Proposal tulis 101, aktual 110 | Update semua skrip dan dokumen |
| 3 | Username Victim berbeda | Proposal tulis iqbal, aktual korban | Update semua skrip |
| 4 | Format field berbeda SOC vs Victim | Filebeat SOC nested, Victim flat | Pipeline handle kedua format |
| 5 | Field source.ip bertipe text | Tidak bisa di-aggregasi | Pakai src_ip.keyword |
| 6 | Kibana Alerting error 500 | encryptionKey belum di-set | Tambah key ke kibana.yml |
| 7 | Suricata tidak trigger alert tiga skenario | Default rules tidak match; custom research rules belum ter-deploy | Custom rules SID 1000010/1000020/1000030 di-deploy ke `/var/lib/suricata/rules/custom.rules` |
| 8 | Filebeat Victim lambat forward | eve.json besar (29 MB) | Restart Filebeat + sleep 45s |
| 9 | rockyou.txt belum di-extract | Kali simpan compressed (.gz) | gunzip |
| 10 | Visualisasi threat-actors kosong | Field source_ip text, bukan keyword | Pakai source_ip.keyword |

---

## 8. Cara Replikasi (Untuk Sidang/Demo)

### 8.1 Startup Lab
```bash
# 1. Nyalakan VM (SOC, Victim, Kali) di VirtualBox
# 2. Di console Kali:
sudo systemctl start ssh

# 3. Di SOC — health check:
sudo systemctl is-active elasticsearch logstash kibana
ssh korban@192.168.56.106 "systemctl is-active suricata filebeat"

# 4. Kalau ES failed (OOM):
sudo pkill -f elasticsearch 2>/dev/null; sleep 3
sudo systemctl start elasticsearch; sleep 90
sudo systemctl is-active elasticsearch
```

### 8.2 Demo Attack + Dashboard
```bash
# Jalankan Nmap dari Kali:
ssh kali@192.168.56.110 'nmap -sS -T4 -p 1-200 192.168.56.106'

# Tunggu 45 detik, lalu refresh Kibana dashboard
# Alert akan muncul di visualisasi MITRE, Pyramid, dan Threat Actors
```

### 8.3 Lihat Hasil MTTD/MTTR
```bash
ES_PASS=$(cat ~/.elastic_password)
curl -sk -u elastic:${ES_PASS} \
  "https://localhost:9200/cti-mttd-mttr-iqbal/_search?size=10&sort=iteration:asc&pretty"
```

---

## 9. Kesimpulan Implementasi

Seluruh 8 task utama telah berhasil diimplementasikan dan divalidasi:

1. ✅ **Spec** — 9 requirements terdokumentasi
2. ✅ **Setup Lab** — 3 VM terhubung, NTP sinkron, SSH passwordless
3. ✅ **MITRE Enricher** — 25+ SID terpetakan ke teknik ATT&CK
4. ✅ **Pyramid Classifier** — 6 layer IOC terklasifikasi
5. ✅ **Threat Scorer** — Continuous Transform menghasilkan score per IP
6. ✅ **Visualisasi** — 6 panel V3 aktif di dashboard
7. ✅ **Pengujian MTTD/MTTR** — 30 iterasi terkontrol selesai (10 Nmap + 10 Hydra + 10 Nikto), data tersimpan di `iterations.csv`
8. ✅ **Alerting Rules** — 3 rules aktif (HIGH, CRITICAL, MEDIUM)

**Hasil utama (30 iterasi terkontrol, mitigasi otomatis Wazuh):** Sistem CTI Dashboard mampu mendeteksi
serangan dalam rata-rata **1,6 – 2,5 detik** (MTTD) dan merespons secara otomatis dalam rata-rata
**3,1 – 5,3 detik** (MTTR) untuk skenario Hydra dan Nikto. Skenario Nmap terdeteksi (MTTD 2,5 detik)
tanpa MTTR karena *reconnaissance* jaringan tidak memicu *active response* Wazuh.
