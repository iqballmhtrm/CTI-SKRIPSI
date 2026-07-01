# Pilar 2 — Deteksi Anomali & Aturan Deteksi

> **Tujuan Penelitian**: Membangun mekanisme deteksi berlapis (*defense in depth*)
> yang menggabungkan machine learning, event correlation, dan aturan deterministik
> untuk mengidentifikasi ancaman pada infrastruktur honeypot.

---

## Daftar Isi

1. [ML Anomaly Detection](#1-ml-anomaly-detection)
2. [EQL — Event Query Language](#2-eql--event-query-language)
3. [Deteksi Hybrid — Suricata NIDS + Wazuh HIDS](#3-deteksi-hybrid--suricata-nids--wazuh-hids)
4. [Detection Rules — Aturan Deteksi Kustom](#4-detection-rules--aturan-deteksi-kustom)
5. [Ringkasan Pemetaan Tujuan Penelitian](#5-ringkasan-pemetaan-tujuan-penelitian)

---

## 1. ML Anomaly Detection

> **Tujuan Penelitian yang Dipetakan**: Mendeteksi anomali volume dan pola serangan
> yang tidak dapat ditangkap oleh aturan statis (signature-based).

### 1.1 Konsep Dasar

Elastic ML Anomaly Detection menggunakan algoritma **unsupervised** yang mempelajari
baseline perilaku normal, kemudian menandai deviasi signifikan sebagai anomali.

| Tipe Job | Kegunaan | Contoh Kasus |
|---|---|---|
| Single Metric | Memantau satu metrik terhadap waktu | Lonjakan total serangan per jam |
| Multi Metric | Memantau beberapa metrik sekaligus | Volume serangan per taktik + per port |
| Population | Membandingkan entitas terhadap populasi | IP yang berperilaku beda dari mayoritas |

### 1.2 Single Metric Job — Langkah UI

1. **Kibana → Machine Learning → Anomaly Detection → Create job**.
2. Pilih data view: `honeypot-*`.
3. Pilih **Single metric**.
4. Konfigurasi:
   - **Aggregation**: `Count`.
   - **Bucket span**: `15m` (interval 15 menit).
   - **Time field**: `@timestamp`.
5. Beri nama job: `honeypot-attack-volume-single`.
6. Klik **Create job** → **Start job**.

### 1.3 Multi Metric Job — Langkah UI

1. **Create job → Multi metric**.
2. Konfigurasi:
   - **Detectors**:
     - Detector 1: `Count` — split by `mitre.tactic.keyword`.
     - Detector 2: `Distinct count of source.ip` — split by `destination.port`.
   - **Bucket span**: `15m`.
   - **Influencers**: `source.ip`, `mitre.tactic.keyword`, `destination.port`.
3. Beri nama job: `honeypot-multi-metric-tactic-port`.
4. Klik **Create job** → **Start job**.

### 1.4 Membuat ML Job via Dev Tools API

Berikut adalah API call lengkap untuk membuat Single Metric job melalui Dev Tools:

```json
PUT _ml/anomaly_detectors/honeypot-attack-volume-api
{
  "description": "Deteksi anomali volume serangan honeypot per 15 menit",
  "analysis_config": {
    "bucket_span": "15m",
    "detectors": [
      {
        "function": "count",
        "detector_description": "Jumlah total event serangan"
      }
    ],
    "influencers": [
      "source.ip",
      "mitre.tactic.keyword"
    ]
  },
  "data_description": {
    "time_field": "@timestamp",
    "time_format": "epoch_ms"
  },
  "analysis_limits": {
    "model_memory_limit": "256mb"
  },
  "results_index_name": "honeypot-anomaly-results"
}
```

Buka datafeed:

```json
PUT _ml/datafeeds/datafeed-honeypot-attack-volume-api
{
  "job_id": "honeypot-attack-volume-api",
  "indices": ["honeypot-*"],
  "query": {
    "bool": {
      "filter": [
        { "exists": { "field": "source.ip" } }
      ]
    }
  },
  "scroll_size": 1000
}
```

Jalankan datafeed:

```json
POST _ml/datafeeds/datafeed-honeypot-attack-volume-api/_start
{
  "start": "now-30d"
}
```

### 1.5 Multi Metric Job via API

```json
PUT _ml/anomaly_detectors/honeypot-multi-tactic-port-api
{
  "description": "Deteksi anomali multi-metrik: taktik MITRE dan port tujuan",
  "analysis_config": {
    "bucket_span": "15m",
    "detectors": [
      {
        "function": "count",
        "by_field_name": "mitre.tactic.keyword",
        "detector_description": "Volume serangan per taktik MITRE"
      },
      {
        "function": "distinct_count",
        "field_name": "source.ip",
        "by_field_name": "destination.port",
        "detector_description": "Jumlah IP unik per port tujuan"
      }
    ],
    "influencers": [
      "source.ip",
      "mitre.tactic.keyword",
      "destination.port"
    ]
  },
  "data_description": {
    "time_field": "@timestamp"
  },
  "analysis_limits": {
    "model_memory_limit": "512mb"
  }
}
```

### 1.6 Melihat Hasil Anomali

1. **Machine Learning → Anomaly Explorer**.
2. Filter berdasarkan **anomaly score** ≥ 75 (critical).
3. Klik titik anomali untuk melihat detail:
   - Nilai aktual vs. nilai ekspektasi.
   - Influencer utama (IP, taktik, port).
4. Dari sini, Anda bisa langsung membuat **alert rule** berdasarkan ML job.

---

## 2. EQL — Event Query Language

> **Tujuan Penelitian yang Dipetakan**: Mendeteksi rangkaian serangan multi-tahap
> (kill chain) menggunakan korelasi event berbasis urutan dan waktu.

### 2.1 Apa Itu EQL?

EQL (Event Query Language) adalah bahasa query khusus Elastic untuk mendeteksi
**urutan event** (sequences), bukan hanya event tunggal. Sangat cocok untuk:

- Mendeteksi kill chain: reconnaissance → exploitation → post-exploitation.
- Korelasi antar event dengan batasan waktu (*maxspan*).
- Menghubungkan event berdasarkan field yang sama (*join key*).

### 2.2 Navigasi EQL di Kibana

1. **Kibana → Security → Timelines**.
2. Klik **Create new timeline**.
3. Pada bagian atas, pilih tab **Correlation** (atau **EQL**).
4. Masukkan query EQL di editor.
5. Klik **▶ Run** untuk menjalankan query.
6. Hasil akan ditampilkan sebagai timeline event yang terkorelasi.

Alternatif via Dev Tools:

```
POST honeypot-*/_eql/search
{
  "query": "<EQL_QUERY_HERE>",
  "timestamp_field": "@timestamp",
  "event_category_field": "event.category"
}
```

### 2.3 Query EQL #1 — Port Scan Diikuti Brute Force

**Skenario**: Penyerang melakukan port scanning terlebih dahulu, kemudian dalam 5 menit
melanjutkan dengan brute force SSH dari IP yang sama.

```eql
sequence by source.ip with maxspan=5m
  [network where event.action == "port_scan" or
   (destination.port != null and event.category == "network_traffic")]
  [authentication where event.outcome == "failure" and
   destination.port == 22 and event.action == "ssh_login"]
```

**Penjelasan**:

| Komponen | Fungsi |
|---|---|
| `sequence by source.ip` | Mengelompokkan urutan berdasarkan IP sumber yang sama |
| `with maxspan=5m` | Kedua event harus terjadi dalam rentang 5 menit |
| Event pertama `[network ...]` | Menangkap aktivitas port scanning |
| Event kedua `[authentication ...]` | Menangkap percobaan login SSH yang gagal |

**Catatan**: Sesuaikan `event.action` dengan nilai yang dihasilkan oleh pipeline
Suricata/Cowrie Anda. Periksa dengan:

```
GET honeypot-*/_terms_enum
{
  "field": "event.action",
  "size": 50
}
```

### 2.4 Query EQL #2 — Brute Force SSH (>10 Percobaan Gagal)

**Skenario**: Satu IP melakukan lebih dari 10 percobaan SSH gagal secara berurutan.

```eql
sequence by source.ip with maxspan=2m
  [authentication where event.outcome == "failure" and
   destination.port == 22] with runs=10
```

**Penjelasan**:

| Komponen | Fungsi |
|---|---|
| `with runs=10` | Event yang sama harus terjadi minimal 10 kali berturut-turut |
| `with maxspan=2m` | Seluruh 10 event harus terjadi dalam 2 menit |

**Alternatif tanpa `runs`** (jika versi EQL tidak mendukung):

```eql
sequence by source.ip with maxspan=2m
  [authentication where event.outcome == "failure" and destination.port == 22]
  [authentication where event.outcome == "failure" and destination.port == 22]
  [authentication where event.outcome == "failure" and destination.port == 22]
  [authentication where event.outcome == "failure" and destination.port == 22]
  [authentication where event.outcome == "failure" and destination.port == 22]
  [authentication where event.outcome == "failure" and destination.port == 22]
  [authentication where event.outcome == "failure" and destination.port == 22]
  [authentication where event.outcome == "failure" and destination.port == 22]
  [authentication where event.outcome == "failure" and destination.port == 22]
  [authentication where event.outcome == "failure" and destination.port == 22]
```

> [!TIP]
> Untuk kasus threshold seperti ini, pertimbangkan juga menggunakan
> **Threshold Detection Rule** (lihat Bagian 4) yang lebih efisien.

### 2.5 Query EQL #3 — Web Scanning Diikuti Eksploitasi

**Skenario**: Penyerang melakukan web scanning (HTTP request ke banyak path)
kemudian dalam 10 menit mengirim payload eksploitasi.

```eql
sequence by source.ip with maxspan=10m
  [network where destination.port in (80, 443, 8080, 8443) and
   event.action == "http_request" and
   (url.path : ("/admin*", "/wp-login*", "/phpmyadmin*", "/.env",
    "/config*", "/backup*", "/shell*", "/cmd*"))]
  [intrusion_detection where event.kind == "alert" and
   (rule.name : ("*SQL Injection*", "*XSS*", "*RCE*", "*Command Injection*",
    "*Path Traversal*", "*LFI*", "*RFI*"))]
```

**Penjelasan**:

| Komponen | Fungsi |
|---|---|
| Event pertama | Menangkap HTTP request ke path yang umum di-scan |
| Event kedua | Menangkap alert Suricata/Wazuh yang mendeteksi serangan web |
| `url.path : ("/admin*", ...)` | Wildcard matching pada path URL |
| `rule.name : ("*SQL Injection*", ...)` | Wildcard matching pada nama rule IDS |

### 2.6 Menyimpan Query EQL sebagai Template

1. Setelah query berhasil di Timeline, klik **Save timeline**.
2. Beri nama deskriptif: `[EQL] Port Scan → Brute Force Sequence`.
3. Timeline yang tersimpan bisa diakses di **Security → Timelines**.
4. Dari sini, Anda juga bisa langsung membuat **Detection Rule** dari query EQL
   (lihat Bagian 4.3).

---

## 3. Deteksi Hybrid — Suricata NIDS + Wazuh HIDS

> **Tujuan Penelitian yang Dipetakan**: Membangun arsitektur deteksi berlapis
> yang menggabungkan visibilitas jaringan (NIDS) dan host (HIDS).

### 3.1 Perbandingan NIDS vs HIDS

| Aspek | Suricata (NIDS) | Wazuh (HIDS) |
|---|---|---|
| **Layer** | Network (Layer 3-7) | Host / Endpoint |
| **Posisi** | Inline atau mirrored traffic | Agent di setiap host |
| **Kekuatan** | Deteksi exploit jaringan, DDoS, C2 traffic | File integrity, rootkit, log anomaly |
| **Kelemahan** | Buta terhadap encrypted traffic (tanpa SSL inspection) | Tidak melihat traffic jaringan lateral |
| **Index di Elastic** | `suricata-*` atau `filebeat-suricata-*` | `wazuh-alerts-*` |
| **Event Category** | `intrusion_detection`, `network` | `intrusion_detection`, `host`, `process` |

### 3.2 Bagaimana Keduanya Saling Melengkapi

```
┌──────────────────────────────────────────────────────────────┐
│                    INTERNET                                  │
│                       │                                      │
│              ┌────────▼────────┐                             │
│              │   Suricata NIDS │ ← Menangkap traffic masuk   │
│              │   (Network)     │   ke honeypot               │
│              └────────┬────────┘                             │
│                       │                                      │
│              ┌────────▼────────┐                             │
│              │  Honeypot Host  │                             │
│              │  ┌─────────────┐│                             │
│              │  │ Wazuh Agent ││ ← Memantau aktivitas di     │
│              │  │ (HIDS)      ││   dalam host honeypot       │
│              │  └─────────────┘│                             │
│              │  ┌─────────────┐│                             │
│              │  │ Cowrie SSH   ││ ← Honeypot service          │
│              │  │ DionaeaHTTP ││                             │
│              │  └─────────────┘│                             │
│              └────────┬────────┘                             │
│                       │                                      │
│              ┌────────▼────────┐                             │
│              │  Elasticsearch  │ ← Semua data terindeks      │
│              │  + Kibana       │   di satu tempat             │
│              └─────────────────┘                             │
└──────────────────────────────────────────────────────────────┘
```

### 3.3 Skenario Deteksi Hybrid

#### Skenario A: Brute Force SSH

| Tahap | Suricata | Wazuh |
|---|---|---|
| 1. SYN Flood ke port 22 | ✅ Alert: `ET SCAN Potential SSH Scan` | — |
| 2. Login attempts | ✅ Alert: `ET EXPLOIT SSH Brute Force` | ✅ Alert: rule 5710 (sshd auth failure) |
| 3. Login berhasil | — | ✅ Alert: rule 5715 (sshd auth success) |
| 4. Command execution | — | ✅ Alert: rule 550 (suspicious command) |

#### Skenario B: Web Exploitation

| Tahap | Suricata | Wazuh |
|---|---|---|
| 1. HTTP scanning | ✅ Alert: `ET SCAN Nikto/DirBuster` | — |
| 2. SQL Injection | ✅ Alert: `ET WEB_SERVER SQL Injection` | ✅ Alert: web log anomaly |
| 3. File upload (webshell) | — | ✅ Alert: FIM (new file detected) |
| 4. Reverse shell | ✅ Alert: `ET MALWARE Reverse Shell` | ✅ Alert: suspicious process |

### 3.4 Korelasi di Elastic Security

Untuk mengorelasikan alert dari kedua sumber:

```kql
event.module: ("suricata" OR "wazuh") AND source.ip: "203.0.113.50"
```

Atau gunakan EQL sequence yang menggabungkan event dari kedua index:

```eql
sequence by source.ip with maxspan=10m
  [intrusion_detection where event.module == "suricata" and
   rule.name : "*Scan*"]
  [intrusion_detection where event.module == "wazuh" and
   rule.name : "*authentication*failure*"]
```

> [!IMPORTANT]
> Agar korelasi cross-index berfungsi, pastikan kedua index menggunakan
> skema field yang konsisten (ECS - Elastic Common Schema). Verifikasi
> bahwa `source.ip`, `event.category`, dan `event.module` terisi di kedua index.

---

## 4. Detection Rules — Aturan Deteksi Kustom

> **Tujuan Penelitian yang Dipetakan**: Mengimplementasikan aturan deteksi yang
> menghasilkan alert terstruktur untuk diproses oleh SOAR dan dihitung MTTD-nya.

### 4.1 Jenis Detection Rule di Elastic Security

| Tipe Rule | Kegunaan | Contoh |
|---|---|---|
| **Custom query (KQL)** | Deteksi berdasarkan kondisi match | Alert jika ada SSH login dari IP baru |
| **Threshold** | Deteksi berdasarkan jumlah event melebihi ambang | >20 SSH failure dalam 1 menit |
| **EQL** | Deteksi urutan event | Port scan → brute force (lihat Bagian 2) |
| **Machine Learning** | Deteksi anomali dari ML job | Anomaly score > 75 |
| **Indicator Match** | Deteksi IOC dari threat intel feed | IP match dengan IOC feed |
| **New Terms** | Deteksi nilai baru yang belum pernah muncul | Negara baru di GeoIP |

### 4.2 Membuat KQL Detection Rule

1. **Kibana → Security → Rules → Create new rule**.
2. Pilih **Custom query**.
3. Konfigurasi:

**Index patterns**:
```
honeypot-*
suricata-*
wazuh-alerts-*
```

**KQL Query** — Deteksi serangan severity tinggi:
```kql
event.kind: "alert" AND event.severity <= 2 AND
(event.module: "suricata" OR event.module: "wazuh")
```

4. **About** (Metadata rule):
   - **Name**: `[Honeypot] High Severity Attack Detected`
   - **Description**: Mendeteksi alert dengan severity 1 (critical) atau 2 (high)
     dari Suricata atau Wazuh.
   - **Severity**: `Critical`
   - **Risk score**: `90`
   - **MITRE ATT&CK**: pilih taktik yang sesuai (misal: Initial Access, Execution).
   - **Tags**: `honeypot`, `high-severity`, `auto-response`

5. **Schedule**:
   - **Runs every**: `1 minute`
   - **Additional look-back time**: `5 minutes`

6. **Actions** (Webhook ke SOAR):
   - Pilih connector: **Webhook**.
   - URL: `http://<SOAR_HOST>:5000/api/webhook/elastic-alert`
   - Method: `POST`
   - Headers: `Content-Type: application/json`
   - Body:

```json
{
  "rule_name": "{{rule.name}}",
  "alert_id": "{{alert.id}}",
  "severity": "{{rule.severity}}",
  "source_ip": "{{context.alerts[0].source.ip}}",
  "mitre_tactic": "{{context.alerts[0].mitre.tactic}}",
  "timestamp": "{{context.alerts[0].@timestamp}}",
  "description": "{{rule.description}}"
}
```

7. Klik **Create & activate rule**.

### 4.3 Membuat Threshold Detection Rule

1. **Create new rule → Threshold**.
2. Konfigurasi:

**Index patterns**: `honeypot-*`

**KQL Query**:
```kql
event.action: "ssh_login" AND event.outcome: "failure"
```

**Threshold**:
- **Group by**: `source.ip`
- **Threshold**: `20`
- **Timestamp field**: `@timestamp`

3. **About**:
   - **Name**: `[Honeypot] SSH Brute Force - Threshold Exceeded`
   - **Severity**: `High`
   - **Risk score**: `75`
   - **MITRE ATT&CK**: `Credential Access` → `Brute Force` (T1110)

4. **Schedule**: Runs every `1 minute`, look-back `5 minutes`.

5. **Actions**: Webhook ke SOAR (sama seperti di atas).

### 4.4 Membuat EQL Detection Rule

1. **Create new rule → Event Correlation (EQL)**.
2. Masukkan query EQL dari Bagian 2.3, 2.4, atau 2.5.
3. Contoh — Port Scan → Brute Force:

```eql
sequence by source.ip with maxspan=5m
  [network where event.action == "port_scan"]
  [authentication where event.outcome == "failure" and destination.port == 22]
```

4. **About**:
   - **Name**: `[Honeypot] Recon to Brute Force Kill Chain`
   - **Severity**: `Critical`
   - **Risk score**: `85`
   - **MITRE ATT&CK**: `Reconnaissance` → `Active Scanning` (T1595),
     kemudian `Credential Access` → `Brute Force` (T1110)

5. **Schedule & Actions**: sama seperti rule sebelumnya.

### 4.5 Membuat ML Detection Rule

1. **Create new rule → Machine Learning**.
2. Pilih ML job: `honeypot-attack-volume-api` (dari Bagian 1).
3. **Anomaly score threshold**: `75`.
4. **About**:
   - **Name**: `[Honeypot] ML Anomaly - Unusual Attack Volume`
   - **Severity**: `Medium`

### 4.6 Verifikasi Rule Berjalan

```json
GET _security/rules/_find?per_page=10&sort_field=name&sort_order=asc
```

Atau melalui UI: **Security → Rules → Rule monitoring tab** — periksa:
- **Last response**: harus `succeeded`.
- **Gap**: harus `0` (tidak ada data yang terlewat).

### 4.7 Monitoring Performa Rule

Periksa apakah rule berjalan tanpa error:

```kql
# Di Discover, filter log Kibana:
event.provider: "detection_engine" AND event.action: "status-change"
```

---

## 5. Ringkasan Pemetaan Tujuan Penelitian

| Komponen Deteksi | Tujuan Penelitian | Tipe Deteksi |
|---|---|---|
| ML Anomaly Detection | Deteksi anomali non-signature | Unsupervised ML |
| EQL Sequences | Deteksi kill chain multi-tahap | Korelasi event |
| Suricata + Wazuh Hybrid | Visibilitas network + host | Defense in depth |
| KQL Detection Rules | Deteksi real-time berbasis kondisi | Signature-based |
| Threshold Rules | Deteksi volume berlebih | Statistical threshold |

---

> **Catatan**: Semua detection rule di atas dirancang untuk mengirim alert ke
> SOAR Dashboard melalui webhook. Timestamp alert yang dihasilkan akan digunakan
> di Pilar 3 untuk menghitung MTTD (Mean Time to Detect).

---

*Dokumen ini merupakan bagian dari Pilar 2 — Proyek Riset CTI Skripsi.*
*Terakhir diperbarui: 16 Juni 2026*
