# Pilar 3 — Monitoring MTTD & MTTR

> **Tujuan Penelitian**: Mengukur efektivitas sistem deteksi dan respons melalui
> metrik kuantitatif MTTD (Mean Time to Detect) dan MTTR (Mean Time to Respond),
> serta membangun mekanisme alerting dan case management yang terintegrasi.

---

## Daftar Isi

1. [ES|QL Queries untuk MTTD & MTTR](#1-esql-queries-untuk-mttd--mttr)
2. [Alerting Rules — Aturan Peringatan](#2-alerting-rules--aturan-peringatan)
3. [Cases — Manajemen Investigasi](#3-cases--manajemen-investigasi)
4. [SOAR Webhook Integration](#4-soar-webhook-integration)
5. [Ringkasan Pemetaan Tujuan Penelitian](#5-ringkasan-pemetaan-tujuan-penelitian)

---

## 1. ES|QL Queries untuk MTTD & MTTR

> **Tujuan Penelitian yang Dipetakan**: Menghitung metrik kuantitatif MTTD dan MTTR
> sebagai indikator utama efektivitas sistem CTI.

### 1.1 Definisi Metrik

| Metrik | Definisi | Formula |
|---|---|---|
| **MTTD** | Mean Time to Detect | `avg(waktu_alert_pertama - waktu_serangan_terjadi)` |
| **MTTR** | Mean Time to Respond | `avg(waktu_respons_selesai - waktu_alert_pertama)` |

**Asumsi field mapping**:

| Field | Sumber | Deskripsi |
|---|---|---|
| `@timestamp` | Suricata / Cowrie / Wazuh | Waktu event serangan terjadi |
| `kibana.alert.start` | Elastic Security alerts index | Waktu alert pertama kali dibuat |
| `kibana.alert.rule.name` | Elastic Security alerts index | Nama detection rule |
| `event.action` | Honeypot logs | Jenis aksi serangan |
| `response.timestamp` | SOAR Dashboard (SQLite → index) | Waktu respons selesai dilakukan |

> [!IMPORTANT]
> ES|QL adalah bahasa query baru di Elasticsearch (≥ 8.11). Pastikan versi
> Elasticsearch Anda mendukung ES|QL. Untuk versi lama, gunakan alternatif
> Elasticsearch SQL atau KQL aggregation yang disediakan di setiap bagian.

### 1.2 Query #1 — MTTD: Selisih Waktu Serangan dan Alert Pertama

```esql
FROM .internal.alerts-security.alerts-default-*
| WHERE kibana.alert.status == "active" OR kibana.alert.status == "acknowledged"
| EVAL attack_time = TO_DATETIME(kibana.alert.original_time)
| EVAL alert_time = TO_DATETIME(kibana.alert.start)
| EVAL mttd_seconds = DATE_DIFF("seconds", attack_time, alert_time)
| EVAL mttd_minutes = mttd_seconds / 60.0
| KEEP kibana.alert.rule.name, source.ip, attack_time, alert_time, mttd_seconds, mttd_minutes
| SORT mttd_seconds DESC
| LIMIT 100
```

**Penjelasan baris per baris**:

| Baris | Fungsi |
|---|---|
| `FROM .internal.alerts-*` | Membaca dari index alert internal Elastic Security |
| `EVAL attack_time` | Mengkonversi waktu event asli (kapan serangan terjadi) |
| `EVAL alert_time` | Mengkonversi waktu alert dibuat oleh detection rule |
| `DATE_DIFF("seconds", ...)` | Menghitung selisih dalam detik |
| `mttd_minutes` | Konversi ke menit agar lebih mudah dibaca |

### 1.3 Query #2 — MTTR: Selisih Waktu Alert dan Respons

```esql
FROM soar-response-log-*
| WHERE response.status == "completed"
| EVAL alert_time = TO_DATETIME(response.alert_timestamp)
| EVAL response_time = TO_DATETIME(response.completed_timestamp)
| EVAL mttr_seconds = DATE_DIFF("seconds", alert_time, response_time)
| EVAL mttr_minutes = mttr_seconds / 60.0
| KEEP response.alert_id, response.action_type, alert_time, response_time,
       mttr_seconds, mttr_minutes
| SORT mttr_seconds DESC
| LIMIT 100
```

> [!NOTE]
> Index `soar-response-log-*` diisi oleh SOAR Dashboard Flask yang mengirim
> data respons ke Elasticsearch. Lihat Bagian 4 untuk detail integrasi.

### 1.4 Query #3 — Rata-rata MTTD/MTTR Berdasarkan Tipe Serangan

```esql
FROM .internal.alerts-security.alerts-default-*
| WHERE kibana.alert.status != "closed"
| EVAL attack_time = TO_DATETIME(kibana.alert.original_time)
| EVAL alert_time = TO_DATETIME(kibana.alert.start)
| EVAL mttd_seconds = DATE_DIFF("seconds", attack_time, alert_time)
| STATS avg_mttd_sec = AVG(mttd_seconds),
        min_mttd_sec = MIN(mttd_seconds),
        max_mttd_sec = MAX(mttd_seconds),
        total_alerts = COUNT(*)
  BY kibana.alert.rule.name
| EVAL avg_mttd_min = ROUND(avg_mttd_sec / 60.0, 2)
| SORT avg_mttd_sec ASC
```

**Contoh output yang diharapkan**:

| `kibana.alert.rule.name` | `avg_mttd_sec` | `avg_mttd_min` | `total_alerts` |
|---|---|---|---|
| [Honeypot] SSH Brute Force - Threshold | 45.2 | 0.75 | 342 |
| [Honeypot] High Severity Attack | 62.8 | 1.05 | 128 |
| [Honeypot] Recon to Brute Force Kill Chain | 180.5 | 3.01 | 47 |
| [Honeypot] ML Anomaly - Unusual Volume | 900.0 | 15.00 | 12 |

Untuk **MTTR per tipe respons**:

```esql
FROM soar-response-log-*
| WHERE response.status == "completed"
| EVAL alert_time = TO_DATETIME(response.alert_timestamp)
| EVAL response_time = TO_DATETIME(response.completed_timestamp)
| EVAL mttr_seconds = DATE_DIFF("seconds", alert_time, response_time)
| STATS avg_mttr_sec = AVG(mttr_seconds),
        min_mttr_sec = MIN(mttr_seconds),
        max_mttr_sec = MAX(mttr_seconds),
        total_responses = COUNT(*)
  BY response.action_type
| EVAL avg_mttr_min = ROUND(avg_mttr_sec / 60.0, 2)
| SORT avg_mttr_sec ASC
```

### 1.5 Query #4 — Tren MTTD Selama 7 Hari

```esql
FROM .internal.alerts-security.alerts-default-*
| WHERE kibana.alert.start >= NOW() - 7 days
| EVAL attack_time = TO_DATETIME(kibana.alert.original_time)
| EVAL alert_time = TO_DATETIME(kibana.alert.start)
| EVAL mttd_seconds = DATE_DIFF("seconds", attack_time, alert_time)
| EVAL day_bucket = DATE_FORMAT(alert_time, "yyyy-MM-dd")
| STATS avg_mttd_sec = AVG(mttd_seconds),
        median_mttd_sec = MEDIAN(mttd_seconds),
        p95_mttd_sec = PERCENTILE(mttd_seconds, 95),
        total_alerts = COUNT(*)
  BY day_bucket
| EVAL avg_mttd_min = ROUND(avg_mttd_sec / 60.0, 2)
| SORT day_bucket ASC
```

**Contoh output yang diharapkan**:

| `day_bucket` | `avg_mttd_sec` | `avg_mttd_min` | `median_mttd_sec` | `p95_mttd_sec` | `total_alerts` |
|---|---|---|---|---|---|
| 2026-06-10 | 58.3 | 0.97 | 42.0 | 210.0 | 85 |
| 2026-06-11 | 52.1 | 0.87 | 38.0 | 195.0 | 92 |
| 2026-06-12 | 45.7 | 0.76 | 35.0 | 180.0 | 78 |
| ... | ... | ... | ... | ... | ... |

**Tren menurun** menunjukkan bahwa sistem deteksi semakin cepat merespons serangan,
yang merupakan indikator positif efektivitas CTI.

### 1.6 Visualisasi Hasil ES|QL

Hasil query ES|QL dapat langsung divisualisasikan:

1. **Discover → New → ES|QL** mode.
2. Jalankan query di atas.
3. Klik **Visualize** di toolbar untuk membuat chart dari hasil.
4. Untuk tren 7 hari, pilih **Line chart** dengan `day_bucket` di sumbu X
   dan `avg_mttd_min` di sumbu Y.
5. **Save** ke dashboard Pilar 3.

### 1.7 Alternatif: Elasticsearch SQL (untuk versi lama)

Jika ES|QL belum tersedia:

```sql
SELECT
  DATE_FORMAT("@timestamp", 'yyyy-MM-dd') AS hari,
  AVG(DATEDIFF('second', "@timestamp", "kibana.alert.start")) AS avg_mttd_sec,
  COUNT(*) AS total_alerts
FROM ".internal.alerts-security.alerts-default-*"
WHERE "kibana.alert.start" >= CURRENT_TIMESTAMP - INTERVAL 7 DAY
GROUP BY DATE_FORMAT("@timestamp", 'yyyy-MM-dd')
ORDER BY hari ASC
```

---

## 2. Alerting Rules — Aturan Peringatan

> **Tujuan Penelitian yang Dipetakan**: Mengotomatiskan deteksi dan notifikasi ancaman
> agar MTTD dapat diminimalkan melalui respons yang lebih cepat.

### 2.1 Prasyarat

| Komponen | Keterangan |
|---|---|
| Connector | Webhook connector sudah dikonfigurasi ke SOAR Flask app |
| Index | `honeypot-*`, `suricata-*`, `wazuh-alerts-*` |
| Lisensi | Basic (untuk KQL rules) atau Trial (untuk ML rules) |

Buat Webhook Connector terlebih dahulu:

1. **Management → Stack Management → Connectors → Create connector**.
2. Pilih **Webhook**.
3. Konfigurasi:
   - **Name**: `SOAR Dashboard Webhook`
   - **URL**: `http://<SOAR_HOST>:5000/api/webhook/elastic-alert`
   - **Method**: POST
   - **Headers**: `Content-Type: application/json`
   - **Authentication**: None (atau Basic auth jika dikonfigurasi)
4. **Save & test** dengan sample payload.

### 2.2 Alert Rule #1 — Serangan Severity Tinggi

**Tujuan**: Mengirim alert ke SOAR ketika Suricata atau Wazuh mendeteksi serangan
dengan severity ≤ 2 (critical atau high).

#### Langkah-Langkah (UI)

1. **Security → Rules → Create new rule**.
2. **Rule type**: Custom query.
3. **Index patterns**: `suricata-*`, `wazuh-alerts-*`
4. **Query (KQL)**:

```kql
event.kind: "alert" AND event.severity <= 2
```

5. **About**:
   - **Name**: `[CTI] High Severity Attack → SOAR Webhook`
   - **Severity**: `Critical`
   - **Risk score**: `90`
   - **MITRE ATT&CK**: sesuaikan dengan taktik yang relevan
   - **Tags**: `cti-pilar3`, `auto-response`, `mttd-tracking`
6. **Schedule**:
   - **Runs every**: `1m`
   - **Additional look-back**: `5m`
7. **Actions**:
   - Connector: `SOAR Dashboard Webhook`
   - Body:

```json
{
  "alert_type": "high_severity",
  "rule_name": "{{rule.name}}",
  "alert_id": "{{alert.id}}",
  "severity": {{rule.params.severity}},
  "risk_score": {{rule.params.riskScore}},
  "source_ip": "{{context.alerts[0].source.ip}}",
  "destination_port": "{{context.alerts[0].destination.port}}",
  "mitre_tactic": "{{context.alerts[0].threat.tactic.name}}",
  "mitre_technique": "{{context.alerts[0].threat.technique.name}}",
  "original_timestamp": "{{context.alerts[0].@timestamp}}",
  "alert_timestamp": "{{date}}",
  "kibana_url": "https://<KIBANA_HOST>:5601/app/security/alerts/{{alert.id}}"
}
```

8. Klik **Create & activate rule**.

### 2.3 Alert Rule #2 — SSH Brute Force Threshold

**Tujuan**: Mendeteksi >20 percobaan SSH gagal dari satu IP dalam 1 menit.

#### Langkah-Langkah (UI)

1. **Security → Rules → Create new rule**.
2. **Rule type**: Threshold.
3. **Index patterns**: `honeypot-*`
4. **Query (KQL)**:

```kql
event.action: "ssh_login" AND event.outcome: "failure" AND destination.port: 22
```

5. **Threshold configuration**:
   - **Group by**: `source.ip`
   - **Threshold**: `20`
6. **About**:
   - **Name**: `[CTI] SSH Brute Force > 20 Attempts/min → SOAR`
   - **Severity**: `High`
   - **Risk score**: `75`
   - **MITRE ATT&CK**: `Credential Access` → `Brute Force` (T1110)
   - **Tags**: `cti-pilar3`, `brute-force`, `ssh`
7. **Schedule**:
   - **Runs every**: `1m`
   - **Additional look-back**: `2m`
8. **Actions**: Webhook ke SOAR dengan body:

```json
{
  "alert_type": "brute_force_ssh",
  "rule_name": "{{rule.name}}",
  "alert_id": "{{alert.id}}",
  "source_ip": "{{context.alerts[0].source.ip}}",
  "attempt_count": "{{context.alerts[0].threshold_result.count}}",
  "time_window": "1m",
  "alert_timestamp": "{{date}}",
  "recommended_action": "block_ip"
}
```

### 2.4 Alert Rule #3 — Negara Baru di GeoIP (New Terms / Rare Value)

**Tujuan**: Mendeteksi ketika serangan datang dari negara yang belum pernah
tercatat sebelumnya dalam 30 hari terakhir.

#### Langkah-Langkah (UI)

1. **Security → Rules → Create new rule**.
2. **Rule type**: New Terms.
3. **Index patterns**: `honeypot-*`
4. **Query (KQL)**:

```kql
source.geo.country_name: * AND event.kind: "alert"
```

5. **New Terms configuration**:
   - **Fields**: `source.geo.country_name`
   - **History window size**: `30d` (bandingkan dengan 30 hari terakhir)
6. **About**:
   - **Name**: `[CTI] New Country Detected in GeoIP → SOAR`
   - **Severity**: `Medium`
   - **Risk score**: `50`
   - **MITRE ATT&CK**: `Reconnaissance` → `Gather Victim Network Information` (T1590)
   - **Tags**: `cti-pilar3`, `geoip`, `new-country`
7. **Schedule**:
   - **Runs every**: `5m`
   - **Additional look-back**: `10m`
8. **Actions**: Webhook ke SOAR:

```json
{
  "alert_type": "new_country_geoip",
  "rule_name": "{{rule.name}}",
  "alert_id": "{{alert.id}}",
  "new_country": "{{context.alerts[0].source.geo.country_name}}",
  "source_ip": "{{context.alerts[0].source.ip}}",
  "alert_timestamp": "{{date}}",
  "recommended_action": "investigate"
}
```

### 2.5 Ringkasan Alert Rules

| Rule | Tipe | Trigger | Severity | Aksi SOAR |
|---|---|---|---|---|
| High Severity Attack | Custom query | severity ≤ 2 | Critical | Auto-investigate |
| SSH Brute Force | Threshold | >20/menit per IP | High | Block IP |
| New Country GeoIP | New Terms | Negara baru (30d window) | Medium | Manual investigate |

---

## 3. Cases — Manajemen Investigasi

> **Tujuan Penelitian yang Dipetakan**: Mendokumentasikan proses investigasi insiden
> dan mengukur waktu penyelesaian (MTTR) secara terstruktur.

### 3.1 Membuat Case Baru

1. **Kibana → Security → Cases → Create case**.
2. Isi form:
   - **Title**: `[INV-2026-001] Brute Force SSH dari 203.0.113.50`
   - **Description**:
     ```
     Terdeteksi >200 percobaan login SSH gagal dari IP 203.0.113.50
     dalam 10 menit terakhir. IP berasal dari Rusia (GeoIP).
     Perlu investigasi apakah ini bagian dari kampanye yang lebih besar.
     ```
   - **Tags**: `brute-force`, `ssh`, `high-priority`
   - **Severity**: `High`
   - **Assignee**: Pilih analis yang bertanggung jawab
3. Klik **Create case**.

### 3.2 Menambahkan Alert ke Case

1. **Security → Alerts** → pilih alert yang relevan.
2. Klik **⋮ (more actions) → Add to existing case**.
3. Pilih case yang sudah dibuat.
4. Alert akan ter-link ke case dengan metadata lengkap.

Atau dari **Timelines**:
1. Buat timeline baru, jalankan query terkait.
2. Klik **Attach to case** pada timeline.

### 3.3 Investigasi & Dokumentasi

Dalam case, tambahkan **comments** untuk mendokumentasikan langkah investigasi:

```markdown
## Langkah Investigasi

### 1. Analisis IP Sumber
- IP: 203.0.113.50
- GeoIP: Moscow, Russia
- Cek di AbuseIPDB: Confidence Score 95% (malicious)
- Sudah ada di threat intel feed internal

### 2. Analisis Pola Serangan
- Total percobaan: 847 dalam 1 jam
- Username yang dicoba: root, admin, ubuntu, test
- Password pattern: dictionary attack

### 3. Dampak
- Tidak ada login berhasil (Cowrie honeypot)
- Tidak ada lateral movement terdeteksi

### 4. Rekomendasi
- [x] Block IP di firewall (sudah dilakukan via SOAR)
- [x] Tambahkan ke IOC feed internal
- [ ] Monitor IP terkait dari subnet yang sama
```

### 3.4 Menutup Case & Mengukur MTTR

1. Setelah investigasi selesai, ubah status case ke **Closed**.
2. Tambahkan comment penutup dengan ringkasan resolusi.
3. Waktu antara **case creation** dan **case closure** = **MTTR** untuk case tersebut.

### 3.5 Query ES|QL untuk Mengekstrak MTTR dari Cases

```esql
FROM .internal.alerts-security.alerts-default-*
| WHERE kibana.alert.workflow_status == "closed"
| EVAL alert_time = TO_DATETIME(kibana.alert.start)
| EVAL close_time = TO_DATETIME(kibana.alert.end)
| EVAL resolution_seconds = DATE_DIFF("seconds", alert_time, close_time)
| EVAL resolution_minutes = ROUND(resolution_seconds / 60.0, 2)
| STATS avg_resolution_min = AVG(resolution_minutes),
        median_resolution_min = MEDIAN(resolution_minutes),
        total_closed = COUNT(*)
  BY kibana.alert.rule.name
| SORT avg_resolution_min ASC
```

---

## 4. SOAR Webhook Integration

> **Tujuan Penelitian yang Dipetakan**: Mengintegrasikan deteksi (Elastic Security)
> dengan respons otomatis (SOAR Dashboard) untuk mengukur MTTR secara end-to-end.

### 4.1 Arsitektur Integrasi

```
┌─────────────────┐     Webhook POST      ┌─────────────────────┐
│ Elastic Security │ ──────────────────►   │  Flask SOAR App     │
│ Detection Rules  │                       │  /api/webhook/      │
│                  │                       │  elastic-alert      │
└─────────────────┘                       └──────────┬──────────┘
                                                      │
                                          ┌───────────▼──────────┐
                                          │  SQLite Database     │
                                          │  - alert_log         │
                                          │  - response_log      │
                                          │  - mttd_mttr_calc    │
                                          └───────────┬──────────┘
                                                      │
                                          ┌───────────▼──────────┐
                                          │  (Opsional) Index    │
                                          │  ke Elasticsearch    │
                                          │  soar-response-log-* │
                                          └──────────────────────┘
```

### 4.2 Flask Webhook Endpoint

Berikut adalah kode endpoint Flask yang menerima alert dari Elastic Security:

```python
# soar_app/routes/webhook.py

from flask import Blueprint, request, jsonify
from datetime import datetime, timezone
import sqlite3
import json
import logging

webhook_bp = Blueprint('webhook', __name__)
logger = logging.getLogger(__name__)

DB_PATH = '/opt/soar-dashboard/data/soar.db'


def get_db():
    """Membuat koneksi ke SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Inisialisasi tabel jika belum ada."""
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS alert_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT UNIQUE NOT NULL,
            rule_name TEXT NOT NULL,
            alert_type TEXT,
            severity TEXT,
            source_ip TEXT,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            original_timestamp TEXT,
            alert_timestamp TEXT NOT NULL,
            received_timestamp TEXT NOT NULL,
            status TEXT DEFAULT 'received',
            raw_payload TEXT
        );

        CREATE TABLE IF NOT EXISTS response_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            action_detail TEXT,
            alert_timestamp TEXT NOT NULL,
            response_start_timestamp TEXT NOT NULL,
            completed_timestamp TEXT,
            status TEXT DEFAULT 'in_progress',
            mttr_seconds REAL,
            FOREIGN KEY (alert_id) REFERENCES alert_log(alert_id)
        );

        CREATE TABLE IF NOT EXISTS mttd_mttr_summary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            calculation_date TEXT NOT NULL,
            alert_type TEXT,
            avg_mttd_seconds REAL,
            avg_mttr_seconds REAL,
            total_alerts INTEGER,
            total_responses INTEGER
        );
    ''')
    conn.commit()
    conn.close()


# Inisialisasi database saat modul dimuat
init_db()


@webhook_bp.route('/api/webhook/elastic-alert', methods=['POST'])
def receive_elastic_alert():
    """
    Menerima alert dari Elastic Security via webhook.
    Mencatat waktu penerimaan untuk kalkulasi MTTD.
    """
    try:
        payload = request.get_json(force=True)
        received_at = datetime.now(timezone.utc).isoformat()

        # Ekstrak field dari payload
        alert_id = payload.get('alert_id', f'unknown-{received_at}')
        rule_name = payload.get('rule_name', 'Unknown Rule')
        alert_type = payload.get('alert_type', 'unknown')
        severity = payload.get('severity', 'unknown')
        source_ip = payload.get('source_ip', 'N/A')
        mitre_tactic = payload.get('mitre_tactic', 'N/A')
        mitre_technique = payload.get('mitre_technique', 'N/A')
        original_ts = payload.get('original_timestamp', '')
        alert_ts = payload.get('alert_timestamp', received_at)

        # Simpan ke database
        conn = get_db()
        conn.execute('''
            INSERT OR REPLACE INTO alert_log
            (alert_id, rule_name, alert_type, severity, source_ip,
             mitre_tactic, mitre_technique, original_timestamp,
             alert_timestamp, received_timestamp, status, raw_payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'received', ?)
        ''', (alert_id, rule_name, alert_type, severity, source_ip,
              mitre_tactic, mitre_technique, original_ts,
              alert_ts, received_at, json.dumps(payload)))
        conn.commit()

        # Hitung MTTD (selisih original_timestamp → alert_timestamp)
        mttd_seconds = None
        if original_ts and alert_ts:
            try:
                t_attack = datetime.fromisoformat(
                    original_ts.replace('Z', '+00:00'))
                t_alert = datetime.fromisoformat(
                    alert_ts.replace('Z', '+00:00'))
                mttd_seconds = (t_alert - t_attack).total_seconds()
            except (ValueError, TypeError):
                mttd_seconds = None

        # Tentukan respons otomatis berdasarkan tipe alert
        auto_response = determine_auto_response(alert_type, severity, source_ip)

        if auto_response:
            response_start = datetime.now(timezone.utc).isoformat()
            conn.execute('''
                INSERT INTO response_log
                (alert_id, action_type, action_detail,
                 alert_timestamp, response_start_timestamp, status)
                VALUES (?, ?, ?, ?, ?, 'in_progress')
            ''', (alert_id, auto_response['action'],
                  auto_response['detail'], alert_ts, response_start))
            conn.commit()

            # Eksekusi respons (asinkron di production)
            execute_response(auto_response, alert_id, conn)

        conn.close()

        logger.info(f"Alert diterima: {alert_id} | "
                     f"MTTD: {mttd_seconds}s | "
                     f"Auto-response: {auto_response is not None}")

        return jsonify({
            'status': 'received',
            'alert_id': alert_id,
            'mttd_seconds': mttd_seconds,
            'auto_response_triggered': auto_response is not None,
            'received_at': received_at
        }), 200

    except Exception as e:
        logger.error(f"Error menerima alert: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


def determine_auto_response(alert_type, severity, source_ip):
    """
    Menentukan aksi respons otomatis berdasarkan tipe dan severity alert.
    """
    response_map = {
        'high_severity': {
            'action': 'investigate_and_block',
            'detail': f'Auto-investigate alert severity tinggi. '
                      f'Block IP {source_ip} jika terkonfirmasi malicious.'
        },
        'brute_force_ssh': {
            'action': 'block_ip',
            'detail': f'Auto-block IP {source_ip} di firewall '
                      f'karena brute force SSH terdeteksi.'
        },
        'new_country_geoip': {
            'action': 'flag_for_review',
            'detail': f'Negara baru terdeteksi dari IP {source_ip}. '
                      f'Ditandai untuk review manual.'
        }
    }
    return response_map.get(alert_type)


def execute_response(auto_response, alert_id, conn):
    """
    Mengeksekusi aksi respons dan mencatat waktu selesai untuk MTTR.
    Di production, ini bisa berupa panggilan API ke firewall, SIEM, dsb.
    """
    import time

    action = auto_response['action']
    completed_at = None

    if action == 'block_ip':
        # Simulasi: panggil API firewall untuk block IP
        # Di production: requests.post(firewall_api, ...)
        time.sleep(0.5)  # Simulasi latency
        completed_at = datetime.now(timezone.utc).isoformat()

    elif action == 'investigate_and_block':
        # Simulasi: buat case investigasi
        time.sleep(1.0)
        completed_at = datetime.now(timezone.utc).isoformat()

    elif action == 'flag_for_review':
        # Langsung selesai — hanya menandai
        completed_at = datetime.now(timezone.utc).isoformat()

    if completed_at:
        # Hitung MTTR
        cursor = conn.execute(
            'SELECT alert_timestamp FROM response_log WHERE alert_id = ?',
            (alert_id,))
        row = cursor.fetchone()

        mttr_seconds = None
        if row:
            try:
                t_alert = datetime.fromisoformat(
                    row['alert_timestamp'].replace('Z', '+00:00'))
                t_complete = datetime.fromisoformat(
                    completed_at.replace('Z', '+00:00'))
                mttr_seconds = (t_complete - t_alert).total_seconds()
            except (ValueError, TypeError):
                pass

        conn.execute('''
            UPDATE response_log
            SET completed_timestamp = ?, status = 'completed',
                mttr_seconds = ?
            WHERE alert_id = ?
        ''', (completed_at, mttr_seconds, alert_id))
        conn.commit()
```

### 4.3 Mengirim Data Respons ke Elasticsearch

Agar query ES|QL di Bagian 1 bisa mengakses data respons SOAR, kirim data
dari SQLite ke Elasticsearch:

```python
# soar_app/utils/es_sync.py

from elasticsearch import Elasticsearch
from datetime import datetime
import sqlite3

es = Elasticsearch(['http://localhost:9200'])
DB_PATH = '/opt/soar-dashboard/data/soar.db'


def sync_response_to_es():
    """
    Sinkronisasi data response_log dari SQLite ke Elasticsearch.
    Dijalankan via cron job setiap 1 menit.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute('''
        SELECT r.*, a.rule_name, a.alert_type, a.source_ip,
               a.mitre_tactic, a.original_timestamp
        FROM response_log r
        JOIN alert_log a ON r.alert_id = a.alert_id
        WHERE r.status = 'completed'
          AND r.completed_timestamp IS NOT NULL
    ''').fetchall()

    for row in rows:
        doc = {
            'response': {
                'alert_id': row['alert_id'],
                'action_type': row['action_type'],
                'action_detail': row['action_detail'],
                'alert_timestamp': row['alert_timestamp'],
                'response_start_timestamp': row['response_start_timestamp'],
                'completed_timestamp': row['completed_timestamp'],
                'status': row['status'],
                'mttr_seconds': row['mttr_seconds']
            },
            'rule_name': row['rule_name'],
            'alert_type': row['alert_type'],
            'source_ip': row['source_ip'],
            'mitre_tactic': row['mitre_tactic'],
            'original_timestamp': row['original_timestamp'],
            '@timestamp': row['completed_timestamp']
        }

        # Index ke Elasticsearch
        index_name = f"soar-response-log-{datetime.now().strftime('%Y.%m')}"
        es.index(
            index=index_name,
            id=f"{row['alert_id']}-{row['action_type']}",
            document=doc
        )

    conn.close()
    return len(rows)
```

### 4.4 Cron Job untuk Sinkronisasi

Tambahkan cron job di server SOAR:

```bash
# Jalankan sinkronisasi setiap menit
* * * * * cd /opt/soar-dashboard && python -c "from soar_app.utils.es_sync import sync_response_to_es; print(f'Synced {sync_response_to_es()} records')" >> /var/log/soar-es-sync.log 2>&1
```

### 4.5 Index Template untuk soar-response-log

```json
PUT _index_template/soar-response-log
{
  "index_patterns": ["soar-response-log-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "response": {
          "properties": {
            "alert_id": { "type": "keyword" },
            "action_type": { "type": "keyword" },
            "action_detail": { "type": "text" },
            "alert_timestamp": { "type": "date" },
            "response_start_timestamp": { "type": "date" },
            "completed_timestamp": { "type": "date" },
            "status": { "type": "keyword" },
            "mttr_seconds": { "type": "float" }
          }
        },
        "rule_name": { "type": "keyword" },
        "alert_type": { "type": "keyword" },
        "source_ip": { "type": "ip" },
        "mitre_tactic": { "type": "keyword" },
        "original_timestamp": { "type": "date" }
      }
    }
  }
}
```

---

## 5. Ringkasan Pemetaan Tujuan Penelitian

| Komponen | Tujuan Penelitian | Output Utama |
|---|---|---|
| ES\|QL MTTD Query | Mengukur kecepatan deteksi | Rata-rata MTTD per rule & tren 7 hari |
| ES\|QL MTTR Query | Mengukur kecepatan respons | Rata-rata MTTR per tipe aksi |
| Alert Rule: High Severity | Deteksi serangan kritis | Alert real-time → SOAR |
| Alert Rule: Brute Force | Deteksi threshold anomali | Auto-block IP |
| Alert Rule: New Country | Deteksi anomali geografis | Flag untuk investigasi |
| Cases Management | Dokumentasi investigasi | Tracking resolusi insiden |
| SOAR Webhook | Integrasi deteksi-respons | Kalkulasi MTTR otomatis |

---

> **Catatan Penting**: Pastikan timezone konsisten di seluruh stack
> (Elasticsearch, Kibana, Flask SOAR, dan SQLite) untuk kalkulasi MTTD/MTTR
> yang akurat. Gunakan UTC sebagai standar.

---

*Dokumen ini merupakan bagian dari Pilar 3 — Proyek Riset CTI Skripsi.*
*Terakhir diperbarui: 16 Juni 2026*
