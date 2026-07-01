# Pilar 1 — Visualisasi Dashboard & Pelaporan

> **Tujuan Penelitian**: Merancang dashboard interaktif yang menyajikan data serangan honeypot
> secara real-time, mendukung pengambilan keputusan berbasis data bagi tim SOC maupun manajemen.

---

## Daftar Isi

1. [Lens / TSVB — Time-Series Panel](#1-lens--tsvb--time-series-panel)
2. [Vega-Lite — Heatmap Kustom](#2-vega-lite--heatmap-kustom)
3. [Canvas — Infografis C-Level](#3-canvas--infografis-c-level)
4. [Maps + GeoIP — Peta Serangan](#4-maps--geoip--peta-serangan)
5. [Reporting — Ekspor PDF Terjadwal](#5-reporting--ekspor-pdf-terjadwal)
6. [Ringkasan Pemetaan Tujuan Penelitian](#6-ringkasan-pemetaan-tujuan-penelitian)

---

## 1. Lens / TSVB — Time-Series Panel

> **Tujuan Penelitian yang Dipetakan**: Menyajikan tren volume serangan dari waktu ke waktu
> sehingga analis dapat mengidentifikasi pola musiman atau lonjakan tak biasa.

### 1.1 Prasyarat

| Komponen | Keterangan |
|---|---|
| Index Pattern | `honeypot-*` atau data view yang sudah dibuat |
| Field wajib | `@timestamp`, `mitre.tactic`, `source.ip`, `event.action` |
| Versi Kibana | ≥ 8.x (Lens sudah menjadi editor default) |

### 1.2 Langkah-Langkah Membuat Panel TSVB

1. **Buka Kibana → Analytics → Visualize Library → Create visualization**.
2. Pilih **TSVB (Time Series Visual Builder)**.
3. Pada tab **Data**:
   - **Index pattern**: ketik `honeypot-*`.
   - **Time field**: pilih `@timestamp`.
4. Pada tab **Panel options**:
   - **Interval**: `auto` (atau `1h` untuk granularitas per jam).
5. Tambahkan **Series**:
   - **Aggregation**: `Count`.
   - **Group by**: `Terms` → field `mitre.tactic.keyword` → Top 10.
6. Pada tab **Options**:
   - Aktifkan **Stacked** agar setiap taktik MITRE terlihat jelas berlapis.
   - Pilih **Bar** atau **Area** chart sesuai preferensi.
7. Beri judul panel: **"Volume Serangan per Taktik MITRE (Time Series)"**.
8. Klik **Save and return** untuk menyimpan ke dashboard.

### 1.3 Tips Optimasi TSVB

- Gunakan **Annotations** untuk menandai event penting (misal: *deployment honeypot baru*).
- Aktifkan **Filter ratio** untuk membandingkan dua periode secara langsung.
- Jika data terlalu banyak, gunakan **Rollup index** agar query lebih ringan.

### 1.4 Alternatif: Lens Editor

Lens adalah editor visual modern yang direkomendasikan Elastic sejak versi 8.x.
Langkah singkat:

1. **Analytics → Dashboard → Create panel → Lens**.
2. Drag field `@timestamp` ke sumbu X.
3. Drag field `mitre.tactic.keyword` ke **Break down by**.
4. Metrik default sudah `Count` — ubah ke `Unique count of source.ip` jika ingin
   menghitung jumlah IP unik.
5. Pilih tipe chart **Stacked bar** atau **Area**.
6. Simpan.

---

## 2. Vega-Lite — Heatmap Kustom

> **Tujuan Penelitian yang Dipetakan**: Mengidentifikasi pola temporal serangan
> (jam sibuk, hari tertentu) melalui visualisasi heatmap yang tidak tersedia
> secara native di Lens.

### 2.1 Kapan Menggunakan Vega-Lite

- Ketika visualisasi bawaan Lens/TSVB **tidak cukup** (misal: heatmap 2D, radial chart).
- Ketika Anda membutuhkan kontrol penuh terhadap encoding warna, sumbu, dan tooltip.

### 2.2 Langkah-Langkah

1. **Analytics → Visualize Library → Create visualization → Custom visualization (Vega)**.
2. Hapus contoh kode default.
3. Tempelkan spesifikasi Vega-Lite di bawah ini.
4. Klik **Update** untuk melihat preview.
5. Simpan dengan judul **"Heatmap Serangan per Jam & Hari"**.

### 2.3 Spesifikasi Vega-Lite — Heatmap Serangan per Jam

```json
{
  "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
  "title": "Heatmap Serangan Honeypot — Jam vs Hari dalam Seminggu",
  "description": "Menampilkan intensitas serangan berdasarkan jam (0-23) dan hari (Senin-Minggu)",

  "data": {
    "url": {
      "%context%": true,
      "%timefield%": "@timestamp",
      "index": "honeypot-*",
      "body": {
        "size": 0,
        "aggs": {
          "by_day": {
            "terms": {
              "script": "doc['@timestamp'].value.dayOfWeekEnum.getDisplayName(java.time.format.TextStyle.SHORT, java.util.Locale.ENGLISH)",
              "order": { "_key": "asc" },
              "size": 7
            },
            "aggs": {
              "by_hour": {
                "terms": {
                  "script": "doc['@timestamp'].value.getHour()",
                  "size": 24,
                  "order": { "_key": "asc" }
                }
              }
            }
          }
        }
      }
    },
    "format": { "property": "aggregations.by_day.buckets" },
    "transform": [
      {
        "type": "flatten",
        "fields": ["by_hour.buckets"],
        "as": ["hour_bucket"]
      }
    ]
  },

  "transform": [
    { "calculate": "datum.key", "as": "Hari" },
    { "calculate": "datum.hour_bucket.key", "as": "Jam" },
    { "calculate": "datum.hour_bucket.doc_count", "as": "Jumlah Serangan" }
  ],

  "mark": { "type": "rect", "tooltip": true },

  "encoding": {
    "x": {
      "field": "Jam",
      "type": "ordinal",
      "title": "Jam (UTC)",
      "sort": null
    },
    "y": {
      "field": "Hari",
      "type": "ordinal",
      "title": "Hari",
      "sort": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    },
    "color": {
      "field": "Jumlah Serangan",
      "type": "quantitative",
      "scale": { "scheme": "reds" },
      "title": "Jumlah Serangan"
    },
    "tooltip": [
      { "field": "Hari", "type": "nominal" },
      { "field": "Jam", "type": "ordinal" },
      { "field": "Jumlah Serangan", "type": "quantitative" }
    ]
  },

  "config": {
    "view": { "strokeWidth": 0 },
    "axis": { "domain": false }
  }
}
```

### 2.4 Penjelasan Spesifikasi

| Bagian | Fungsi |
|---|---|
| `%context%` & `%timefield%` | Menghubungkan query Vega dengan time picker dashboard Kibana |
| `aggs.by_day` | Agregasi bucket berdasarkan hari dalam seminggu menggunakan Painless script |
| `aggs.by_hour` | Sub-agregasi bucket berdasarkan jam (0–23) |
| `mark: rect` | Menampilkan sel heatmap persegi |
| `scale.scheme: reds` | Skema warna merah — semakin gelap, semakin banyak serangan |

### 2.5 Kustomisasi Lanjutan

- Ganti `"scheme": "reds"` dengan `"scheme": "inferno"` untuk skema warna yang lebih dramatis.
- Tambahkan `"width": 600, "height": 300` di level root untuk mengatur ukuran tetap.
- Untuk filter taktik tertentu, tambahkan `"query"` di dalam `body`:

```json
"query": {
  "bool": {
    "filter": [
      { "term": { "mitre.tactic.keyword": "Initial Access" } }
    ]
  }
}
```

---

## 3. Canvas — Infografis C-Level

> **Tujuan Penelitian yang Dipetakan**: Menyediakan format pelaporan visual tingkat eksekutif
> yang merangkum status keamanan infrastruktur honeypot dalam satu halaman.

### 3.1 Mengapa Canvas?

Canvas memungkinkan pembuatan **workpad** bergaya infografis yang cocok untuk:

- Presentasi ke manajemen / C-Level yang membutuhkan ringkasan visual.
- Laporan bulanan keamanan siber.
- Display di SOC wall monitor.

### 3.2 Langkah-Langkah Membuat Workpad

1. **Kibana → Analytics → Canvas → Create workpad**.
2. Atur ukuran workpad:
   - **Width**: 1920 px, **Height**: 1080 px (Full HD).
   - **Background**: Pilih warna gelap (`#1a1a2e`) untuk kesan profesional.

#### 3.2.1 Elemen 1 — Total Serangan (Big Number)

1. Klik **Add element → Metric**.
2. Klik **Data → Elasticsearch SQL**:

```sql
SELECT COUNT(*) AS total_serangan
FROM "honeypot-*"
WHERE "@timestamp" >= NOW() - INTERVAL 30 DAY
```

3. Klik **Display**:
   - Font size: `72px`.
   - Label: `Total Serangan (30 Hari Terakhir)`.
   - Warna teks: `#e94560`.
4. Posisikan di **pojok kiri atas** workpad.

#### 3.2.2 Elemen 2 — Top 5 IP Penyerang (Tabel)

1. **Add element → Data table**.
2. Query Elasticsearch SQL:

```sql
SELECT "source.ip" AS ip_penyerang, COUNT(*) AS jumlah
FROM "honeypot-*"
WHERE "@timestamp" >= NOW() - INTERVAL 30 DAY
GROUP BY "source.ip"
ORDER BY jumlah DESC
LIMIT 5
```

3. Styling:
   - Header background: `#16213e`.
   - Font: monospace untuk IP address.
   - Alternating row colors untuk keterbacaan.

#### 3.2.3 Elemen 3 — Top Taktik MITRE (Donut Chart)

1. **Add element → Shape → Donut / Pie**.
2. Atau gunakan **Saved Lens visualization** yang sudah ada:
   - **Add element → Add from Visualize Library**.
   - Pilih panel pie chart taktik MITRE yang sudah dibuat.
3. Posisikan di **tengah** workpad.

#### 3.2.4 Elemen 4 — Status Teks Dinamis

1. **Add element → Markdown**.
2. Isi dengan teks dinamis:

```markdown
## Status Keamanan Honeypot
**Periode**: {{now | formatDate "MMMM YYYY"}}

Sistem honeypot beroperasi normal. Terdeteksi peningkatan
aktivitas brute-force SSH dari wilayah Asia Tenggara.
```

3. Styling: font putih di atas background gelap.

#### 3.2.5 Elemen 5 — Sparkline Tren 7 Hari

1. **Add element → Area chart** (mini / sparkline).
2. Datasource: Elasticsearch SQL dengan agregasi harian.
3. Sembunyikan axis dan legend untuk tampilan minimalis.

### 3.3 Export & Sharing

- Klik **Share → Download as PDF** untuk unduh langsung.
- Atau gunakan **Reporting** (lihat Bagian 5) untuk penjadwalan otomatis.

---

## 4. Maps + GeoIP — Peta Serangan

> **Tujuan Penelitian yang Dipetakan**: Memvisualisasikan distribusi geografis sumber serangan
> untuk mendukung analisis *threat landscape* dan kebijakan geo-blocking.

### 4.1 Prasyarat GeoIP

Pastikan enrichment GeoIP sudah aktif di pipeline Logstash/Ingest:

```ruby
# Potongan konfigurasi Logstash (logstash.conf)
filter {
  geoip {
    source => "[source][ip]"
    target => "[source][geo]"
    database => "/usr/share/GeoIP/GeoLite2-City.mmdb"
    add_field => {
      "[source][geo][location]" => "%{[source][geo][latitude]},%{[source][geo][longitude]}"
    }
  }
}
```

Atau gunakan **Ingest Pipeline** di Elasticsearch:

```json
PUT _ingest/pipeline/geoip-enrichment
{
  "description": "Enrichment GeoIP untuk IP sumber serangan",
  "processors": [
    {
      "geoip": {
        "field": "source.ip",
        "target_field": "source.geo",
        "database_file": "GeoLite2-City.mmdb",
        "properties": [
          "continent_name",
          "country_name",
          "country_iso_code",
          "region_name",
          "city_name",
          "location"
        ],
        "ignore_missing": true
      }
    }
  ]
}
```

### 4.2 Verifikasi Mapping

Pastikan field `source.geo.location` bertipe `geo_point`:

```json
GET honeypot-*/_mapping/field/source.geo.location
```

Respons yang diharapkan:

```json
{
  "honeypot-2026.06.16": {
    "mappings": {
      "source.geo.location": {
        "full_name": "source.geo.location",
        "mapping": {
          "location": {
            "type": "geo_point"
          }
        }
      }
    }
  }
}
```

### 4.3 Langkah-Langkah Membuat Peta

1. **Kibana → Analytics → Maps → Create map**.
2. Klik **Add layer → Documents**.
3. Konfigurasi layer:
   - **Data view**: `honeypot-*`.
   - **Geospatial field**: `source.geo.location`.
   - **Scaling**: pilih **Clusters** (untuk performa) atau **Documents** (detail).
4. Klik **Layer style**:
   - **Fill color**: By value → `Count` → skema warna `Yellow to Red`.
   - **Border color**: transparan.
   - **Symbol size**: By value → `Count` → range 4–40 px.
5. **Tooltip fields** — tambahkan:
   - `source.ip`
   - `source.geo.country_name`
   - `source.geo.city_name`
   - `mitre.tactic`
6. Klik **Save & close** → beri judul **"Peta Distribusi Sumber Serangan"**.

### 4.4 Layer Tambahan — Choropleth per Negara

1. **Add layer → Choropleth**.
2. **EMS boundaries**: World Countries.
3. **Join field**: `source.geo.country_iso_code.keyword`.
4. **Metric**: Count.
5. **Color ramp**: `Blues` (semakin gelap = semakin banyak serangan).

Hasilnya: peta dunia dengan negara diwarnai berdasarkan jumlah serangan.

### 4.5 Tips Lanjutan

- Tambahkan **filter** di peta untuk menyaring berdasarkan `mitre.tactic` tertentu.
- Gunakan **Spatial joins** untuk menggabungkan data dari index berbeda (misal: threat intel feed).
- Aktifkan **Map → Fit to data** agar peta otomatis zoom ke area dengan data.

---

## 5. Reporting — Ekspor PDF Terjadwal

> **Tujuan Penelitian yang Dipetakan**: Mengotomatiskan distribusi laporan keamanan
> kepada stakeholder secara berkala.

> [!NOTE]
> Fitur Reporting terjadwal memerlukan lisensi **Gold** atau **Trial** (30 hari gratis).
> Pastikan Trial sudah diaktifkan melalui **Management → License Management**.

### 5.1 Ekspor Manual (Sekali Pakai)

1. Buka dashboard yang ingin diekspor.
2. Klik **Share → PDF Reports → Generate PDF**.
3. Tunggu notifikasi selesai, lalu unduh file PDF.

### 5.2 Ekspor Terjadwal (Scheduled)

1. **Management → Stack Management → Reporting**.
2. Atau melalui **Watcher** (jika tersedia):

```json
PUT _watcher/watch/weekly-dashboard-pdf
{
  "trigger": {
    "schedule": {
      "weekly": {
        "on": ["monday"],
        "at": ["08:00"]
      }
    }
  },
  "actions": {
    "send_report": {
      "reporting": {
        "url": "https://<KIBANA_HOST>:5601/api/reporting/generate/printablePdf",
        "auth": {
          "basic": {
            "username": "elastic",
            "password": "{{ctx.metadata.password}}"
          }
        },
        "retries": 3
      }
    }
  }
}
```

### 5.3 Alternatif: Kibana Alerting → Email Action

Cara yang lebih sederhana tanpa Watcher:

1. **Kibana → Stack Management → Rules → Create rule**.
2. **Rule type**: Elasticsearch query.
3. **Action**: pilih **Email** connector.
4. Pada body email, sertakan link langsung ke dashboard:

```
Laporan mingguan dashboard honeypot tersedia.
Akses di: https://<KIBANA_HOST>:5601/app/dashboards#/view/<DASHBOARD_ID>
```

5. **Schedule**: setiap hari Senin pukul 08:00 WIB.

### 5.4 Mengaktifkan Trial License

Jika belum aktif:

```json
POST _license/start_trial?acknowledge=true
```

Atau melalui UI: **Management → License Management → Start Trial**.

---

## 6. Ringkasan Pemetaan Tujuan Penelitian

| Komponen Visualisasi | Tujuan Penelitian | Manfaat Utama |
|---|---|---|
| TSVB / Lens Time Series | Analisis tren volume serangan | Deteksi lonjakan / pola musiman |
| Vega-Lite Heatmap | Identifikasi pola waktu serangan | Jam & hari paling rawan |
| Canvas Infografis | Pelaporan eksekutif | Ringkasan 1 halaman untuk C-Level |
| Maps + GeoIP | Analisis *threat landscape* geografis | Kebijakan geo-blocking |
| PDF Reporting | Otomatisasi distribusi laporan | Efisiensi operasional SOC |

---

> **Catatan Teknis**: Semua visualisasi di atas menggunakan data view `honeypot-*`
> yang mencakup index Suricata, Wazuh, dan Cowrie. Pastikan field mapping sudah
> konsisten di seluruh index sebelum membuat visualisasi.

---

*Dokumen ini merupakan bagian dari Pilar 1 — Proyek Riset CTI Skripsi.*
*Terakhir diperbarui: 16 Juni 2026*
