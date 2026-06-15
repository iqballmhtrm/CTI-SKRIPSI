# Laporan Root Cause Analysis (Kibana Panels)

Berdasarkan hasil audit `_mapping` pada index `wazuh-alerts-*` di Elasticsearch dan perbandingannya dengan objek visualisasi di Kibana, ditemukan beberapa ketidaksesuaian skema (*Schema Mismatch*) yang menyebabkan panel gagal memuat data (*No results found* atau *error*).

## Tabel Analisis Akar Masalah

| Panel | Field Digunakan (Kibana) | Field Ada di ES? | Penyebab (Root Cause) |
|---|---|---|---|
| **1. MITRE ATT&CK Tactic Distribution** | `mitre.tactic.keyword` | ❌ TIDAK | Kibana mencari field `mitre.tactic`, namun pipeline Logstash memetakan field asli Suricata ke `mitre_tactic_name` (atau `data.alert.metadata.mitre_tactic_name`). Akibatnya terjadi *No results found*. |
| **2. Top Threat Actors Table** | `source_ip_fixed.keyword`, `alert_count`, `unique_techniques` | ❌ TIDAK | Field-field ini adalah agregasi khusus yang biasanya dihasilkan oleh proses Elasticsearch Transform (Continuous Transform). Karena Transform belum berjalan atau tidak ada, raw index `wazuh-alerts-*` tidak memiliki field `alert_count` dan `source_ip_fixed`. |
| **3. Forensic Alert Stream** | `message` atau `rule.description` (ECS Standard) | ⚠️ PARTIAL | Skema standar Elastic Common Schema (ECS) menggunakan `source.ip` dan `message`. Wazuh merubahnya ke dalam namespace spesifik seperti `data.srcip` dan `data.alert.signature`. Visualisasi gagal mem-parsing *stream* jika menggunakan ECS fields. |
| **4. Unique Threat Sources** | `source.ip` atau `src_ip.keyword` | ❌ TIDAK | Skema bawaan Wazuh untuk IP sumber adalah `data.srcip`. Menggunakan field `src_ip` atau `source.ip` bawaan Logstash akan mengembalikan N/A. |
| **5. Port Scanning Detection** | `rule.id` (Ekspektasi: 1000010) | ❌ TIDAK | Di Wazuh, field `rule.id` berisi ID Rule Wazuh (misal `86601`), sedangkan ID Rule Suricata (1000010) disimpan di field `data.alert.signature_id`. Panel tidak akan mendeteksi Nmap (1000010) jika filter menggunakan `rule.id: 1000010`. |

## Rekomendasi Perbaikan (Minimal Change)

Untuk memperbaiki seluruh panel tanpa merombak Elasticsearch, Logstash, maupun Dashboard secara ekstrem, lakukan perubahan *minimal* secara langsung pada antarmuka Kibana (Edit Visualization):

1. **MITRE ATT&CK Tactic Distribution:**
   Ubah parameter `Field` di bagian bucket aggregation dari `mitre.tactic.keyword` menjadi `data.alert.metadata.mitre_tactic_name.keyword` (atau sesuai mapping aktual).
2. **Top Threat Actors Table:**
   Ganti visualisasi menjadi mode *Data View / Raw Index*. Hapus penggunaan field `source_ip_fixed.keyword` dan ganti dengan `data.srcip`. Untuk *count*, cukup gunakan agregasi *Count* standar Kibana tanpa mengandalkan metrik `alert_count` eksternal.
3. **Forensic Alert Stream & Unique Threat Sources:**
   Sesuaikan field *Data Table/Stream* untuk mengacu ke `data.srcip` untuk IP, dan `data.alert.signature` untuk deskripsi.
4. **Port Scanning Detection:**
   Ganti query filter panel dari `rule.id: 1000010` menjadi `data.alert.signature_id: 1000010`.

Dengan rekomendasi tersebut, visualisasi akan kembali terhubung secara akurat ke *source of truth* dari index Wazuh saat ini.
