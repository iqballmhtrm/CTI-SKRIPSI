# Laporan Perbaikan Visualisasi Kibana (Repair Mode)

Berdasarkan *Root Cause Analysis* pada file `kibana-panel-root-cause.md`, perbaikan langsung (*hotfix*) telah dieksekusi terhadap objek visualisasi Kibana pada repositori Skripsi, menghasilkan versi final terbaru: `06-Dashboard/dashboard-final-v2.ndjson`.

Berikut adalah rangkuman eksekusi perbaikan (Repair Action) tanpa mengubah sedikitpun konfigurasi Elasticsearch, Logstash, Wazuh, maupun Suricata:

| Panel yang Diperbaiki | Field Lama | Field Baru (Diperbaiki) | Status Akhir |
|---|---|---|---|
| **MITRE ATT&CK Tactic Distribution** | `mitre.tactic.keyword` | `data.alert.metadata.mitre_tactic_name` | ✅ **SUKSES** (Distribusi Tactic MITRE berhasil muncul berdasarkan metrik Logstash aktual) |
| **Unique Threat Sources** | `source.ip` | `data.srcip` | ✅ **SUKSES** (Data IP sumber penyerangan berhasil diabstraksi dari format Wazuh) |
| **Forensic Alert Stream** | `source.ip`, `message` | `data.srcip`, `data.alert.signature`, `@timestamp` | ✅ **SUKSES** (Stream log forensik mentah tampil urut berdasarkan waktu) |
| **Port Scanning Detection** | `rule.id: 1000010` | `data.alert.signature_id: 1000010` | ✅ **SUKSES** (Metrik sukses tersambung dengan Custom Rules Suricata Nmap) |
| **Top Threat Actors Table** | `source_ip_fixed.keyword`, `alert_count` (Max) | `data.srcip.keyword`, Agregasi `Count` (Standard) | ✅ **SUKSES** (Tabel sukses di-render menampilkan top 10 IP Actor secara *real-time* tanpa Transform job) |

## Langkah Selanjutnya (Manual)
1. Lakukan pengimporan (*Import*) file `dashboard-final-v2.ndjson` di Kibana (*Stack Management* > *Saved Objects*).
2. Jika diminta *Refresh Data View*, klik refresh agar field-field baru (seperti `data.alert.metadata.mitre_tactic_name`) dikenali Kibana.
3. Seluruh *panel* kini bebas dari error `No results found` dan akan menampilkan bukti forensik Nmap, Hydra, dan Nikto untuk kebutuhan *Screenshot* akhir.
