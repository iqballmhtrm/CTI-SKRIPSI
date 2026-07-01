# Traceability Matrix — Penelitian CTI ELK Stack

**Judul:** Optimisasi Visualisasi Data Log dan Alert Siber Melalui Dashboard ELK Stack  
**Peneliti:** Muhammad Iqbal Muhtaram — NIM 2241720265 — Polinema  
**Tanggal Audit:** 2026-07-01 (diperbarui)  
**Status:** VALIDATED

---

## 1. Ringkasan Eksperimen

| Parameter | Nilai |
|-----------|-------|
| Total iterasi terkontrol | 30 |
| Skenario | 3 (Nmap, Hydra, Nikto) |
| Iterasi per skenario | 10 |
| Tanggal FINAL run | 2026-06-24 |
| Data primer | `14-Research/datasets/iterations.csv` |
| Tanggal PILOT run | 2026-06-15 |
| Topologi FINAL | SOC .10 / VICTIM .106 / ATTACKER .110 |
| Topologi PILOT | SOC .10 / VICTIM .10 (sama host) / ATTACKER dari .1 (gateway) |

> **Catatan topologi PILOT:** Seluruh artefak bertanggal 2026-06-15 menggunakan
> `src_ip: 192.168.56.1` dan `dest_ip: 192.168.56.10`. Ini adalah konfigurasi
> PILOT sebelum node terpisah. Bukti FINAL (iterations.csv, 2026-06-24) menggunakan
> topologi tiga-node yang benar.

---

## 2. Matriks Keterlacakan Per Skenario

### Skenario 1 — Port Scanning (Nmap)

| Dimensi | Nilai |
|---------|-------|
| **Alat serangan** | Nmap 7.80 (dari ATTACKER 192.168.56.110) |
| **Target** | VICTIM 192.168.56.106 |
| **SID Suricata** | 1000010 rev:1 |
| **Aturan Suricata** | `alert tcp any any -> $HOME_NET any (msg:"[CTI] Nmap SYN Stealth Scan Detected"; flags:S; flow:stateless; threshold:type both, track by_src, count 50, seconds 5; ...)` |
| **Nama alert** | `[CTI] Nmap SYN Stealth Scan Detected` |
| **Teknik MITRE** | T1046 — Network Service Scanning |
| **Taktik MITRE** | Discovery |
| **Mitigasi Wazuh** | TIDAK ADA (tidak ada rule HIDS yang terpicu) |
| **MTTR** | N/A |

| Jenis | Berkas | Status |
|-------|--------|--------|
| Definisi aturan | `03-Suricata/custom.rules` baris 1 | ✅ Tracked |
| Pemetaan MITRE | `05-MITRE/mitre-mapping.yml` (SID 1000010 → T1046) | ✅ Tracked |
| Data iterasi FINAL | `14-Research/datasets/iterations.csv` baris 2–11 (iter 1–10) | ✅ Tracked |
| Protokol eksperimen | `14-Research/protocols/PROTOCOL_30_CONTROLLED_ITERATIONS.md` §Nmap | ✅ Tracked |
| Orkestrator | `14-Research/protocols/run_controlled_iterations.sh` fungsi `run_nmap()` | ✅ Tracked |
| Alert eve.json PILOT | `09-Evidence/final-nmap-suricata-alert.json` | ✅ Tracked (PILOT) |
| Alert Kibana PILOT | `09-Evidence/final-nmap-kibana-event.json` | ⚠️ Tracked tapi KOSONG |
| Validasi serangan | `07-Testing/Nmap/nmap_validation_success.txt` | ✅ Tracked |
| Output nmap PILOT | `07-Testing/Nmap/nmap_scan.txt` | ✅ Tracked (PILOT, target .10) |
| Dashboard | `06-Dashboard/dashboard-final-v5.ndjson` (panel "Port Scan Activity") | ✅ Tracked |
| Referensi Bab IV | `11-Bab4/implementasi_dan_pengujian.md` §Skenario 1 | ✅ Tracked |
| Referensi Bab IV | `11-Bab4/draft-bab5-pengujian-dan-analisis.md` Tabel iter 1–10 | ✅ Tracked |

**Metrik FINAL (rata-rata 10 iterasi):**

| Iter | T0_epoch | T1_epoch | MTTD (s) | MTTR | Status |
|------|----------|----------|----------|------|--------|
| 1 | 1782303972 | 1782303974 | 2 | — | OK;NO_MITIG |
| 2 | 1782304132 | 1782304134 | 2 | — | OK;NO_MITIG |
| 3 | 1782304293 | 1782304294 | 1 | — | OK;NO_MITIG |
| 4 | 1782304648 | 1782304650 | 2 | — | OK;NO_MITIG |
| 5 | 1782304816 | 1782304818 | 2 | — | OK;NO_MITIG |
| 6 | 1782304981 | 1782304984 | 3 | — | OK;NO_MITIG |
| 7 | 1782305144 | 1782305150 | 6 | — | OK;NO_MITIG |
| 8 | 1782305316 | 1782305317 | 1 | — | OK;NO_MITIG |
| 9 | 1782305484 | 1782305489 | 5 | — | OK;NO_MITIG |
| 10 | 1782305655 | 1782305656 | 1 | — | OK;NO_MITIG |
| **Rata²** | | | **2,5** | **—** | 10/10 terdeteksi |

---

### Skenario 2 — SSH Brute Force (Hydra)

| Dimensi | Nilai |
|---------|-------|
| **Alat serangan** | Hydra (dari ATTACKER 192.168.56.110) |
| **Target** | VICTIM 192.168.56.106 port 22 (SSH) |
| **SID Suricata** | 1000020 rev:2 |
| **Aturan Suricata** | `alert tcp any any -> $HOME_NET 22 (msg:"[CTI] Hydra SSH Brute Force Attempt"; flow:stateless; flags:S; threshold:type both, track by_src, count 5, seconds 60; ...)` |
| **Nama alert** | `[CTI] Hydra SSH Brute Force Attempt` |
| **Teknik MITRE** | T1110.001 — Brute Force: Password Guessing |
| **Taktik MITRE** | Credential Access |
| **Mitigasi Wazuh** | Rule 5763 → active-response firewall-drop pada VICTIM |
| **MTTR** | Rata-rata 5,3 detik |

| Jenis | Berkas | Status |
|-------|--------|--------|
| Definisi aturan | `03-Suricata/custom.rules` baris 2 | ✅ Tracked |
| Pemetaan MITRE | `05-MITRE/mitre-mapping.yml` (SID 1000020 → T1110.001) | ✅ Tracked |
| Data iterasi FINAL | `14-Research/datasets/iterations.csv` baris 12–21 (iter 11–20) | ✅ Tracked |
| Protokol eksperimen | `14-Research/protocols/PROTOCOL_30_CONTROLLED_ITERATIONS.md` §Hydra | ✅ Tracked |
| Orkestrator | `14-Research/protocols/run_controlled_iterations.sh` fungsi `run_hydra()` | ✅ Tracked |
| Reset mitigasi | `14-Research/protocols/cti-unblock.sh` | ✅ Tracked |
| Alert eve.json PILOT | `09-Evidence/final-hydra-suricata-alert.json` | ✅ Tracked (PILOT) |
| Validasi serangan | `07-Testing/Hydra/hydra_validation_success.txt` | ✅ Tracked |
| Dashboard | `06-Dashboard/dashboard-final-v5.ndjson` (panel "SSH Brute Force") | ✅ Tracked |
| Referensi Bab IV | `11-Bab4/implementasi_dan_pengujian.md` §Skenario 2 | ✅ Tracked |
| Referensi Bab IV | `11-Bab4/draft-bab5-pengujian-dan-analisis.md` Tabel iter 11–20 | ✅ Tracked |

**Metrik FINAL (rata-rata 10 iterasi):**

| Iter | T0_epoch | T1_epoch | T2_epoch | MTTD (s) | MTTR (s) |
|------|----------|----------|----------|----------|----------|
| 11 | 1782305821 | 1782305822 | 1782305830 | 1 | 9 |
| 12 | 1782305991 | 1782305993 | 1782305993 | 2 | 2 |
| 13 | 1782306070 | 1782306071 | 1782306079 | 1 | 9 |
| 14 | 1782306149 | 1782306150 | 1782306151 | 1 | 2 |
| 15 | 1782306229 | 1782306230 | 1782306237 | 1 | 8 |
| 16 | 1782306321 | 1782306323 | 1782306323 | 2 | 2 |
| 17 | 1782306405 | 1782306406 | 1782306409 | 1 | 4 |
| 18 | 1782306486 | 1782306488 | 1782306489 | 2 | 3 |
| 19 | 1782306571 | 1782306572 | 1782306577 | 1 | 6 |
| 20 | 1782306659 | 1782306663 | 1782306667 | 4 | 8 |
| **Rata²** | | | | **1,6** | **5,3** |

---

### Skenario 3 — Web Vulnerability Scan (Nikto)

| Dimensi | Nilai |
|---------|-------|
| **Alat serangan** | Nikto/2.1.6 (dari ATTACKER 192.168.56.110) |
| **Target** | VICTIM 192.168.56.106 port 80/443 (HTTP) |
| **SID Suricata** | 1000030 rev:3 |
| **Aturan Suricata** | `alert http any any -> $HOME_NET [80,443] (msg:"[CTI] Nikto Web Vulnerability Scan Detected"; flow:established,to_server; threshold:type both, track by_src, count 20, seconds 10; ...)` |
| **Nama alert** | `[CTI] Nikto Web Vulnerability Scan Detected` |
| **Teknik MITRE** | T1595.002 — Active Reconnaissance: Vulnerability Scanning |
| **Taktik MITRE** | Reconnaissance |
| **Mitigasi Wazuh** | Rule 31151 → active-response firewall-drop pada VICTIM |
| **MTTR** | Rata-rata 3,1 detik |

| Jenis | Berkas | Status |
|-------|--------|--------|
| Definisi aturan | `03-Suricata/custom.rules` baris 3 | ✅ Tracked |
| Pemetaan MITRE | `05-MITRE/mitre-mapping.yml` (SID 1000030 → T1595.002) | ✅ Tracked |
| Data iterasi FINAL | `14-Research/datasets/iterations.csv` baris 22–31 (iter 21–30) | ✅ Tracked |
| Protokol eksperimen | `14-Research/protocols/PROTOCOL_30_CONTROLLED_ITERATIONS.md` §Nikto | ✅ Tracked |
| Orkestrator | `14-Research/protocols/run_controlled_iterations.sh` fungsi `run_nikto()` | ✅ Tracked |
| Reset mitigasi | `14-Research/protocols/cti-unblock.sh` | ✅ Tracked |
| Alert eve.json PILOT | `09-Evidence/final-nikto-suricata-alert.json` | ✅ Tracked (PILOT) |
| Validasi serangan | `07-Testing/Nikto/nikto_validation_success.txt` | ✅ Tracked |
| Dashboard | `06-Dashboard/dashboard-final-v5.ndjson` (panel "Web Scan Activity") | ✅ Tracked |
| Referensi Bab IV | `11-Bab4/implementasi_dan_pengujian.md` §Skenario 3 | ✅ Tracked |
| Referensi Bab IV | `11-Bab4/draft-bab5-pengujian-dan-analisis.md` Tabel iter 21–30 | ✅ Tracked |

**Metrik FINAL (rata-rata 10 iterasi):**

| Iter | T0_epoch | T1_epoch | T2_epoch | MTTD (s) | MTTR (s) |
|------|----------|----------|----------|----------|----------|
| 21 | 1782306739 | 1782306741 | 1782306742 | 2 | 3 |
| 22 | 1782307246 | 1782307249 | 1782307249 | 3 | 3 |
| 23 | 1782307736 | 1782307737 | 1782307738 | 1 | 2 |
| 24 | 1782308222 | 1782308226 | 1782308226 | 4 | 4 |
| 25 | 1782308709 | 1782308711 | 1782308712 | 2 | 3 |
| 26 | 1782309198 | 1782309200 | 1782309201 | 2 | 3 |
| 27 | 1782309687 | 1782309690 | 1782309690 | 3 | 3 |
| 28 | 1782310094 | 1782310096 | 1782310097 | 2 | 3 |
| 29 | 1782310581 | 1782310582 | 1782310584 | 1 | 3 |
| 30 | 1782311072 | 1782311074 | 1782311076 | 2 | 4 |
| **Rata²** | | | | **2,2** | **3,1** |

---

## 3. Arsitektur Pipeline Deteksi (End-to-End)

```
ATTACKER (.110)
  │
  │  [serangan: nmap/hydra/nikto]
  ▼
VICTIM (.106)
  │
  ├─ Suricata 8.0.3 (NIDS)
  │    └─ custom.rules (SID 1000010/1000020/1000030)
  │    └─ /var/log/suricata/eve.json
  │
  └─ Wazuh Agent (HIDS)
       └─ Rule 5763 (SSH) / 31151 (HTTP) → active-response firewall-drop
            └─ T2 dicatat saat drop terjadi
  │
  ▼ [Filebeat → Logstash]
SOC SERVER (.10)
  │
  ├─ Logstash
  │    ├─ soc-pipeline.conf (287 baris) — parsing, filter, output
  │    ├─ 99-mitre-normalize.conf — normalisasi field MITRE
  │    └─ mitre-mapping.yml — translate SID → technique_id/name
  │
  ├─ Elasticsearch
  │    └─ Index: cti-logs-iqbal-* (UUID 7afca9a4)
  │         T1=waktu dokumen masuk ES (first_alert timestamp)
  │
  ├─ Kibana
  │    └─ dashboard-final-v5.ndjson (21 panel)
  │         Visualisasi: KPI (MTTD/MTTR/Total/GeoCount), Timeline,
  │         MITRE technique bar, Pyramid of Pain, Validation bar,
  │         Threat Score table, Benchmark bar, SOAR metrics,
  │         Attack Origin Map (Kibana Maps / GeoIP publik)
  │    └─ 5x Saved Search (all/nmap/hydra/nikto/mitre-mapped)
  │
  └─ SOAR Dashboard (Flask :5000)
       └─ /webhook ← HTTP output Logstash
       └─ incidents.db (SQLite)
       └─ Manual /block-ip
```

**Definisi waktu (R-14, LOCKED):**
- T0 = waktu serangan diluncurkan (epoch dari ATTACKER)
- T1 = waktu first alert masuk Elasticsearch
- T2 = waktu event firewall-drop Wazuh Active Response
- MTTD = T1 − T0
- MTTR = T2 − T0

---

## 4. Inventaris Bukti — Klasifikasi dan Status

### 4.1 Bukti Utama (PRIMARY)

| Berkas | Fase | Konten | Status |
|--------|------|--------|--------|
| `14-Research/datasets/iterations.csv` | FINAL | 30 iterasi T0/T1/T2/MTTD/MTTR | ✅ Primer |
| `14-Research/protocols/PROTOCOL_30_CONTROLLED_ITERATIONS.md` | FINAL | Protokol formal 141 baris | ✅ Primer |
| `14-Research/protocols/run_controlled_iterations.sh` | FINAL | Skrip orkestrator 155 baris | ✅ Primer |
| `14-Research/protocols/system_readiness_check.sh` | FINAL | Pre-flight 29 item | ✅ Primer |
| `14-Research/protocols/cti-unblock.sh` | FINAL | Reset iptables antar-iterasi | ✅ Primer |
| `03-Suricata/custom.rules` | FINAL | 3 SID penelitian (1000010/20/30) | ✅ Primer |
| `05-MITRE/mitre-mapping.yml` | FINAL | Kamus SID→MITRE | ✅ Primer |
| `06-Dashboard/dashboard-final-v5.ndjson` | FINAL | Export Kibana 21 panel (incl. Attack Origin Map) | ✅ Primer |
| `12-SOAR-Dashboard/app/soar_app.py` | FINAL | Aplikasi SOAR Flask | ✅ Primer |

### 4.2 Bukti Validasi

| Berkas | Konten | Status |
|--------|--------|--------|
| `07-Testing/Nmap/nmap_validation_success.txt` | "NMAP VALIDATION PASS - T1046 DETECTED" | ✅ Valid |
| `07-Testing/Hydra/hydra_validation_success.txt` | "HYDRA VALIDATION PASS - T1110.001 DETECTED" | ✅ Valid |
| `07-Testing/Nikto/nikto_validation_success.txt` | "NIKTO VALIDATION PASS - T1595.002 DETECTED" | ✅ Valid |

### 4.3 Bukti Fase PILOT (2026-06-15) — Konteks Historis

> Semua bukti di bawah ini berasal dari fase PILOT sebelum topologi tiga-node
> final ditetapkan. `src_ip` adalah 192.168.56.1 (gateway VirtualBox) dan
> `dest_ip` adalah 192.168.56.10 (SOC). Ini BUKAN topologi eksperimen final.
> Artefak ini dipertahankan sebagai konteks evolusi penelitian.

| Berkas | Konten | Catatan |
|--------|--------|---------|
| `09-Evidence/final-nmap-suricata-alert.json` | 5 baris alert eve.json | SID 1000010, sig "LOCAL NMAP SYN Scan Detected", rev:1, src .1 |
| `09-Evidence/final-hydra-suricata-alert.json` | 1 baris alert eve.json | SID 1000020, sig "LOCAL HYDRA SSH Brute Force Attempt", MITRE T1110 (bukan T1110.001) |
| `09-Evidence/final-nikto-suricata-alert.json` | 1 baris alert eve.json | SID 1000030, sig "LOCAL NIKTO Web Scanner Detected", MITRE T1595 (bukan T1595.002) |
| `07-Testing/Nmap/nmap_scan.txt` | Output nmap -sS 192.168.56.10 | Target SOC bukan VICTIM (fase pilot) |
| `07-Testing/Nmap/nmap_validation_after_fix.txt` | Output nmap kedua ke 192.168.56.10 | Konfirmasi setelah fix rule |

### 4.4 Bukti Infrastruktur

| Berkas | Konten | Status |
|--------|--------|--------|
| `09-Evidence/environment-verification.txt` | Verifikasi lingkungan SOC | ✅ Tracked |
| `09-Evidence/mitre-validation-final.md` | Laporan validasi MITRE enrichment | ✅ Tracked |
| `09-Evidence/mitre-validation-after-fix.json` | JSON hasil validasi MITRE post-fix | ✅ Tracked |
| `09-Evidence/suricata-fix-validation.txt` | Validasi perbaikan Suricata | ✅ Tracked |
| `09-Evidence/suricata-root-cause-analysis.txt` | Analisis akar masalah Suricata | ✅ Tracked |
| `09-Evidence/final-readiness-report.md` | Laporan kesiapan sistem | ✅ Tracked |
| `09-Evidence/alert-validation.md` | Validasi alert end-to-end | ✅ Tracked |
| `09-Evidence/dashboard-audit.md` | Audit dashboard Kibana | ✅ Tracked |
| `09-Evidence/EVIDENCE_SOURCE_CLASSIFICATION.md` | Klasifikasi sumber bukti (21 Jun 2026) | ✅ Tracked |
| `09-Evidence/elasticsearch-mitre-validation.json` | Contoh ES doc dengan enrichment MITRE | ✅ Tracked |

### 4.5 Bukti GeoIP dan Attack Origin Map

| Item | Nilai | Status |
|------|-------|--------|
| Dokumen dengan koordinat GeoIP valid | 36 | ✅ Ada di ES |
| Asal negara | Amerika Serikat (20), Singapura (16) | ✅ Terverifikasi |
| Field GeoIP | `source.geo.location` (geo_point) | ✅ Ter-enriched |
| Panel visualisasi | `cti-attack-origin-map` (Kibana Maps, tipe `map`) | ✅ Deploy |
| Layer peta | EMS_TMS basemap + ES_SEARCH GEOJSON_VECTOR | ✅ Konfigurasi |
| Referensi Bab IV | `11-Bab4/implementasi_dan_pengujian.md` §4.5 panel 21 | ✅ Tracked |

> **Catatan:** 36 dokumen GeoIP berasal dari trafik eksternal nyata yang masuk ke
> VICTIM-NODE sebelum jaringan *host-only* dikunci. IP internal 192.168.56.x tidak
> memiliki GeoIP (private range). Attack Origin Map menampilkan trafik eksternal ini.

---

### 4.6 Berkas Tracked tapi Bermasalah

| Berkas | Masalah |
|--------|---------|
| `09-Evidence/elasticsearch-alert-sample.json` | Isi: `{ "error": "No Nmap alerts found in Elasticsearch" }` — query gagal waktu capture, bukan alert nyata |
| `09-Evidence/final-nmap-kibana-event.json` | File KOSONG (SHA: E3B0C44...) |
| `09-Evidence/nmap-alert-after-fix.json` | File KOSONG (SHA: E3B0C44...) |
| `04-Wazuh/ossec.conf` | File KOSONG — memerlukan `sudo` di VM untuk membaca konten nyata |

### 4.6 Arsip Provenance (Tidak Ditracking di Repo)

| Lokasi | Konten | Keputusan |
|--------|--------|-----------|
| `14-Research/archive/2026-06-21_evidence-snapshot/` | Snapshot 93 file pada 2026-06-21, SHA-256 per berkas | Dipertahankan on-disk; tidak dicommit (ukuran ~0.72MB tapi berisi config duplikat) |
| `14-Research/protocols/run_controlled_iterations.sh.bak_20260621` | Backup skrip orkestrator | Tidak dicommit (duplikat versi lama) |

---

## 5. Temuan Audit dan Tindakan

### 5.1 Duplikat Teridentifikasi

| Pasangan | Status | Tindakan |
|----------|--------|----------|
| `09-Evidence/final-nmap-suricata-alert.json` vs `14-Research/archive/.../evidence/final-nmap-suricata-alert.json` | Isi identik | Arsip di-disk, bukan di repo — tidak ada konflik |
| `09-Evidence/nmap-alert.json` (untracked, sintetis) vs `final-nmap-suricata-alert.json` | Berbeda: sintetis vs nyata (pilot) | Tidak ditambahkan ke repo |
| `09-Evidence/hydra-alert.json` (untracked, sintetis) vs `final-hydra-suricata-alert.json` | Berbeda: sintetis vs nyata (pilot) | Tidak ditambahkan ke repo |
| `09-Evidence/nikto-alert.json` (untracked, sintetis) vs `final-nikto-suricata-alert.json` | Berbeda: sintetis vs nyata (pilot) | Tidak ditambahkan ke repo |

### 5.2 Berkas Sintetis — Dikecualikan dari Repository

Berkas-berkas berikut memiliki data sintetis (timestamp bulat .123456/.654321,
field tidak lengkap, `src_ip: 192.168.56.1`) dan TIDAK ditambahkan ke repository:

- `09-Evidence/nmap-alert.json`
- `09-Evidence/hydra-alert.json`
- `09-Evidence/nikto-alert.json`
- `09-Evidence/safe_simulated_alerts.json`

### 5.3 Berkas Operasional — Dikecualikan

Berkas query runtime berikut tidak mewakili bukti penelitian:
- `09-Evidence/agg_unmapped.json`, `count_unmapped.json`, `search_enriched.json`, `fieldcaps.json`
- `09-Evidence/fetch_unmapped_samples.sh`
- `09-Evidence/safe-full-stack-injection.txt`

---

## 6. Rantai Perlacakan Lengkap Per Skenario

### Format: Serangan → Alert → Elasticsearch → Dashboard → SOAR → Bab IV

**Nmap:**
```
nmap -sS -p- 192.168.56.106 (ATTACKER .110)
  → Suricata SID 1000010 alert (eve.json)
  → Filebeat → Logstash (soc-pipeline.conf)
  → GeoIP enrichment → source.geo.location (jika IP publik)
  → mitre-mapping.yml: 1000010 → T1046 "Network Service Discovery"
  → pyramid.layer = "TTPs"
  → cti-logs-iqbal-* index (ES)
  → Kibana panel "MITRE Technique Bar" (dashboard-final-v5.ndjson)
  → Kibana panel "Attack Origin Map" cti-attack-origin-map (IP publik)
  → SOAR webhook /webhook (attack_type="nmap_scan")
  → iterations.csv baris 1-10 (MTTD avg 2,5s; NO_MITIG)
  → Bab IV §4.5 panel 11 (MITRE bar), §4.6 §Skenario 1
```

**Hydra:**
```
hydra -l root -P wordlist.txt ssh://192.168.56.106 (ATTACKER .110)
  → Suricata SID 1000020 alert (eve.json)
  → Filebeat → Logstash
  → mitre-mapping.yml: 1000020 → T1110.001 "Brute Force: Password Guessing"
  → cti-logs-iqbal-* index (ES)
  → Kibana panel "SSH Brute Force" (dashboard-final-v5.ndjson)
  → SOAR webhook /webhook (attack_type="hydra_brute")
  → Wazuh Rule 5763 → firewall-drop (VICTIM iptables)
  → iterations.csv baris 11-20 (MTTD avg 1,6s; MTTR avg 5,3s)
  → Bab IV §Skenario 2, Bab V §Analisis Hydra
```

**Nikto:**
```
nikto -h http://192.168.56.106 (ATTACKER .110)
  → Suricata SID 1000030 alert (eve.json)
  → Filebeat → Logstash
  → mitre-mapping.yml: 1000030 → T1595.002 "Active Reconnaissance: Vulnerability Scanning"
  → cti-logs-iqbal-* index (ES)
  → Kibana panel "Web Scan Activity" (dashboard-final-v5.ndjson)
  → SOAR webhook /webhook (attack_type="nikto_scan")
  → Wazuh Rule 31151 → firewall-drop (VICTIM iptables)
  → iterations.csv baris 21-30 (MTTD avg 2,2s; MTTR avg 3,1s)
  → Bab IV §Skenario 3, Bab V §Analisis Nikto
```

---

## 7. Ringkasan Kelengkapan Penelitian

| Komponen | Status | Berkas |
|----------|--------|--------|
| Aturan Suricata (3 SID) | ✅ Lengkap | `03-Suricata/custom.rules` |
| Pemetaan MITRE | ✅ Lengkap | `05-MITRE/mitre-mapping.yml` |
| Pipeline Logstash | ✅ Lengkap | `02-ELK/soc-pipeline.conf`, `99-mitre-normalize.conf` |
| Dashboard Kibana (21 panel) | ✅ Lengkap | `06-Dashboard/dashboard-final-v5.ndjson` |
| SOAR Flask | ✅ Lengkap | `12-SOAR-Dashboard/app/soar_app.py` |
| Dataset 30 iterasi | ✅ Lengkap | `14-Research/datasets/iterations.csv` |
| Protokol eksperimen | ✅ Lengkap | `14-Research/protocols/` (4 berkas) |
| Bukti validasi serangan | ✅ Lengkap | `07-Testing/*/validation_success.txt` |
| Bukti alert PILOT | ✅ Tersedia (fase pilot) | `09-Evidence/final-*-suricata-alert.json` |
| Konfigurasi Wazuh | ⚠️ Kosong | `04-Wazuh/ossec.conf` (perlu sudo di VM) |
| Screenshot dashboard | ⚠️ Ada di arsip | `14-Research/archive/.../screenshots/` (tidak dicommit) |
| Topology diagram | ✅ Tersedia | `01-Topologi/topologi_penelitian_elk_cti.png` (untracked) |
| GeoIP Attack Origin Map | ✅ Lengkap | 36 dok publik (USA:20, SG:16), panel `cti-attack-origin-map` |
| Saved Search Discover | ✅ Lengkap | 5 saved searches (all/nmap/hydra/nikto/mitre-mapped) |
| Jumlah alert penelitian di ES | ✅ Terverifikasi | SID 1000010: 180, SID 1000020: 64, SID 1000030: 111 (total 355) |
