# CHECKPOINT DISKUSI ARAH PENELITIAN — 2026-06-25

> Disimpan atas permintaan: lanjutkan SETELAH memetakan sistem live.
> Tidak ada perubahan sistem dilakukan pada sesi diskusi ini (mode: memahami konteks).

---

## 0. KEPUTUSAN FONDASI (terkunci)
- **Judul & fokus TERKUNCI:** *"Optimisasi Visualisasi Data Log dan Alert Siber Melalui Dashboard ELK Stack untuk Mendukung Pengambilan Keputusan Operasional CTI."*
- **Kontribusi inti = DASHBOARD visualisasi (Kibana) + konteks CTI**, untuk keputusan operasional analis. Deteksi (Suricata/Wazuh), respons (SOAR/Wazuh AR), dan MTTD/MTTR = **pendukung/alat ukur**, BUKAN klaim utama.
- **Bukti utama = studi responden before/after (10 partisipan, Discover vs Dashboard CTI)** — sampai sekarang MASIH KOSONG (`[AKAN DIISI]`).
- Prinsip kerja diskusi: **memperjelas = mempersempit & mengunci, BUKAN menambah.**

## 1. LANGKAH BERIKUTNYA (yang disepakati untuk dikerjakan dulu)
**Memetakan sistem live saat ini (fondasi) SEBELUM dokumentasi/eksplorasi baru.** Modul:
1. Inventaris **live vs repo** (service, versi, config aktif; cari di mana Telegram hidup).
2. Modul Elastic: ES (heap, index, ILM), Logstash (pipeline penuh + 3 kamus MITRE), Kibana (data view, dashboard, alerting, connectors).
3. Modul Deteksi: Suricata (rules 9000xxx vs 1000xxx — mana yang live), Wazuh (rule 5763/31151, active-response).
4. Modul Respons: bandingkan jalur SOAR-manual vs Wazuh-otomatis.
5. Modul SOAR: kode, DB, endpoint, Telegram.
6. Modul Dashboard (INTI): bedah `.ndjson` di `06-Dashboard/` panel-per-panel; tentukan versi final.
7. Modul Pengukuran: satukan definisi MTTD/MTTR; tentukan dataset resmi.

> Saat resume: mulai dari modul 1 (inventaris live vs repo). Siapkan perintah read-only di SOC + victim.

## 2. TEMUAN BESAR — DUA "DUNIA" SISTEM
**Kanon resmi** (Buku SOC Polinema Press [co-author pembimbing Pak Yuri], Manual Book/SOP, Proposal Bab I–III) vs **sistem live** kita sekarang. Divergensi yang harus direkonsiliasi:

| Hal | Kanon (buku/SOP/proposal) | Sistem live sekarang |
|---|---|---|
| IP attacker | **192.168.56.120** | 192.168.56.**110** |
| Index ES | **`soc-alerts-*`** | `cti-logs-iqbal-*` |
| Keamanan ES | xpack off, `http` | xpack on, `https` + password |
| SID rule | 9000001/2/3 ("CTI-LAB ...") | 1000010/20/30 ("[CTI] ...") |
| Respons | manual (analis → iptables) | otomatis (Wazuh active-response) |
| Notifikasi | tidak ada di kanon | **Telegram live (TIDAK ada di repo)** |
| Skenario C | Privilege Escalation/Metasploit (Bab III) / hanya 2 serangan (Bab I) | **Nikto** (T1595.002) |
| Iterasi | 14 (naskah Bab V) | **30** (10 Nmap+10 Hydra+10 Nikto) |

## 3. DEFINISI MTTD/MTTR (TIDAK KONSISTEN — perlu disatukan)
- `iterations.csv` (30-run) & Naskah Bab IV Tabel 4.8: **MTTD=T1−T0, MTTR=T2−T0** (T0=peluncuran).
- Buku/Manual Bab 5: MTTR = **T_respons − T_deteksi** (containment manual).
- `soar_app.py`: MTTD = waktu dicatat SOAR − timestamp_alert; MTTR = waktu klik aksi − waktu dicatat SOAR (manual).
- → MTTD relatif konsisten (T1−T0); **MTTR yang berbeda-beda.** Harus pilih SATU definisi & terapkan di seluruh naskah. Semua T0/T1/T2 tersimpan → bisa hitung ulang.

## 4. ASAL PERGESERAN FOKUS (sudah dipahami)
SOP "Pelaporan Insiden" (di buku/SOP) → inisiatif otomasi pelaporan per-24-jam → tambah **Telegram** → tambah **active-response otomatis** → fokus bergeser dari "visualisasi bantu manusia" ke "sistem merespons sendiri". User sadar & ingin re-anchor ke visualisasi. Koreksi presisi: **Telegram mempercepat MTTA/kesadaran analis, BUKAN MTTD sistem.**

## 5. SUMBER DAYA & RAMBU
- **Elastic Trial 30 hari** AKTIF. Tujuan user: **menambah literatur ELK + maksimalkan fitur**, TANPA ubah konteks.
- **AWS kredit**: $100, sisa ~$93,29. ⚠️ **VERIFIKASI: tanggal kedaluwarsa tampak 20/06/2026 (hari ini 25/06) — kemungkinan SUDAH EXPIRED.** Cek dulu sebelum rencana honeypot.
- **Batasan Bab I = "hanya fitur Basic (gratis)"** → klaim inti WAJIB di fitur Basic (reproducible). Fitur trial = eksplorasi/literatur/future work, diberi label "butuh lisensi berbayar".

### Klasifikasi fitur ELK (untuk "literatur tertata")
- **Basic (inti, reproducible):** Lens, Vega, Canvas, Maps+GeoIP, ES|QL, EQL, Alerting threshold + Webhook connector, Cases, ILM+Data streams, Detection Rules (query-based), Continuous Transform.
- **Trial/Platinum (eksplorasi/literatur saja):** ML Anomaly Detection, Attack Discovery (AI+LLM), Reporting PDF/PNG (verifikasi; CSV=Basic), Indicator-match Threat Intel rules.

## 6. RUANG LINGKUP 3-LAPIS (usulan kompas — belum difinalkan jadi dokumen)
- **INTI:** dashboard visualisasi (13+6 panel), MTTD/MTTR terkontrol, studi responden — Basic + lab lokal.
- **PENGAYAAN:** data nyata honeypot (GeoIP/threat actor nyata), eksplorasi fitur premium — AWS + trial, time-boxed, berlabel.
- **FUTURE WORK:** SOAR auto-response sebagai klaim, ML low-and-slow, STIX/TAXII.
- **Arsitektur hemat honeypot (bila jadi):** honeypot kecil di AWS (Suricata+Filebeat, time-boxed 5–7 hari) → Tailscale → **SOC tetap lokal** (pakai ELK yang sudah jalan). Hemat biaya, pakai ulang sistem berjalan.

## 7. KEPUTUSAN YANG MASIH TERTUNDA (untuk dibahas setelah pemetaan)
1. Dataset resmi: **14 iterasi (manual, naskah)** atau **30 iterasi (otomatis, hasil baru)**?
2. Model respons untuk naskah: **manual (SOAR)** atau **otomatis (Wazuh AR)**? (atau dua-duanya dengan framing jelas)
3. Definisi MTTR final: **T2−T0** atau **T2−T1**?
4. Skenario C: **Metasploit (kanon)**, **Nikto (live)**, atau tetap 2 skenario?
5. Penomoran SID & logika deteksi Hydra: **9000xxx (established, MTTD~15s)** atau **1000xxx (SYN, MTTD~1.6s)**?
6. Penamaan index: **soc-alerts-*** atau **cti-logs-iqbal-***?
7. Rekonsiliasi IP attacker **.120 vs .110**.

## 8. FILE YANG DIBUAT SELAMA SESI INI (bahan, belum final)
- `11-Bab4/kesesuaian-konsep-vs-implementasi.md` — analisis kesesuaian + 9 perubahan.
- `11-Bab4/draft-bab5-pengujian-dan-analisis.md` — draft Bab 5.5/5.6 + klarifikasi MTTR (pakai data riil 30-run).
- `11-Bab4/remediasi-pipeline-troubleshooting.md` (§7 addendum) & `PROGRESS-CHECKPOINT-2026-06-23.md` (hasil 30-run).
- `14-Research/protocols/system_readiness_check.sh` — checklist kesiapan (29/29 OK).
- `14-Research/protocols/cti-unblock.sh`, `run_controlled_iterations.sh` (patched), `02-ELK/patch_logstash_ar.py`, `patch_filebeat_ar.py`.
- Catatan: dokumen-dokumen ini lahir dari era "sistem live otomatis" — perlu diselaraskan dengan keputusan §7.

## 9. HASIL 30-RUN (data riil, tersimpan)
`~/research-archive/2026-06-21_controlled-run/iterations.csv` (+ backup `_FINAL_`). Nmap MTTD 2,5s (NO_MITIG); Hydra MTTD 1,6s / MTTR 5,3s; Nikto MTTD 2,2s / MTTR 3,1s. Mitigasi Nikto NYATA (Wazuh rule 31151). Deteksi 100%.

## 10. PREFERENSI/INSTRUKSI USER (untuk dipatuhi saat resume)
- Selalu sebut **DI MANA** perintah dijalankan (SOC/victim/attacker) + jelaskan SEBELUM beri sintaks.
- Perintah `sudo`/`read -s` dijalankan SENDIRI (paste multi-baris bikin prompt password "memakan" baris berikut).
- Chat menghapus whitespace awal pada output yang dipaste → patch pakai Python `.strip()` / `printf` per-baris (kebal whitespace), JANGAN sed anchor berbasis indentasi.
- READ-ONLY by default; tunjukkan diff + backup sebelum tulis; satu fase satu waktu; jelaskan sebelum aksi destruktif.
- Respons dalam Bahasa Indonesia.
- JANGAN dokumentasi ke `.docx` sebelum sistem dipahami penuh. JANGAN ubah arah/konteks penelitian.

---

## 11. HASIL MODUL 1 — INVENTARIS LIVE (terkonfirmasi 2026-06-25)

### Versi & service (1A)
- SOC 6/6 active. **ES/Kibana/Filebeat/Logstash = 8.19.12**, **Wazuh-manager = 4.7.5-1**.

### Wazuh integrations & active-response (1B) — fakta penting
- **Telegram = integrasi Wazuh `custom-telegram`** di `/var/ossec/integrations/custom-telegram` + blok `<integration>` di `ossec.conf` (level ≥10, alert_format json, hook_url bot). **TIDAK ada di repo** → konfirmasi repo≠live.
- **BARU/belum terdata: integrasi `abuseipdb`** (level ≥5, API key) — pengayaan reputasi IP (threat intel). Belum pernah dibahas/didokumentasikan.
- **Active-response `firewall-drop` OTOMATIS**: location local, **level 10**, timeout 180s. (Konfirmasi: respons live = otomatis.)
- Wazuh `localfile` membaca: `active-responses.log`, `/var/log/auth.log`, `/var/log/syslog`, **`/var/log/suricata/fast.log`** → Suricata "CTI-LAB ..." masuk Wazuh→Telegram lewat fast.log.
- ⚠️ **Hygiene: `ossec.conf` tampak punya blok DUPLIKAT** (`<command>`, `<active-response>`, `<integration>` muncul ganda/nested). Perlu dirapikan nanti (bukan sekarang).

### Index Elasticsearch (1C)
- **Index utama LIVE = `cti-logs-iqbal-*`** (harian 2026.05.18 → 2026.06.25, volume besar; mis. 06.20 = 1,07 jt dok/816MB). **TIDAK ADA `soc-alerts-*`** → kanon buku/SOP/proposal (`soc-alerts-*`) BUKAN yang live.
- `cti-threat-score-iqbal` = 263 dok (output Continuous Transform threat score). Aktif.
- **Legacy/bypass**: `.ds-filebeat-8.19.12-*` (672k; **7,5 jt dok/12,2GB**; 157k) + `filebeat-8.19.12-2026.05.17/18` → sisa jalur Filebeat-langsung-ke-ES (era bypass). Kandidat dibersihkan via ILM nanti.
- `.internal.alerts-ml.anomaly-detection-health` & `transform.health` ada → fitur ML/Transform sudah pernah disentuh (ML = trial).

### Komponen yang kini diketahui ADA tapi belum terdokumentasi
1. Integrasi **Telegram** (Wazuh custom-telegram).
2. Integrasi **AbuseIPDB** (reputasi IP).
3. **Continuous Transform** threat score (`cti-threat-score-iqbal`).
4. Sisa **data stream filebeat** (jalur bypass lama, volume besar).

### Tambahan daftar rotasi kredensial (setelah riset)
- Bot token Telegram & API key AbuseIPDB (tampil di `ossec.conf` saat inventaris) → **rotasi**.

### Belum dipetakan (lanjutan Modul 1D + dst)
- Isi `soc-pipeline.conf` live (sudah pernah dilihat; perlu konfirmasi final), Filebeat victim, **rules Suricata live (9000xxx vs 1000xxx)**, dan **objek Kibana (dashboard `.ndjson`, data view, alerting rules, connectors)**.

### Modul 1D — objek Kibana & rule Suricata (terkonfirmasi)
- **Dashboard CTI live (2 buah, di luar dashboard bawaan Elastic/System):**
  - `cti-dashboard-main` — "Dashboard CTI - Monitoring Serangan Jaringan (ELK Stack)"
  - `v3-cti-dashboard-final` — "CTI Dashboard V3"
  - (Naskah menyebut "v2 PRO 13 panel" + "V3 6 panel"; live tampak: main + V3.)
- **Data view CTI:** `cti-logs-iqbal-*` (muncul **2x → kemungkinan duplikat**). **Tidak terlihat data view `cti-threat-score-iqbal`** → panel Top Threat Actors perlu dicek sumbernya.
- **Alerting rules (3, semua `.es-query` = Basic, enabled):** New Threat Actor (MEDIUM), Port Scan (CRITICAL), Failed Login (HIGH). → sesuai KF-04, **reproducible (Basic)**. ✓
- **CONNECTORS = KOSONG.** Artinya alerting rules **tidak punya action/notifikasi**; Telegram murni via integrasi Wazuh, webhook SOAR via Logstash. Rules Kibana = "deteksi saja".
- **Suricata rules live = `1000010/1000020/1000030`** (rev 1/2/3, "[CTI] ..."), terdaftar di `suricata.yaml` (`suricata.rules` + `custom.rules`). → **BUKAN 9000xxx.** Era 9000xxx (di naskah Bab V) sudah digantikan. **Divergensi SID terkonfirmasi.**

### Keputusan §7 yang kini terjawab oleh fakta live
- SID & deteksi: live = **1000xxx** (Nmap SYN 50/5s, Hydra SYN 5/60s, Nikto behavioral 20/10s). Naskah 9000xxx perlu diselaraskan.
- Index: live = **cti-logs-iqbal-***. `soc-alerts-*` (buku/SOP) perlu diselaraskan.

### Modul 1D-3 — Inventaris panel (produk inti)
Panel tersimpan (lens/visualization):
- lens: **CTI - Port Scanning Detection**, **CTI - Top 10 Source IP (Aktor Ancaman)** (sisa era "v2/main")
- visualization (9 panel **V3**): MITRE Alert Timeline by Tactic; MITRE ATT&CK Tactic Distribution; MITRE ATT&CK Technique Distribution; Pyramid of Pain Layer Distribution; Top Threat Actors Table; Total Mapped MITRE Alerts; **Validasi Nmap (T1046)**; **Validasi Hydra (T1110.001)**; **Validasi Nikto (T1595.002)**.
- Dashboard: `cti-dashboard-main` = **7 panel**; `v3-cti-dashboard-final` ("CTI Dashboard V3") = **~9 panel** (angka perlu konfirmasi ulang; output "98" ambigu).

**Catatan penting:**
- V3 punya **9 panel** (bukan 6 spt naskah Bab IV) — termasuk **3 panel Validasi Nmap/Hydra/Nikto** → **produk live sudah mencakup 3 skenario termasuk Nikto** (konsisten dgn 30-run, beda dgn naskah Bab IV yg 2 skenario).
- **GAP Pilar 4 (MTTD/MTTR):** TIDAK ada panel MTTD/MTTR dan **TIDAK ada index `cti-mttd-mttr-iqbal`** (grep di 1C kosong). MTTD/MTTR saat ini hanya di `iterations.csv` (file) → **belum divisualisasikan di dashboard.** Ini gap nyata untuk skripsi "optimisasi visualisasi".
- **Kemungkinan panel rusak:** "Top Threat Actors Table" sumbernya `cti-threat-score-iqbal` tapi **data view-nya tak terlihat** (hanya `cti-logs-iqbal-*`, malah duplikat). Perlu verifikasi apakah panel ini tampil data.

### Pemetaan panel → 4 pilar (awal)
- Pilar 1 Visualisasi: semua panel.
- Pilar 2 MITRE mapping: 4 panel MITRE + 3 Validasi.
- Pilar 3 Hybrid detection: Validasi (Suricata) + Top Source IP + Port Scanning; (Wazuh via AbuseIPDB/auth).
- Pilar 4 MTTD/MTTR: **belum ada panel (GAP).**
- Pyramid of Pain: panel Pyramid Layer Distribution.
- Threat scoring (Endsley): Top Threat Actors (perlu cek sumber data).

### Modul 1D-4 — verifikasi final (MODUL 1 SELESAI)
- `cti-dashboard-main` = **7 panel**; `CTI Dashboard V3` = **9 panel** (angka "98" sebelumnya glitch).
- **Top Threat Actors Table = RUSAK**: data view `cti-threat-score-iqbal` **= 0 (tidak ada)**, padahal index `cti-threat-score-iqbal` berisi 263 dok → panel orphan, perlu data view.
- **Data view `cti-logs-iqbal-*` DUPLIKAT** (2 objek: `7afca9a4...` & `ba3ea9c0...`).

## STATUS: MODUL 1 (PEMETAAN SISTEM LIVE) — SELESAI ✅

### Peta sistem live (ringkas)
Attacker `.110` → Victim `.106` (Suricata sid 1000010/20/30 → eve.json; Wazuh agent → auth.log/fast.log) → Filebeat → Logstash `.10:5044` (pipeline: Drop Stats → GeoIP → DROP noise STREAM → normalize → MITRE enrich → Pyramid → SOAR norm → tag firewall-drop) → ES `cti-logs-iqbal-*` → Kibana (2 dashboard). Paralel: Wazuh `firewall-drop` (auto, level10/180s) + integrasi **Telegram** & **AbuseIPDB**; webhook → SOAR Flask (incident log + aksi manual). Threat score via Continuous Transform → `cti-threat-score-iqbal`.

### DAFTAR GAP/ISU LIVE (semua in-scope, Basic, untuk perkuat "optimisasi visualisasi")
- **GAP-A (prioritas tinggi):** Pilar 4 MTTD/MTTR **belum divisualisasikan** (tak ada index `cti-mttd-mttr-iqbal`, tak ada panel; data hanya di `iterations.csv`).
- **GAP-B:** Panel **Top Threat Actors** rusak (data view `cti-threat-score-iqbal` hilang).
- **GAP-C:** Data view `cti-logs-iqbal-*` duplikat.
- **Hygiene:** `ossec.conf` blok duplikat; sisa data stream `.ds-filebeat-*` (12GB) belum dibersihkan.

### DAFTAR REKONSILIASI NASKAH ↔ LIVE (untuk dokumentasi nanti)
| Item | Naskah/Buku | Live | Aksi |
|---|---|---|---|
| IP attacker | .120 | .110 | samakan |
| Index | soc-alerts-* | cti-logs-iqbal-* | samakan |
| SID | 9000xxx | 1000xxx | update naskah |
| Skenario | 2 (Nmap+Hydra) / Metasploit | **3 (Nmap+Hydra+Nikto)** | update naskah → Nikto |
| Panel V3 | 6 | **9** (incl 3 Validasi) | update naskah |
| Respons | manual | otomatis (Wazuh) | pilih framing |
| MTTR def | beragam | T2−T0 (iterations.csv) | kunci 1 definisi |
| Iterasi | 14 | 30 | pilih dataset resmi |
