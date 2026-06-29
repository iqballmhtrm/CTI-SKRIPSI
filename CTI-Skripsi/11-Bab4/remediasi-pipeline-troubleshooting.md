# Remediasi Pipeline & Troubleshooting Sistem CTI-ELK (Bab 4)

> Dokumen ini mencatat analisis akar masalah (root cause analysis), perbaikan yang
> telah diterapkan, dan langkah penyelesaian tersisa untuk memperoleh pengukuran
> MTTD/MTTR terkontrol (Tabel 4.8). Ditulis untuk diintegrasikan ke
> `DRAFT-SKRIPSI-FINAL-IQBAL.docx`.

Tanggal: 2026-06-23 · Lingkungan: Lab VirtualBox host-only `192.168.56.0/24`
Node: SOC `192.168.56.10` (iqbal) · Victim `192.168.56.106` (korban) · Attacker/Kali `192.168.56.110` (kali)

---

## 1. Ringkasan Eksekutif

Saat menjalankan orkestrasi 30 iterasi (10 Nmap + 10 Hydra + 10 Nikto), seluruh
iterasi menghasilkan `NO_DETECT`/`NO_MITIG`. Investigasi menemukan **rangkaian
masalah berlapis** (bukan satu penyebab tunggal), mulai dari rule deteksi yang
belum ter-deploy hingga kemacetan pipeline ingest selama ~24 jam. Seluruh akar
masalah berhasil diidentifikasi; sebagian besar sudah diperbaiki dan sisanya
terdokumentasi sebagai langkah penyelesaian.

---

## 2. Analisis Akar Masalah (Root Cause Analysis)

Urutan temuan (dari gejala ke akar):

1. **Custom rule Suricata belum ter-deploy.** Orchestrator meng-query SID
   `1000010/1000020/1000030`, tetapi `/etc/suricata/rules/custom.rules` tidak ada
   di victim dan `rule-files` hanya memuat `suricata.rules`. File `local.rules`
   lama memakai SID berbeda (`9000001-9000004`) dan tidak pernah dimuat.

2. **Kebocoran file descriptor (fd leak) di SOAR.** Pola
   `with sqlite3.connect(DB_PATH) as conn:` pada Python **tidak menutup koneksi**
   (hanya commit/rollback). Setiap permintaan `/webhook` membocorkan 1 fd. Banjir
   permintaan dari Logstash menumpuk hingga ~1018 koneksi (batas 1024) → SQLite
   gagal `unable to open database file` → webhook membalas HTTP 500.

3. **Pipeline Logstash macet karena output HTTP gagal.** Output HTTP Logstash
   mengirim setiap event ke `/webhook` SOAR. Karena webhook 500, Logstash
   retry tanpa henti → backpressure → seluruh pipeline (termasuk output
   Elasticsearch) berhenti. Akibatnya **tidak ada data baru masuk ES sejak
   2026-06-21 14:10** (gap ~24 jam).

4. **Skema database SOAR tidak sinkron.** Setelah fd diperbaiki, webhook tetap
   500: `table incidents has no column named mitre_technique`. `init_db()`
   membuat kolom `mitre_tactic`, sedangkan kode INSERT memakai `mitre_technique`
   & `mitre_status`.

5. **Active-response salah target (self-block).** Victim menambahkan aturan
   `iptables -A INPUT -s 192.168.56.10 -j DROP` (memblok IP SOC sendiri) →
   SOC tidak bisa ping/SSH ke victim (100% loss, timeout).

6. **Banjir replay Filebeat (dua shipper).** Dua Filebeat me-replay log lama
   dari offset lama (kemungkinan akibat VM di-resume dari saved-state):
   - Filebeat victim → `eve.json` (Suricata) **langsung ke Elasticsearch**.
   - Filebeat SOC → `alerts.json` (Wazuh) → Logstash.
   Keduanya membanjiri ES dengan duplikat ber-timestamp lama (`@timestamp`
   mentok di 2026-06-21 14:10 sementara total dokumen melonjak ratusan ribu).

7. **Mismatch arsitektur jalur ingest (akar struktural).** Terdapat DUA jalur:
   - **Suricata `eve.json`** (field `alert.signature_id = 1000010`) → Filebeat
     victim → **langsung ES** → datastream `filebeat-*` (tanpa Logstash, tanpa
     enrichment MITRE, tidak masuk `cti-logs-iqbal-*`).
   - **Wazuh `alerts.json`** → Filebeat SOC → Logstash → `cti-logs-iqbal-*`
     (struktur `data.*`, ter-enrich MITRE). Di sini Suricata hanya muncul
     sebagai hasil decode `fast.log` oleh Wazuh dengan id di `data.id`
     (mis. `"1:1000010:1"`), **bukan** `data.alert.signature_id = 1000010`.
   Orchestrator meng-query `cti-logs-iqbal-*` + `data.alert.signature_id == 1000010`
   → tidak pernah cocok.

8. **Banjir NOISE STREAM.** Sumber kebisingan dominan: event Suricata
   "STREAM packet with invalid ack / out of window" dari trafik manajemen
   `192.168.56.1` & `192.168.56.10` ke port `:5000` (dashboard SOAR). Dashboard
   menunjukkan `192.168.56.1` ≈ 571.515 alert dan `192.168.56.10` ≈ 391.264 alert,
   serta SOAR mencatat ~470.665 insiden "New". Noise inilah pemicu beruntun:
   penumpukan fd, self-block active-response, dan beban berlebih (victim sempat
   tak responsif).

---

## 3. Perbaikan yang Telah Diterapkan (dengan bukti)

| # | Perbaikan | Bukti verifikasi |
|---|-----------|------------------|
| 1 | Deploy `custom.rules` (sid 1000010/1000020/1000030) ke `/var/lib/suricata/rules/` + daftarkan di `rule-files` | `suricata -T`: `2 rule files processed. 50239 rules successfully loaded, 0 rules failed` |
| 2 | Reload Suricata; uji deteksi di sumber | `grep -c 'Nmap SYN Stealth Scan Detected' eve.json` = 1 (alert sid 1000010 muncul) |
| 3 | Perbaiki fd leak SOAR: `with sqlite3.connect()` → `with contextlib.closing(sqlite3.connect()) as conn, conn:` (4 lokasi) + `import contextlib` | fd proses turun dari 1023 → 4–5; `dbconns=0` |
| 4 | Perbaiki skema: tambah kolom `mitre_technique`, `mitre_status` di `init_db()`; buat ulang `incidents.db` | `PRAGMA table_info(incidents)` memuat kedua kolom; `webhook HTTP 201` |
| 5 | Hapus aturan self-block | `iptables -D INPUT -s 192.168.56.10 -j DROP`; ping SOC→victim 0% loss |
| 6 | Hentikan banjir replay (parkir kedua Filebeat) | total dokumen ES stabil (`t1 = t2`) |
| 7 | Set `tail_files: true` pada Filebeat SOC + reset registry | `Config OK` (penyesuaian agar baca dari ujung) |

Catatan keamanan terdokumentasi: kredensial `elastic` tampil plaintext pada
`filebeat.yml` victim → dijadwalkan rotasi setelah riset.

---

## 4. Langkah Penyelesaian Tersisa (Runbook)

> Tujuan: `cti-logs-iqbal-*` & SOAR bersih, jalur Suricata tersatukan, dan
> 30 iterasi menghasilkan MTTD/MTTR valid. Pola kerja: backup → ubah → verifikasi.

### Langkah A — Redam NOISE STREAM di sumber (Suricata, di victim)
Tujuan: hentikan alert "STREAM invalid ack/out of window" untuk trafik manajemen
(`:5000` dashboard, host `.1`, SOC `.10`).
Opsi (pilih yang paling bersih setelah meninjau konfigurasi):
- Nonaktifkan ruleset `stream-events.rules` / `decoder-events.rules` yang
  memicu noise, atau
- Tambahkan `suppress`/`threshold` di `threshold.config` untuk SID terkait
  (mis. `2210045`) bagi `track by_either` IP `.1`/`.10`, atau
- Kecualikan trafik port 5000 dari inspeksi (BPF filter Suricata `not port 5000`).

### Langkah B — Satukan jalur Suricata → Logstash → `cti-logs-iqbal-*`
- Ubah output Filebeat victim dari `output.elasticsearch` (langsung ES) menjadi
  `output.logstash: hosts: ["192.168.56.10:5044"]`.
- Pastikan pipeline Logstash mem-parse `eve.json` (ndjson) dan menghasilkan
  `data.alert.signature_id` + menjalankan `translate` MITRE (dictionary
  `mitre-mapping.yml`) sebelum output ke `cti-logs-iqbal-%{+YYYY.MM.dd}`.
  *(Perlu konfirmasi isi `/etc/logstash/conf.d/*.conf` untuk finalisasi.)*

### Langkah C — Filter NOISE di Logstash (lapis kedua)
- Tambah `if "STREAM" in [alert][signature] and [src_ip] in ["192.168.56.1","192.168.56.10"] { drop {} }`
  agar noise yang lolos tidak masuk index/SOAR.

### Langkah D — Reset SOAR
- Stop SOAR → hapus/arsip `incidents.db` (berisi ~470k noise + baris uji) →
  start SOAR (`init_db` membuat skema benar) → verifikasi `COUNT(incidents)=0`.

### Langkah E — Uji end-to-end bersih
- Sinkronkan jam Kali (offset < 2 dtk), jalankan satu Nmap dari Kali →
  pastikan `data.alert.signature_id:1000010` muncul di `cti-logs-iqbal-*`
  dengan `@timestamp` terkini (< 60 dtk) → konfirmasi T1; dan event
  firewall-drop attacker → konfirmasi T2.

### Langkah F — Jalankan 30 iterasi
- `DRY_RUN=1 ./run_controlled_iterations.sh <PASS>` (verifikasi query) →
  bila bersih, `RUN_NIKTO=1 ./run_controlled_iterations.sh <PASS> | tee iteration_log_*.txt`.
- Kumpulkan `iterations.csv` → susun **Tabel 4.8** (T0/T1/T2/MTTD/MTTR per iterasi).

---

## 5. Definition of Done (Lab Lokal)
- [ ] Noise STREAM teredam (`cti-logs-iqbal-*` & SOAR bersih).
- [ ] Jalur Suricata tersatukan (sid 1000010 di `cti-logs-iqbal-*`, ter-enrich MITRE).
- [ ] Uji end-to-end T1 & T2 lulus.
- [ ] `incidents.db` ter-reset.
- [ ] 30 iterasi selesai → `iterations.csv` → Tabel 4.8 bersih.

---

## 6. Fase Lanjutan — Pemaksimalan Elastic/ELK (Track 2)
Setelah lab lokal tuntas, lanjut ke topologi terbaru:
- **Honeypot ber-IP publik** (AWS EC2, VPS A) — Suricata + Wazuh + Filebeat,
  egress dibatasi, terhubung ke SOC via VPN privat (Tailscale).
- **Elastic Trial** — aktifkan fitur premium (ML Anomaly, Security,
  Attack Discovery, Maps/GeoIP, Reporting) untuk analisis lanjutan.
- **Validasi dunia nyata** (scoped ~7 hari): statistik serangan (negara asal,
  top teknik MITRE) sebagai pelengkap hasil terkontrol.
- Pemetaan ke 4 pilar penelitian (visualisasi, deteksi anomali, MTTD/MTTR,
  threat intelligence).

> Prinsip: amankan hasil inti terkontrol lebih dulu; honeypot/cloud sebagai
> pengayaan, bukan pengganti. Waspadai scope creep dan masa berlaku trial.

---

## 7. Addendum 2026-06-24 — Penyelesaian Final & Eksekusi 30-Run

Bagian ini melengkapi runbook §4 dengan tindakan final yang telah dieksekusi
sehingga seluruh prasyarat pengukuran terpenuhi dan 30 iterasi dijalankan.

### 7.1 Penyatuan jalur & normalisasi (lanjutan §4-B/C)
- Filebeat victim final mengirim ke **Logstash 5044** (bukan ES langsung).
- Logstash menambah filter **normalisasi** `alert.* → data.alert.*` dan **drop
  noise STREAM** untuk trafik manajemen, sehingga `data.alert.signature_id`
  konsisten dengan query orchestrator dan index `cti-logs-iqbal-*` bersih.

### 7.2 Perbaikan deteksi per skenario
| Skenario | Masalah | Perbaikan | Verifikasi |
|---|---|---|---|
| Nmap (T1046) | — | rule sid 1000010 `count 50/5s` | ES sid 1000010, MTTD ~2 dtk |
| Hydra (T1110.001) | ambang `10/10s` terlalu ketat (Hydra ~17–20 percobaan/menit) | turunkan ke **`count 5/60s`** (rev:2) | eve.json + ES sid 1000020 (count=3) |
| Nikto (T1595.002) | Nikto menyamar User-Agent browser → signature `content:"Nikto"` gagal | ganti ke **rule behavioral** `count 20/10s` (rev:3) | ES sid 1000030 (count=3) |

### 7.3 Pipeline MTTR (T2) — active-response firewall-drop
Wazuh 4.x menulis `active-responses.log` dalam format JSON sehingga rule klasik
651 tidak terpicu. Solusi: kirim `/var/ossec/logs/active-responses.log` victim
via Filebeat (`log_type: wazuh-ar`) → Logstash menandai entri `"command":"add"`
sebagai `rule.description="Host Blocked by firewall-drop Active Response"` +
`data.srcip` + `@timestamp` = waktu eksekusi blokir (tz Asia/Jakarta).
**Verifikasi:** Hydra → Wazuh rule 5763 (brute) → firewall-drop "add" `.110` →
ter-index dengan `rule.description` & `srcip 192.168.56.110`. Query T2
orchestrator menemukan event.

### 7.4 Independensi antar-iterasi (kontrol eksperimen)
Active-response memblok `.110` di iptables victim; tanpa reset, iterasi setelah
Hydra akan gagal konek. Dipasang script root `/usr/local/sbin/cti-unblock.sh`
(loop hapus DROP `.110`) + sudoers NOPASSWD; orchestrator memanggil unblock di
awal **setiap** iterasi (dilewati saat DRY_RUN). Hasil uji: `UNBLOCK OK`.

### 7.5 Parameter & validasi pra-run
- Offset jam victim↔SOC = 0,59 dtk; kali↔SOC = 0,25 dtk (< 1 dtk).
- `MITIG_TIMEOUT` 180→90 dtk (hanya waktu tunggu polling; tidak mengubah nilai
  terukur) agar durasi run wajar.
- **DRY_RUN = 30/30 DRYRUN_OK** (validasi query ES seluruh SID).

### 7.6 Eksekusi 30-run — SELESAI (30/30 OK, 0 NO_DETECT)
Dijalankan via `nohup` di SOC → `~/research-archive/2026-06-21_controlled-run/iterations.csv`
(backup `_FINAL_*`). Seluruh 30 iterasi terdeteksi (tingkat deteksi 100%, tanpa
*false negative*). Rekapitulasi akhir (sumber **Tabel 4.8**; rincian per-iterasi
dan analisis lengkap ada di `draft-bab5-pengujian-dan-analisis.md`):

| Skenario (iter) | MITRE | MTTD rata² (rentang) | MTTR rata² (rentang) | Mitigasi otomatis |
|---|---|---|---|---|
| Nmap (1–10)   | T1046     | **2,5 dtk** (1–6) | — (NO_MITIG) | tidak (recon jaringan, tak picu rule HIDS) |
| Hydra (11–20) | T1110.001 | **1,6 dtk** (1–4) | **5,3 dtk** (2–9) | ya — Wazuh 5763 (sshd brute) → firewall-drop |
| Nikto (21–30) | T1595.002 | **2,2 dtk** (1–4) | **3,1 dtk** (2–4) | ya — Wazuh 31151 (banjir 400 web) → firewall-drop |

Catatan: pemicu mitigasi Nikto terverifikasi rule **31151** "Multiple web server
400 error codes" (level 10) — MTTR Nikto valid, bukan artefak Hydra. Status
`NO_MITIG` pada Nmap adalah hasil sah (auto-respons hanya untuk serangan yang
berinteraksi langsung dengan layanan korban).

### 7.7 Definition of Done — status mutakhir (FINAL)
- [x] Noise STREAM teredam; index/SOAR bersih.
- [x] Jalur Suricata tersatukan (sid 1000010/20/30 di `cti-logs-iqbal-*`, ter-enrich MITRE).
- [x] Uji end-to-end T1 (Nmap/Hydra/Nikto) & T2 (firewall-drop) lulus.
- [x] Independensi antar-iterasi (unblock otomatis) terpasang.
- [x] **30 iterasi SELESAI** (30/30 OK) → `iterations.csv` → Tabel 4.8 (lihat §7.6).
- [x] Reset SOAR `incidents.db` (823.263 baris noise historis → 0; backup `incidents.db.bak_preclean_*`).
- [ ] Rotasi kredensial `elastic`/`testuser`; tinjau sudoers `clocksync`(Kali)/`cti-unblock`(victim) (setelah riset).
- [ ] Integrasi hasil ke `DRAFT-SKRIPSI-FINAL-IQBAL.docx`/`Bab4.docx` (Tabel 4.8 + narasi dari §7 dan `draft-bab5-pengujian-dan-analisis.md`).

### 7.8 Catatan integritas data (untuk pertanggungjawaban ilmiah)
- Semua nilai MTTD/MTTR dihitung per iterasi (T1−T0, T2−T0); jeda antar-iterasi
  tidak memengaruhi nilai terukur.
- Rule Nikto berbasis perilaku (laju permintaan) mendeteksi **aktivitas
  pemindaian** (recon), bukan string vendor — lebih tahan evasion dan sesuai
  pemetaan T1595.002.
- Status `NO_MITIG` pada Nmap adalah hasil sah: sistem melakukan auto-respons
  (firewall-drop) terhadap serangan yang berinteraksi langsung dengan layanan host —
  Wazuh rule 5763 (brute force SSH) dan rule 31151 (banjir HTTP 400 web). Nmap tidak
  memicu rule host apapun karena *port scan* murni tidak berinteraksi dengan layanan,
  sehingga T2 tidak terbentuk. Nikto memiliki MTTR valid (rata-rata 3,1 detik)
  yang dipicu oleh rule 31151.
