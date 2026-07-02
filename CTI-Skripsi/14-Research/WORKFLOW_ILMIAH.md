# Alur Kerja Ilmiah — CTI Dashboard ELK Stack
## Kontribusi Metodologis Penelitian

**Peneliti:** Muhammad Iqbal Muhtaram (2241720265)  
**Judul:** Optimisasi Visualisasi Data Log dan Alert Siber Melalui Dashboard ELK Stack untuk Mendukung Pengambilan Keputusan Operasional CTI  
**Institusi:** Politeknik Negeri Malang

> **Pembaruan terakhir:** 2026-07-02 — sistem tervalidasi end-to-end real-time (nmap, hydra, nikto).
> Ringkasan perubahan ada di bagian **8. Changelog Validasi Sistem**.

---

## 1. Alur Kerja Deteksi Ancaman (Threat Detection Workflow)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    THREAT DETECTION PIPELINE                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ATTACKER (192.168.56.110) — Kali Linux 2026.1                      │
│      │                                                              │
│      │  [T0] Serangan dimulai                                       │
│      │  ┌──────────────┐                                            │
│      ├─▶│ Nmap Scan    │ → SID 1000010 → MITRE T1046               │
│      ├─▶│ Hydra SSH BF │ → SID 1000020 → MITRE T1110.001           │
│      └─▶│ Nikto Web    │ → SID 1000030 → MITRE T1595.002           │
│         └──────┬───────┘                                            │
│                │  (serangan menuju VICTIM .106:22/.106:80)          │
│                ▼                                                    │
│         VICTIM (192.168.56.106) — Ubuntu + Apache 2.4              │
│                │                                                    │
│                │  Traffic host-only di-mirror ke SOC               │
│                ▼  (promiscuous "allow-all" pada adapter SOC)        │
│         SURICATA IDS (di SOC, interface enp0s8, mode SPAN)          │
│         ├── Deteksi paket mencurigakan (app-layer HTTP aktif)       │
│         ├── Match custom.rules (SID 1000010/20/30)                  │
│         └── [T1] Alert di-raise → /var/log/suricata/eve.json        │
│                │                                                    │
│                ▼                                                    │
│         FILEBEAT → Logstash (port 5044)                             │
│                │                                                    │
│                ▼                                                    │
│         LOGSTASH PIPELINE (soc-pipeline.conf)                       │
│         ├── Enrichment: MITRE ATT&CK (technique_id, tactic)         │
│         ├── Enrichment: Pyramid of Pain (TTPs/Tools/IP)             │
│         ├── Enrichment: GeoIP (source.geo.location)                 │
│         ├── Normalisasi sig_id_str (array→scalar) *                 │
│         └── RESEARCH FILTER: SID 1000010/20/30 → tulis REAL-TIME    │
│                │             ke cti-research-alerts-iqbal            │
│                ▼                                                    │
│         ELASTICSEARCH                                               │
│         ├── cti-research-alerts-iqbal (62 baseline + live)          │
│         ├── cti-mttd-mttr-iqbal (30 record metrik)                  │
│         ├── cti-geoip-iqbal (data lokasi)                           │
│         └── cti-logs-iqbal-* (raw, ILM auto-delete 3 hari)          │
│                │                                                    │
│                ▼                                                    │
│         KIBANA DASHBOARD (auto-refresh 5s, Last 15 min)             │
│         └── 5 layer (lihat bagian 3)                                │
│                                                                     │
│   ══ JALUR RESPONS PARALEL (Wazuh HIDS, level ≥ 10) ══              │
│         WAZUH MANAGER                                               │
│         ├── [T2] Active Response: firewall-drop IP attacker (180s)  │
│         ├── custom-telegram → Laporan Insiden ke Telegram Bot       │
│         └── abuseipdb → enrichment reputasi IP (level ≥ 5)          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

* Catatan teknis: Filebeat + filter json Logstash melakukan double-parse
  sehingga signature_id menjadi array [id,id]. Normalisasi ruby mengubah
  ke scalar string agar kondisi filter research cocok.
```

**Keterangan Timeline:**
- **T0** = Timestamp serangan dimulai (epoch_ms)
- **T1** = Timestamp alert pertama muncul di Elasticsearch
- **T2** = Timestamp Wazuh Active Response dieksekusi
- **MTTD** = T1 − T0 (Mean Time to Detect)
- **MTTR** = T2 − T0 (Mean Time to Respond)

**Catatan arsitektur monitoring (penting untuk replikasi):**
Suricata berjalan di SOC dan memantau interface host-only `enp0s8`. Agar SOC
dapat melihat traffic antar-VM (attacker→victim) yang bukan ditujukan ke SOC,
adapter host-only SOC diset **promiscuous "allow-all"** (mode span/mirror).
Tanpa ini, switch host-only VirtualBox hanya meneruskan unicast ke tujuannya,
sehingga Suricata SOC tidak akan melihat serangan .110→.106.

---

## 2. Alur Kerja Pengukuran Metrik (Measurement Workflow)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    30 ITERASI PENGUJIAN TERKONTROL                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Untuk setiap iterasi i ∈ {1..30}:                                  │
│                                                                     │
│  1. Catat T0 = current_epoch_ms                                     │
│  2. Eksekusi serangan (nmap/hydra/nikto)                            │
│  3. Poll Elasticsearch setiap 500ms:                                │
│     → Tunggu alert SID yang sesuai muncul                           │
│  4. Catat T1 saat alert pertama terdeteksi                          │
│     → MTTD = T1 − T0 (dalam milidetik → konversi ke detik)         │
│  5. Poll Wazuh agent log setiap 500ms:                              │
│     → Tunggu event firewall-drop untuk IP attacker                  │
│  6. Catat T2 saat active response dieksekusi                        │
│     → MTTR = T2 − T0 (dalam milidetik → konversi ke detik)         │
│  7. Simpan ke cti-mttd-mttr-iqbal:                                  │
│     {iter, attack_type, mttd_s, mttr_s, T0_epoch, T1_epoch,        │
│      T2_epoch, src_ip, sid, status}                                 │
│  8. Delay 30 detik sebelum iterasi berikut                          │
│                                                                     │
│  Distribusi: 10 iterasi × Nmap + 10 × Hydra + 10 × Nikto = 30      │
│                                                                     │
│  HASIL (terverifikasi dari cti-mttd-mttr-iqbal, avg ES):           │
│  ┌──────────────┬──────────┬──────────┬────────────────┐           │
│  │ Skenario     │ Avg MTTD │ Avg MTTR │ Detection Rate │           │
│  ├──────────────┼──────────┼──────────┼────────────────┤           │
│  │ Nmap (T1046) │  2.50s   │  -       │ 10/10 (100%)   │           │
│  │ Hydra (T1110)│  1.60s   │  5.30s   │ 10/10 (100%)   │           │
│  │ Nikto (T1595)│  2.20s   │  3.10s   │ 10/10 (100%)   │           │
│  ├──────────────┼──────────┼──────────┼────────────────┤           │
│  │ KESELURUHAN  │  2.10s   │  4.20s   │ 30/30 (100%)   │           │
│  └──────────────┴──────────┴──────────┴────────────────┘           │
│                                                                     │
│  *MTTR Nmap = tidak diukur (Wazuh AR hanya aktif untuk Hydra)       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Alur Kerja Dashboard (Dashboard Intelligence Workflow)

```
┌─────────────────────────────────────────────────────────────────────┐
│              INFORMATION → INTELLIGENCE PIPELINE                    │
│              (Konsep Backbone R-09)                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Security Event                                                     │
│  └── Raw alert dari Suricata (SID, src_ip, dst_ip, proto, msg)     │
│                                                                     │
│       ▼ KONTEKSTUALISASI                                            │
│                                                                     │
│  Enriched Alert                                                     │
│  ├── MITRE ATT&CK: technique_id, tactic, technique_name            │
│  ├── Pyramid of Pain: layer classification (Tools/Network/Domain)   │
│  ├── GeoIP: country, city, longitude/latitude                       │
│  ├── AbuseIPDB: reputasi IP publik (confidence score)              │
│  └── Attack metadata: attack_type, scenario, risk_level            │
│                                                                     │
│       ▼ ACTIONABLE INTELLIGENCE                                     │
│                                                                     │
│  Dashboard 5 Layer                                                  │
│  ├── KPI: Total alert, unique attacker, detection rate              │
│  ├── Timeline: Urutan serangan per jam/menit                        │
│  ├── MITRE Heatmap: Distribusi teknik ATT&CK                        │
│  ├── MTTD/MTTR Chart: Kecepatan deteksi & respons per skenario     │
│  └── Attack Origin Map: Visualisasi geografis sumber serangan       │
│                                                                     │
│       ▼ OPERATIONAL DECISION SUPPORT                               │
│                                                                     │
│  Analis SOC                                                         │
│  ├── Identifikasi pola serangan (multi-stage: Nmap → Hydra)         │
│  ├── Prioritas respons berdasarkan Pyramid of Pain layer            │
│  ├── Evaluasi efektivitas deteksi (MTTD benchmark)                  │
│  └── Tindakan: escalate / close / investigate                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. Alur Kerja Alerting & Respons Otomatis (Automated Response Workflow)

```
┌─────────────────────────────────────────────────────────────────────┐
│         DUA JALUR RESPONS: KIBANA (analitik) + WAZUH (host)         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  JALUR A — KIBANA ALERTING (berbasis data Elasticsearch)           │
│  Kibana Alerting Rules (7 aktif):                                   │
│  ├── CTI — Port Scan Detected (Nmap)         [threshold: ≥5/5min]  │
│  ├── CTI — SSH Brute Force Detected (Hydra)  [threshold: ≥3/5min]  │
│  ├── CTI — Web Scan Detected (Nikto)         [threshold: ≥2/5min]  │
│  ├── CTI - Port Scan Detection (CRITICAL)    [composite rule]       │
│  ├── CTI - New Threat Actor Detected         [new src_ip]           │
│  ├── CTI - Failed Login Threshold            [login attempts]       │
│  └── CTI — Multi-Stage: Nmap → Hydra        [EQL sequence 10min]   │
│                 │ Webhook Action                                    │
│                 ▼                                                   │
│  SOAR Flask (port 5000)                                             │
│  └── Terima alert JSON research → Parse → Log → Escalate            │
│                 │                                                   │
│                 ▼                                                   │
│  Kibana Cases (auto-create, severity, tags CTI/MITRE)              │
│                                                                     │
│  ─────────────────────────────────────────────────────────────    │
│                                                                     │
│  JALUR B — WAZUH MANAGER (berbasis rule level, PARALEL)            │
│  Trigger: alert level ≥ 10 (mis. Hydra SSH brute force)            │
│  ├── (1) Active Response: firewall-drop IP 192.168.56.110 (180s)  │
│  ├── (2) custom-telegram integration:                              │
│  │       └─▶ Telegram Bot "NETWORK SECURITY INCIDENT REPORTING"    │
│  │           Laporan: ID, waktu, severity, ringkasan, IOC IP,      │
│  │           sistem terdampak, status, instruksi SOP Bab 5.8       │
│  └── (3) abuseipdb integration (level ≥ 5):                        │
│          └─▶ Query reputasi IP publik untuk enrichment CTI         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.1 Multi-Channel Incident Reporting (Telegram)

Wazuh Manager memiliki integrasi `custom-telegram` (`/var/ossec/integrations/custom-telegram`,
tersimpan redacted di `04-Wazuh/custom-telegram.py`) yang mengirim **Peringatan Keamanan**
ke channel Telegram. Dua prinsip desain sesuai kebutuhan operasional:

**(a) Hanya insiden berdampak & mendesak.** Filter `<level>10</level>` +
`<group>authentication_failures,web_attack,sql_injection,command_injection,privilege_escalation,attacks</group>`
memastikan HANYA serangan yang perlu tindak lanjut segera (mis. brute force SSH)
yang dikirim. Recon (port/web scan) dan noise korelasi (mis. false-positive
"Multiple IDS events" dari traffic host) TIDAK dikirim.

**(b) Bahasa non-teknis.** Jargon (IOC, level Wazuh, deskripsi rule berbahasa
Inggris, status SOP) diterjemahkan ke bahasa awam agar mudah dipahami penerima:

```
🚨 PERINGATAN KEAMANAN
────────────────────

Upaya Pembobolan Kata Sandi

🔴 Tingkat Bahaya : TINGGI
📍 Asal Serangan  : 192.168.56.110
🎯 Server Sasaran : victim-node
🕐 Waktu          : 02 Juli 2026, 13:17 WIB

💬 Penjelasan:
Ada pihak yang mencoba menebak kata sandi untuk masuk
ke sistem secara paksa dan berulang kali.

✅ Tindakan Sistem:
Alamat penyerang sudah otomatis diblokir.

👉 Mohon segera diperiksa oleh tim keamanan.
```

Script memetakan jenis serangan (berdasarkan `rule.groups`) ke penjelasan awam:
brute force → "Upaya Pembobolan Kata Sandi", sql_injection → "Upaya Pencurian
Data", web_attack → "Upaya Serangan ke Situs Web", dst. Waktu dikonversi ke WIB.

**Nilai untuk operasional SOC:** analis menerima notifikasi push real-time di
perangkat mobile — ringkas, actionable, dan dapat dipahami tanpa latar belakang
teknis mendalam — mendukung keputusan cepat di luar ruang kendali (out-of-band).

> Token bot & chat ID disimpan di server (disensor di repository).

---

## 5. Prosedur Demo Real-Time (Presentasi)

> **Status: TERVALIDASI end-to-end (2026-07-02).** Ketiga skenario (nmap, hydra,
> nikto) terbukti mengalir dari attacker → dashboard secara real-time, dan
> Wazuh→Telegram mengirim laporan insiden untuk Hydra (level 10).

### Persiapan (5 menit sebelum demo)

```bash
# 1. Pastikan 3 VM berjalan: SOC-SERVER, VICTIM-NODE, ATTACKER-NODE
# 2. SOC — pastikan promiscuous mode aktif (agar Suricata lihat traffic antar-VM):
#    VBoxManage controlvm SOC-SERVER nicpromisc2 allow-all
# 3. SOC — semua service running:
sudo systemctl status elasticsearch kibana logstash filebeat suricata wazuh-manager
# 4. Buka Kibana: http://192.168.56.10:5601
#    → Dashboard "cti-dashboard-final-v2", Last 15 min, auto-refresh 5s
# 5. Buka channel Telegram "NETWORK SECURITY INCIDENT REPORTING"
# 6. ATTACKER (192.168.56.110) — verifikasi IP: ip a show eth1  → 192.168.56.110
```

### Eksekusi Demo

```bash
# Di ATTACKER node (192.168.56.110), target = VICTIM (192.168.56.106):
bash /tmp/demo_attack.sh all
# Atau per skenario:
bash /tmp/demo_attack.sh _ nmap   # Port scan   → SID 1000010
bash /tmp/demo_attack.sh _ hydra  # SSH brute   → SID 1000020 (+ Telegram)
bash /tmp/demo_attack.sh _ nikto  # Web scan    → SID 1000030
```

### Yang Akan Terlihat (dalam detik)

| Waktu | Yang terjadi |
|-------|-------------|
| T+2-3s | Suricata deteksi; `cti-research-alerts-iqbal` bertambah |
| T+5s | Dashboard: KPI Total Alert naik, Timeline & MITRE update |
| T+8s | Pyramid of Pain & distribusi skenario update |
| T+10s | Attack Origin Map menampilkan titik attacker |
| T+15s | (Hydra) Wazuh firewall-drop .110 + **laporan masuk Telegram** |
| T+20s | Kibana Alerting → SOAR webhook; Cases diperbarui |

---

## 6. Kontribusi Ilmiah

### Novelty Metodologis

1. **Pengukuran MTTD/MTTR terkontrol**: Metodologi pengukuran waktu deteksi dan respons menggunakan timestamp granular (epoch_ms) pada lingkungan lab VirtualBox — dapat direplikasi.

2. **Pipeline CTI 4-tahap**: Formalisasi alur Security Event → Contextualization → Actionable Intelligence → Decision Support sebagai kerangka evaluasi dashboard keamanan.

3. **Multi-layer enrichment**: Kombinasi MITRE ATT&CK + Pyramid of Pain + GeoIP + AbuseIPDB dalam satu Logstash/Wazuh pipeline — pendekatan terintegrasi yang belum umum pada sistem ELK skala laboratorium.

4. **Deteksi multi-stage attack via EQL**: Rule sequence Nmap→Hydra dalam window 10 menit menggunakan Kibana Alerting sebagai alternatif Detection Engine (yang tidak tersedia di semua instalasi ELK).

5. **Validasi 30 iterasi terkontrol**: Design experiment dengan 3 skenario × 10 iterasi memberikan data kuantitatif yang dapat dibandingkan antar teknik serangan.

6. **Respons multi-kanal (dashboard + out-of-band)**: Kombinasi Kibana Cases (analitik terpusat) dan pelaporan Telegram real-time (notifikasi mobile) menunjukkan model SOC yang tidak bergantung pada pemantauan dashboard terus-menerus — relevan untuk keputusan operasional cepat.

7. **Deteksi real-time terverifikasi**: Pipeline enrichment membuktikan alur serangan→visualisasi dalam hitungan detik pada lingkungan lab, dengan penanganan kasus teknis (array signature_id, isolasi unicast host-only) yang terdokumentasi untuk replikasi.

---

## 7. Inventaris Komponen Sistem

| # | Komponen | Peran | Lokasi |
|---|----------|-------|--------|
| 1 | Suricata IDS | Deteksi jaringan (SID 1000010/20/30), app-layer HTTP | SOC (enp0s8, promiscuous) |
| 2 | Wazuh Manager | HIDS, Active Response, integrasi Telegram & AbuseIPDB | SOC |
| 3 | Filebeat | Kirim eve.json → Logstash | SOC |
| 4 | Logstash | Enrichment MITRE/Pyramid/GeoIP + research real-time output | SOC (soc-pipeline.conf) |
| 5 | Elasticsearch | Penyimpanan & agregasi | SOC :9200 |
| 6 | Kibana | Dashboard 5 layer, Alerting (7 rule), Cases | SOC :5601 |
| 7 | SOAR Flask | Webhook receiver alert research | SOC :5000 |
| 8 | Telegram Bot | Laporan insiden real-time (level ≥ 10) | Cloud (Bot API) |
| 9 | AbuseIPDB | Enrichment reputasi IP (level ≥ 5) | Cloud (API) |
| 10 | ILM Policy | Auto-delete cti-logs-iqbal-* (retensi 3 hari) | SOC |

---

## 8. Changelog Validasi Sistem (2026-07-02)

Perubahan/temuan selama validasi end-to-end sesi ini:

| Aspek | Sebelum | Sesudah (tervalidasi) |
|-------|---------|----------------------|
| Attacker VM | ATTACKER-NODE lama (disk hilang) | Kali 2026.1 di-rename ATTACKER-NODE, IP statis .110 (nmcli) |
| Suricata melihat traffic | Asumsi | Promiscuous "allow-all" di SOC → traffic .110→.106 terlihat |
| Pipeline research real-time | Belum teruji | Terverifikasi: nmap/hydra/nikto masuk cti-research-alerts-iqbal |
| Bug signature_id | Filter research tidak jalan (array) | Normalisasi ruby array→scalar → filter cocok |
| SOAR webhook | Untuk semua alert (pipeline stall) | Dibatasi ke alert research (cegah backlog) |
| Telegram reporting | Tidak terdokumentasi | Terdokumentasi + terverifikasi (laporan Hydra level 10) |
| AbuseIPDB | Tidak terdokumentasi | Terdokumentasi (enrichment level ≥ 5) |
| Storage | 12.8 juta docs raw (~7.5 GB) | Dibersihkan + ILM auto-delete 3 hari |

---

*Dokumen ini merupakan bagian dari penelitian skripsi Muhammad Iqbal Muhtaram (2241720265)*  
*Politeknik Negeri Malang — 2025/2026*
