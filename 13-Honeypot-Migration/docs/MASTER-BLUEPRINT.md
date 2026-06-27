# 🏗️ MASTER BLUEPRINT: Sistem CTI Honeypot ELK Stack
# Pemetaan Lengkap Diagram Arsitektur → Implementasi Teknis

Dokumen ini memetakan **setiap komponen** pada diagram arsitektur 4-Layer ke dalam langkah implementasi konkret, file konfigurasi, dan *script* yang siap dieksekusi.

---

## Layer 1 — Ancaman Nyata dari Internet

| Komponen | Deskripsi | Cara Mendapatkan Data |
|---|---|---|
| **Botnet Scanner** | Sweep port 22/80 otomatis | Otomatis masuk begitu VPS A online |
| **SSH Brute Force** | Hydra, Medusa, dll. | Otomatis. Port 22 dibuka, bot akan menyerang |
| **Web Crawler** | Port 80/443 exploit | Nginx dipasang sebagai umpan |
| **APT Groups** | 50+ negara | GeoIP akan memetakan asal negara |

> **Tidak perlu aksi apapun.** Cukup buka port dan tunggu. Internet akan menyerang Anda.

---

## Layer 2 — VPS A: Honeypot / Victim Node

| Komponen | File Konfigurasi | Lokasi Deploy |
|---|---|---|
| **Suricata NIDS** | `vps-a-honeypot/setup_honeypot.sh` + `suricata-local.rules` | `/etc/suricata/` |
| **Wazuh HIDS** | `vps-a-honeypot/setup_honeypot.sh` (bagian Wazuh Agent) | `/var/ossec/etc/ossec.conf` |
| **Filebeat** | `vps-a-honeypot/setup_honeypot.sh` (bagian Filebeat) | `/etc/filebeat/filebeat.yml` |
| **Fail2ban** | `vps-a-honeypot/fail2ban-honeypot.conf` | `/etc/fail2ban/jail.d/` |

### Catatan Keamanan VPS A
- Port 22 (SSH) dan Port 80 (HTTP) **sengaja dibiarkan terbuka** sebagai umpan.
- SSH hanya mengizinkan **key-based authentication** (password dinonaktifkan).
- Fail2ban di-set dengan threshold **tinggi** (maxretry=10) agar serangan sempat terekam sebelum IP di-ban.

---

## Private VPN Layer — Tailscale / ZeroTier

| Komponen | File Panduan | Fungsi |
|---|---|---|
| **Tailscale VPN** | `vpn-setup/setup-tailscale.md` | Membuat tunnel terenkripsi antara VPS A ↔ VPS B |

Setelah VPN aktif, kedua VPS mendapat IP privat baru `100.x.x.x`. Semua komunikasi Filebeat → Logstash dan SSH SOAR → Honeypot melewati jalur ini.

---

## Layer 3 — VPS B: SOC Server

| Komponen | File Konfigurasi | Lokasi Deploy | Fungsi |
|---|---|---|---|
| **Elasticsearch** | `vps-b-soc-server/setup_soc_server.sh` | Port 9200 (lokal) | Indexing, ILM, Data Streams |
| **Logstash** | `vps-b-soc-server/soc-pipeline.conf` | `/etc/logstash/conf.d/` | Pipeline hybrid: ECS normalize, GeoIP, MITRE, Webhook |
| **Kibana** | `vps-b-soc-server/setup_soc_server.sh` | Port 5601 (lokal) | Dashboard, Canvas, Security, ML, Maps |
| **SOAR Dashboard** | `12-SOAR-Dashboard/app/soar_app.py` | Port 5000 (lokal) | Flask webhook + Active Response |
| **MITRE Mapping** | `vps-b-soc-server/mitre-name.yml` + `mitre-tactic.yml` | `/etc/logstash/dictionaries/` | SID → Technique ID/Name |
| **ILM Policy** | `vps-b-soc-server/ilm-policy.json` | Elasticsearch API | Rotasi indeks: 7d hot → 30d warm → 90d delete |
| **Elastic Trial** | `elk-exploration/elk-trial-exploration-plan.md` | Kibana Dev Tools | ML, Security App, Attack Discovery, Reports |

### Firewall VPS B (UFW)
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp                    # SSH dari laptop
sudo ufw allow in on tailscale0          # Semua port via VPN
# Port 5601 (Kibana) dan 5000 (SOAR) TIDAK dibuka ke publik
sudo ufw enable
```

---

## Layer 4 — Analyst (Laptop Lokal)

| Komponen | Cara Akses | Port Lokal |
|---|---|---|
| **Kibana Dashboard** | `ssh -L 5601:localhost:5601 user@VPS_B_IP` | `localhost:5601` |
| **SOAR Dashboard** | `ssh -L 5000:localhost:5000 user@VPS_B_IP` | `localhost:5000` |
| **Dev Tools / ES\|QL** | Via Kibana → Dev Tools | `localhost:5601/app/dev_tools` |

---

## Pilar 1 — Visualisasi Dashboard

| Fitur | File Panduan | Tujuan Penelitian |
|---|---|---|
| **Lens / Vega** | `elk-exploration/pilar1-visualisasi-dashboard.md` | Visualisasi TSVB time-series serangan |
| **Canvas** | `elk-exploration/pilar1-visualisasi-dashboard.md` | Presentasi infografik PDF-style |
| **Maps + GeoIP** | `elk-exploration/pilar1-visualisasi-dashboard.md` | Peta asal negara Top Threat Actors |
| **Reporting** | `elk-exploration/pilar1-visualisasi-dashboard.md` | Scheduled PDF export untuk Bab Hasil |

### Prasyarat GeoIP
Pipeline Logstash (`soc-pipeline.conf`) sudah dikonfigurasi dengan filter `geoip` pada field `source.ip`. Database GeoLite2-City sudah termasuk di Logstash secara default.

---

## Pilar 2 — Deteksi Anomali

| Fitur | File Panduan | Tujuan Penelitian |
|---|---|---|
| **ML Anomaly** | `elk-exploration/pilar2-deteksi-anomali.md` | Deteksi pola traffic abnormal (unsupervised) |
| **EQL** | `elk-exploration/pilar2-deteksi-anomali.md` | Deteksi multi-stage attack sequence |
| **Hybrid Detection** | `elk-exploration/pilar2-deteksi-anomali.md` | Suricata (NIDS) + Wazuh (HIDS) saling melengkapi |
| **Detection Rules** | `elk-exploration/pilar2-deteksi-anomali.md` | Query-based detection di Elastic Security |

### Alur Deteksi Hybrid
```
[Serangan SSH]
  ├── Suricata (NIDS): Mendeteksi pola traffic → SID 1000020
  └── Wazuh (HIDS): Mendeteksi failed login di auth.log → Rule 5710
      └── Keduanya masuk Elasticsearch → Korelasi di Kibana Security
```

---

## Pilar 3 — Monitoring MTTD dan MTTR

| Fitur | File Panduan | Tujuan Penelitian |
|---|---|---|
| **ES\|QL Query** | `elk-exploration/pilar3-monitoring-mttd-mttr.md` | Hitung MTTD/MTTR otomatis dari timestamp |
| **Alerting Rules** | `elk-exploration/pilar3-monitoring-mttd-mttr.md` | Trigger otomatis saat severity tinggi |
| **Cases** | `elk-exploration/pilar3-monitoring-mttd-mttr.md` | Tiket investigasi & workflow SOC |
| **SOAR Webhook** | `12-SOAR-Dashboard/app/soar_app.py` | One-click response: Block IP, Forensics |

### Alur Pengukuran MTTD
```
T0 = @timestamp di eve.json (saat Suricata mendeteksi)
T1 = @timestamp di Elasticsearch (saat log terindeks)
MTTD = T1 - T0

T2 = timestamp di SOAR incidents.db (saat analis klik tombol aksi)
MTTR = T2 - T1
```

---

## Pilar 4 — Pemetaan Pola Ancaman & Threat Intelligence

| Fitur | File Panduan | Tujuan Penelitian |
|---|---|---|
| **Threat Intel IOC** | `elk-exploration/pilar4-pemetaan-ancaman.md` | Ekstraksi IOC dari data honeypot |
| **Attack Discovery** | `elk-exploration/pilar4-pemetaan-ancaman.md` | Korelasi AI untuk narasi serangan |
| **MITRE ATT&CK** | `vps-b-soc-server/mitre-name.yml` + `mitre-tactic.yml` | Mapping SID → Technique ID |
| **ILM + Data Streams** | `vps-b-soc-server/ilm-policy.json` | Rotasi & retensi indeks otomatis |

---

## Roadmap Eksekusi 4 Minggu

### Minggu 1: Setup Infrastruktur
| Hari | Aktivitas | File Referensi |
|---|---|---|
| Senin | Sewa 2 VPS (DigitalOcean/Vultr/Alibaba) | - |
| Selasa | Setup Tailscale VPN di kedua VPS | `vpn-setup/setup-tailscale.md` |
| Rabu | Jalankan `setup_soc_server.sh` di VPS B | `vps-b-soc-server/setup_soc_server.sh` |
| Kamis | Jalankan `setup_honeypot.sh` di VPS A | `vps-a-honeypot/setup_honeypot.sh` |
| Jumat | Aktivasi Elastic Trial License | `elk-exploration/elk-trial-exploration-plan.md` |
| Sabtu-Minggu | Verifikasi aliran data end-to-end | Pipeline test manual |

### Minggu 2: Pengumpulan Data Honeypot (7 Hari)
| Aktivitas | Detail |
|---|---|
| **Honeypot Live** | Biarkan VPS A diserang selama 7 hari penuh |
| **ML Anomaly Job** | Buat job ML untuk mendeteksi lonjakan trafik | 
| **Detection Rules** | Buat 3+ detection rules di Elastic Security |
| **Monitoring** | Pantau Kibana dashboard setiap hari, catat temuan |

### Minggu 3: SOAR, Alerting, dan Analisis
| Aktivitas | Detail |
|---|---|
| **SOAR + Alerting** | Aktifkan webhook ke Flask SOAR, test respons |
| **EQL + ES\|QL** | Jalankan query deteksi multi-stage & hitung MTTD |
| **Threat Intel IOC** | Ekstraksi IP/domain berbahaya, buat feed IOC |
| **Cases** | Buat tiket investigasi untuk serangan terbesar |

### Minggu 4: Dokumentasi & Finalisasi
| Aktivitas | Detail |
|---|---|
| **Canvas + Maps** | Buat infografik Canvas dan peta GeoIP |
| **PDF Reporting** | Export dashboard ke PDF terjadwal |
| **Modul Penelitian** | Tulis Bab 4 (Hasil) dengan screenshot & data |
| **Shutdown** | Matikan VPS A (Honeypot), backup data VPS B |

---

## Target Output Penelitian
| Metrik | Target |
|---|---|
| **Serangan Terdeteksi** | 10.000+ serangan nyata |
| **Asal Negara** | 50+ negara (via GeoIP) |
| **MTTD Terukur** | < 5 detik (pipeline otomatis) |
| **MTTR Terukur** | < 30 detik (SOAR one-click) |
| **Dashboard** | 5+ visualisasi (Lens, Canvas, Maps, TSVB, Table) |
| **Detection Rules** | 3+ aturan deteksi aktif |
| **ML Jobs** | 1+ anomaly detection job |
| **IOC Feed** | 100+ indikator ancaman |

---

## Daftar Lengkap File yang Harus Dibuat

```
13-Honeypot-Migration/
├── docs/
│   ├── architecture-honeypot.md          ✅ Sudah ada
│   └── MASTER-BLUEPRINT.md              ✅ File ini
│
├── vpn-setup/
│   └── setup-tailscale.md               ✅ Sudah ada
│
├── vps-a-honeypot/
│   ├── setup_honeypot.sh                🔄 Diperbarui (+ Wazuh Agent)
│   ├── suricata-local.rules             🆕 Custom Suricata rules
│   └── fail2ban-honeypot.conf           🆕 Konfigurasi Fail2ban
│
├── vps-b-soc-server/
│   ├── setup_soc_server.sh              🆕 Script setup ELK + Wazuh Manager
│   ├── setup_soc_server.md              ✅ Sudah ada (panduan manual)
│   ├── soc-pipeline.conf                🆕 Pipeline Logstash lengkap
│   ├── mitre-name.yml                   🆕 Kamus MITRE nama teknik
│   ├── mitre-tactic.yml                 🆕 Kamus MITRE taktik
│   └── ilm-policy.json                  🆕 ILM retention policy
│
├── elk-exploration/
│   ├── elk-trial-exploration-plan.md    ✅ Sudah ada (diperbarui)
│   ├── pilar1-visualisasi-dashboard.md  🆕 Panduan Lens/Canvas/Maps
│   ├── pilar2-deteksi-anomali.md        🆕 Panduan ML/EQL/Detection Rules
│   ├── pilar3-monitoring-mttd-mttr.md   🆕 Panduan ES|QL/Alerting/Cases
│   └── pilar4-pemetaan-ancaman.md       🆕 Panduan Threat Intel/IOC/ILM
│
12-SOAR-Dashboard/
├── app/
│   ├── soar_app.py                      ✅ Sudah ada (env-based config)
│   ├── .env.example                     ✅ Sudah ada
│   ├── templates/index.html             ✅ Sudah ada
│   ├── requirements.txt                 ✅ Sudah ada
│   ├── setup_victim_node.sh             ✅ Sudah ada
│   └── README.md                        ✅ Sudah ada
└── soc-pipeline-webhook-output.conf     ✅ Sudah ada (terintegrasi ke pipeline baru)
```

Legenda: ✅ = Sudah ada | 🆕 = Baru dibuat | 🔄 = Diperbarui
