# Alur Kerja Ilmiah — CTI Dashboard ELK Stack
## Kontribusi Metodologis Penelitian

**Peneliti:** Muhammad Iqbal Muhtaram (2241720265)  
**Judul:** Optimisasi Visualisasi Data Log dan Alert Siber Melalui Dashboard ELK Stack untuk Mendukung Pengambilan Keputusan Operasional CTI  
**Institusi:** Politeknik Negeri Malang

---

## 1. Alur Kerja Deteksi Ancaman (Threat Detection Workflow)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    THREAT DETECTION PIPELINE                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ATTACKER (192.168.56.110)                                          │
│      │                                                              │
│      │  [T0] Serangan dimulai                                       │
│      │  ┌──────────────┐                                            │
│      ├─▶│ Nmap Scan    │ → SID 1000010 → MITRE T1046               │
│      ├─▶│ Hydra SSH BF │ → SID 1000020 → MITRE T1110.001           │
│      └─▶│ Nikto Web    │ → SID 1000030 → MITRE T1595.002           │
│         └──────┬───────┘                                            │
│                │                                                    │
│         VICTIM (192.168.56.106) — Traffic dimonitor                 │
│                │                                                    │
│                ▼                                                    │
│         SURICATA IDS                                                │
│         ├── Deteksi paket mencurigakan                              │
│         ├── Match custom.rules (SID 1000010/20/30)                  │
│         └── [T1] Alert di-raise → Log ke /var/log/suricata/         │
│                │                                                    │
│                ▼                                                    │
│         FILEBEAT                                                    │
│         └── Parse & kirim ke Logstash                               │
│                │                                                    │
│                ▼                                                    │
│         LOGSTASH PIPELINE                                           │
│         ├── Enrichment: MITRE ATT&CK mapping (technique_id, tactic) │
│         ├── Enrichment: Pyramid of Pain (Tools/Network)             │
│         ├── Enrichment: GeoIP (source.geo.location)                 │
│         └── Index: cti-logs-iqbal-* / cti-research-alerts-iqbal    │
│                │                                                    │
│                ▼                                                    │
│         ELASTICSEARCH                                               │
│         ├── cti-research-alerts-iqbal (62 alert penelitian)         │
│         ├── cti-mttd-mttr-iqbal (30 record metrik)                  │
│         └── cti-geoip-iqbal (data lokasi)                           │
│                │                                                    │
│                ▼                                                    │
│         KIBANA DASHBOARD                                            │
│         ├── Layer 1: Gambaran Umum (KPI, distribusi skenario)       │
│         ├── Layer 2: Timeline (urutan serangan)                     │
│         ├── Layer 3: CTI Analysis (MITRE, Pyramid of Pain)          │
│         ├── Layer 4: MTTD/MTTR per skenario                         │
│         └── Layer 5: Attack Origin Map (peta Indonesia)             │
│                │                                                    │
│                ▼                                                    │
│         WAZUH ACTIVE RESPONSE                                       │
│         ├── [T2] Auto-block IP attacker via firewall-drop           │
│         ├── Timeout: 180 detik                                       │
│         └── Trigger: Level ≥ 10 (SSH brute force)                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Keterangan Timeline:**
- **T0** = Timestamp serangan dimulai (epoch_ms)
- **T1** = Timestamp alert pertama muncul di Elasticsearch
- **T2** = Timestamp Wazuh Active Response dieksekusi
- **MTTD** = T1 − T0 (Mean Time to Detect)
- **MTTR** = T2 − T0 (Mean Time to Respond)

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
│  HASIL:                                                             │
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
│               KIBANA ALERTING → SOAR → CASES PIPELINE               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Kibana Alerting Rules (7 aktif):                                   │
│  ├── CTI — Port Scan Detected (Nmap)         [threshold: ≥5/5min]  │
│  ├── CTI — SSH Brute Force Detected (Hydra)  [threshold: ≥3/5min]  │
│  ├── CTI — Web Scan Detected (Nikto)         [threshold: ≥2/5min]  │
│  ├── CTI - Port Scan Detection (CRITICAL)    [composite rule]       │
│  ├── CTI - New Threat Actor Detected         [new src_ip]           │
│  ├── CTI - Failed Login Threshold            [login attempts]       │
│  └── CTI — Multi-Stage: Nmap → Hydra        [EQL sequence 10min]   │
│                 │                                                   │
│                 ▼ Webhook Action                                    │
│                                                                     │
│  SOAR Flask (port 5000)                                             │
│  └── Terima alert JSON → Parse → Log → Opsional escalate           │
│                 │                                                   │
│                 ▼                                                   │
│                                                                     │
│  Kibana Cases                                                       │
│  ├── Auto-create case per rule trigger                              │
│  ├── Severity: critical/high/medium                                 │
│  └── Tags: CTI, MITRE teknik, skenario                             │
│                                                                     │
│  Wazuh Active Response (PARALLEL):                                  │
│  ├── Trigger: rule level ≥ 10 (hydra brute force)                  │
│  ├── Action: firewall-drop pada IP 192.168.56.110                  │
│  └── Timeout: 180 detik → auto-unblock                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 5. Prosedur Demo Real-Time (Presentasi)

### Persiapan (5 menit sebelum demo)

```bash
# 1. SOC server (192.168.56.10) — pastikan semua services running
sudo systemctl status elasticsearch kibana logstash filebeat suricata wazuh-manager

# 2. Buka Kibana di browser
# http://192.168.56.10:5601
# → Dashboard: "cti-dashboard-final-v2"
# → Time filter: Last 15 minutes
# → Auto-refresh: 5 seconds (sudah dikonfigurasi)

# 3. Buka SOAR Dashboard (opsional)
# http://192.168.56.10:5000

# 4. ATTACKER VM (192.168.56.110) — start dan login
```

### Eksekusi Demo

```bash
# Di ATTACKER node (192.168.56.110):
bash /tmp/demo_attack.sh all
# Atau per skenario:
bash /tmp/demo_attack.sh _ nmap   # Hanya Nmap
bash /tmp/demo_attack.sh _ hydra  # Hanya Hydra
bash /tmp/demo_attack.sh _ nikto  # Hanya Nikto
```

### Yang Akan Terlihat di Dashboard (dalam detik)

| Waktu | Panel yang Update |
|-------|------------------|
| T+2-3s | KPI "Total Alerts" naik, Timeline muncul event baru |
| T+5s | MITRE heatmap bar bertambah, Pyramid of Pain update |
| T+10s | Attack Origin Map menampilkan titik IP attacker |
| T+15s | Kibana Alerting rule triggered → SOAR webhook |
| T+20s | Cases baru muncul di Kibana Cases |

---

## 6. Kontribusi Ilmiah

### Novelty Metodologis

1. **Pengukuran MTTD/MTTR terkontrol**: Metodologi pengukuran waktu deteksi dan respons menggunakan timestamp granular (epoch_ms) pada lingkungan lab VirtualBox — dapat direplikasi.

2. **Pipeline CTI 4-tahap**: Formalisasi alur Security Event → Contextualization → Actionable Intelligence → Decision Support sebagai kerangka evaluasi dashboard keamanan.

3. **Multi-layer enrichment**: Kombinasi MITRE ATT&CK + Pyramid of Pain + GeoIP dalam satu Logstash pipeline — pendekatan terintegrasi yang belum umum pada sistem ELK skala laboratorium.

4. **Deteksi multi-stage attack via EQL**: Rule sequence Nmap→Hydra dalam window 10 menit menggunakan Kibana Alerting sebagai alternatif Detection Engine (yang tidak tersedia di semua instalasi ELK).

5. **Validasi 30 iterasi terkontrol**: Design experiment dengan 3 skenario × 10 iterasi memberikan data kuantitatif yang dapat dibandingkan antar teknik serangan.

---

*Dokumen ini merupakan bagian dari penelitian skripsi Muhammad Iqbal Muhtaram (2241720265)*  
*Politeknik Negeri Malang — 2025/2026*
