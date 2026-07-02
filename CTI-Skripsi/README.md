# CTI-Skripsi

Repositori artefak implementasi penelitian skripsi:
**"Optimisasi Visualisasi Data Log dan Alert Siber Melalui Dashboard ELK Stack
untuk Mendukung Pengambilan Keputusan Operasional Cyber Threat Intelligence"**

Muhammad Iqbal Muhtaram — NIM 2241720265 — Teknik Informatika, Polinema

---

## Topologi Lab

| Node | IP | Peran |
|------|----|-------|
| SOC-SERVER | 192.168.56.10 | Elasticsearch, Logstash, Kibana, Wazuh Manager, SOAR |
| VICTIM-NODE | 192.168.56.106 | Suricata 8.0.3 (NIDS), Wazuh Agent (HIDS) |
| ATTACKER-NODE | 192.168.56.110 | Nmap, Hydra, Nikto |

---

## Struktur Repositori

| Direktori | Isi |
|-----------|-----|
| `01-Topologi/` | Diagram topologi penelitian |
| `02-ELK/` | Konfigurasi ELK: `soc-pipeline.conf` (Logstash), `elasticsearch.yml`, `kibana.yml`, `filebeat.yml`, `99-mitre-normalize.conf` |
| `03-Suricata/` | Custom rules Suricata penelitian (SID 1000010/1000020/1000030) |
| `04-Wazuh/` | Konfigurasi Wazuh Manager (`ossec.conf`) + integrasi Telegram (`custom-telegram.py`, token disensor) |
| `05-MITRE/` | Kamus pemetaan MITRE ATT&CK (`mitre-mapping.yml`) + rules ber-metadata |
| `06-Dashboard/` | Export CTI Dashboard Kibana final (`dashboard-final-v9.ndjson`, 27 objek) + dokumen desain |
| `07-Testing/` | `demo_attack.sh` (demo real-time 3 skenario), skrip iterasi MTTD, hasil validasi Nmap/Hydra/Nikto |
| `08-Screenshots/` | Tangkapan layar SOC, dashboard, ELK, Wazuh |
| `09-Evidence/` | Bukti alert JSON (Suricata + Elasticsearch) untuk ketiga skenario + laporan validasi |
| `10-Bab3/` | Metodologi penelitian (Bab III) |
| `11-Bab4/` | Implementasi dan pengujian (Bab IV) |
| `12-SOAR-Dashboard/` | Aplikasi SOAR Flask/SQLite (port 5000) |
| `13-Audit/` | Laporan audit ground-truth, klasifikasi sumber bukti, komposisi dataset |
| `14-Research/` | `WORKFLOW_ILMIAH.md` (alur kerja & kontribusi), `TRACEABILITY_MATRIX.md`, dataset 30-iterasi, protokol eksperimen |
| `15-Project-Governance/` | Governance penelitian (R-00…R-14, konstitusi, keputusan) |

> **Catatan:** File VM VirtualBox (`SOC-SERVER/`, `*.vdi`, snapshot, log) sengaja
> di-*exclude* dari repositori via `.gitignore` karena berukuran puluhan GB.

---

## Komponen Sistem

| Komponen | Peran |
|----------|-------|
| Suricata IDS | Deteksi jaringan (SID 1000010/20/30), app-layer HTTP |
| Wazuh Manager | HIDS + Active Response (firewall-drop) + integrasi Telegram & AbuseIPDB |
| Filebeat → Logstash | Pengiriman & enrichment (MITRE ATT&CK, Pyramid of Pain, GeoIP) |
| Elasticsearch | Penyimpanan & agregasi; ILM auto-delete `cti-logs-iqbal-*` (retensi 3 hari) |
| Kibana | Dashboard 5 layer, Alerting (7 rule), Cases |
| SOAR Flask | Webhook receiver alert (port 5000) |
| Telegram Bot | Peringatan insiden real-time (hanya serangan berdampak, bahasa awam) |

---

## Skenario Serangan yang Divalidasi

| # | Skenario | Alat | SID Suricata | Teknik MITRE |
|---|----------|------|--------------|--------------|
| 1 | Port Scan | Nmap | 1000010 (rev:1) | T1046 — Network Service Scanning |
| 2 | SSH Brute Force | Hydra | 1000020 (rev:2) | T1110.001 — Brute Force: Password Guessing |
| 3 | Web Vulnerability Scan | Nikto | 1000030 (rev:3) | T1595.002 — Active Reconnaissance: Vulnerability Scanning |

---

## Metrik Utama (30 Iterasi Terkontrol, 2026-06-24)

| Skenario | MTTD rata² | MTTR rata² | Mitigasi Otomatis |
|----------|-----------|-----------|------------------|
| Nmap | 2,5 detik | — | Tidak (recon jaringan) |
| Hydra | 1,6 detik | 5,3 detik | Wazuh rule 5763 → firewall-drop |
| Nikto | 2,2 detik | 3,1 detik | Wazuh rule 31151 → firewall-drop |

Deteksi 100% (30/30 iterasi). Data: `14-Research/datasets/iterations.csv`.
