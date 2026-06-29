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
| `02-ELK/` | Konfigurasi Logstash pipeline (`soc-pipeline.conf`, `99-mitre-normalize.conf`) dan skrip operasional ELK |
| `03-Suricata/` | Custom rules Suricata penelitian (SID 1000010/1000020/1000030) |
| `04-Wazuh/` | Konfigurasi Wazuh Manager (`ossec.conf`) dengan active response |
| `05-MITRE/` | Kamus pemetaan MITRE ATT&CK (`mitre-mapping.yml`) |
| `06-Dashboard/` | Export CTI Dashboard Kibana (NDJSON), v1–v5 |
| `07-Testing/` | Skrip dan data pengujian |
| `08-Screenshots/` | Tangkapan layar SOC dashboard |
| `09-Evidence/` | Bukti alert JSON (Suricata + Elasticsearch) untuk ketiga skenario |
| `10-Bab3/` | Metodologi penelitian (Bab III) |
| `11-Bab4/` | Implementasi dan pengujian (Bab IV) |
| `12-SOAR-Dashboard/` | Aplikasi SOAR Flask/SQLite (port 5000) |
| `14-Research/` | Dataset 30-iterasi (`datasets/iterations.csv`), protokol eksperimen, dan arsip |
| `15-Project-Governance/` | Governance penelitian |

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
