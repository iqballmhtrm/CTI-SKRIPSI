# GROUND TRUTH SNAPSHOT — 2026-06-21

**Tujuan:** Membekukan (freeze) kondisi sistem CTI-Skripsi berdasarkan evidence runtime SEBELUM perubahan apapun dilakukan.
**Status Dokumen:** FROZEN / IMMUTABLE REFERENCE
**Prinsip:** Evidence-based only. Data runtime adalah satu-satunya sumber kebenaran.
**RULE:** READ ONLY — belum ada backup, modify, atau reset yang dilakukan.

---

## METADATA SNAPSHOT

| Atribut | Nilai |
|---------|-------|
| Tanggal pembekuan | 21 Juni 2026 |
| Sumber data | Runtime query `incidents.db` (SOC Server 192.168.56.10) |
| Tool | `minimal_ground_truth.py` (Python sqlite3, READ ONLY) |
| Database path | `/home/iqbal/soar-dashboard/app/incidents.db` |
| Database size | 66 MB |
| API response size | 251,237,180 bytes (≈251 MB) |
| Rentang waktu data | 2026-06-20T12:32:20Z s.d. 2026-06-20T21:00:43Z (≈8.5 jam) |
| Metode | Query langsung + 100 sample acak |

---

## 1. SNAPSHOT RUNTIME — TOTAL INCIDENT

```
Total Incident: 540,889
```

**Catatan:** Membantah klaim lama "~9,020 incident". Angka runtime aktual = **540,889**.

---

## 2. STATUS DISTRIBUTION

| Status | Count | Persentase |
|--------|-------|------------|
| New | 540,868 | 99.996% |
| Resolved | 12 | 0.002% |
| False Positive | 6 | 0.001% |
| In Progress | 4 | 0.001% |

**Implikasi:** Hampir seluruh incident belum ditangani. Data MTTR runtime hanya berbasis 12 record Resolved (tidak signifikan secara statistik).

---

## 3. MITRE DISTRIBUTION

| MITRE Status | Count | Persentase |
|--------------|-------|------------|
| Unmapped | 532,225 | 98.40% |
| Mapped | 8,679 | 1.60% |

**Verdict MITRE:** **FAIL** — Coverage hanya 1.60%. Pilar penelitian "pemetaan ancaman MITRE ATT&CK" tidak terbukti efektif pada dataset ini. Membantah klaim lama "1 mapped : 151 unmapped".

---

## 4. TOP ATTACK TYPE

| Rank | Attack Type | Count | Persentase |
|------|-------------|-------|------------|
| 1 | IDS event. | 267,542 | 49.46% |
| 2 | SURICATA STREAM ESTABLISHED packet out of window | 104,437 | 19.31% |
| 3 | SURICATA STREAM Packet with invalid ack | 79,745 | 14.74% |
| 4 | SURICATA STREAM ESTABLISHED invalid ack | 79,729 | 14.74% |
| 5 | syslog: User authentication failure. | 8,662 | 1.60% |
| 6 | Host Blocked by firewall-drop Active Response | 139 | 0.03% |
| 7 | Successful login during weekend. | 118 | 0.02% |
| 8 | Host Unblocked by firewall-drop Active Response | 91 | 0.02% |
| 9 | PAM: Login session closed. | 82 | 0.02% |
| 10 | Multiple IDS events from same source ip. | 79 | 0.01% |
| 14 | CTI-LAB SSH Connection Attempt | 26 | 0.00% |
| 20 | CTI-LAB SSH Brute Force Attempt | 8 | 0.00% |

**Catatan kritis:** Top 4 (98.25%) adalah generic IDS + Suricata STREAM noise. Event riset eksplisit "CTI-LAB" total hanya **34 incident**.

---

## 5. SOURCE IP DISTRIBUTION

| Rank | Source IP | Count | Persentase | Identifikasi |
|------|-----------|-------|------------|--------------|
| 1 | 192.168.56.1 | 317,498 | 58.70% | Host/gateway VirtualBox |
| 2 | 192.168.56.10 | 214,426 | 39.64% | SOC Server (self-traffic) |
| 3 | Unknown | 8,973 | 1.66% | Parsing gagal |
| 4 | 10.0.2.2 | 18 | 0.00% | NAT VirtualBox |
| 5 | 0.0.0.0 | 2 | 0.00% | Invalid |
| 6 | 192.168.56.106 | 1 | 0.00% | Victim node |

**Temuan:** Attacker node **192.168.56.105 TIDAK MUNCUL**. Victim hanya 1 incident. Traffic didominasi internal SOC + gateway, bukan skenario serangan.

---

## 6. DATASET VERDICT

| Kriteria | Target | Aktual | Status |
|----------|--------|--------|--------|
| Research Event Dominant | ≥80% | 0% | ❌ FAIL |
| MITRE Mapping Complete | ≥80% | 1.60% | ❌ FAIL |
| Operational Noise Low | ≤20% | 46% | ❌ FAIL |

### VERDICT: **DATASET TIDAK LAYAK UNTUK PENELITIAN**

Klasifikasi 100 sample acak: Research 0% · Operational Noise 46% · System 0% · Unknown 54%.

---

## 7. STATUS KOMPONEN (FROZEN)

| Status | Komponen |
|--------|----------|
| **PASS** | ELK Stack, Suricata, MTTD, Bab 3, Elasticsearch core |
| **PARTIAL** | Kibana, Logstash, Filebeat, Wazuh, Threat Intelligence, SOAR Backend, MTTR, Bab 4, Defense Readiness |
| **FAIL** | MITRE Mapping, SOAR Frontend, Dataset Penelitian |
| **BELUM TERBUKTI** | Pyramid of Pain, Threat Scoring, ES health/size, Kibana dashboard runtime, Filebeat shipping |
| **NOT STARTED** | Bab 5 |

---

## 8. PROJECT PROGRESS

```
Engineering : ██████████████░░░░░░  70%
Research    : ███████░░░░░░░░░░░░░░  35%
Academic    : █████████░░░░░░░░░░░░  45%
----------------------------------------
OVERALL     : ██████████░░░░░░░░░░  50%
```

---

## 9. CRITICAL PATH

```
MITRE Enrichment (FAIL 1.60%)
        +
Dataset (FAIL 0% research)
        ↓
Bab 4 (PARTIAL, validitas terancam)
        ↓
Bab 5 (NOT STARTED)
        ↓
Defense Readiness (PARTIAL)
        ↓
SIDANG (RISIKO TINGGI)
```

Kegagalan di MITRE + Dataset menjalar ke seluruh rantai akademik.

---

## 10. TOP ISSUES (RINGKAS)

### CRITICAL
1. Dataset tidak layak (0% research event)
2. MITRE coverage 1.60% (532,225 unmapped)
3. Bab 5 NOT STARTED
4. Tidak ada 30 iterasi terkontrol (hanya 34 event CTI-LAB)
5. Attacker node 192.168.56.105 absen dari dataset

### HIGH
6. SOAR Frontend stuck (251 MB JSON, no pagination)
7. 46% dataset operational noise
8. MTTR runtime hanya 12 Resolved
9. CSV raw MTTD/MTTR hilang dari repo
10. Pyramid of Pain tidak terbukti runtime

### MEDIUM
11. Threat Scoring belum diverifikasi runtime
12. ES health/size belum di-query
13. SOAR jalan manual (nohup), bukan systemd
14. "IDS event." generic 49.46% tanpa klasifikasi

---

## 11. OPEN DECISIONS (BELUM DIPUTUSKAN)

| # | Keputusan | Opsi | Status |
|---|-----------|------|--------|
| D1 | Penanganan dataset | Selective Cleanup vs Full Rebuild 30 iterasi | OPEN |
| D2 | Waktu reset database | Setelah backup tervalidasi 13/13 | OPEN (menunggu D-backup) |
| D3 | Perbaikan MITRE pipeline | Sebelum atau sesudah rebuild dataset | OPEN |
| D4 | Pisah Operational vs Research dataset | Tabel/index terpisah | OPEN |
| D5 | Fix SOAR frontend | Pagination/limit endpoint | OPEN |
| D6 | Jadwal sidang | Tunda hingga dataset layak | DIREKOMENDASIKAN DITUNDA |

**Catatan:** Tidak ada satupun keputusan di atas yang boleh dieksekusi sebelum backup tervalidasi.

---

## 12. PRIORITAS BERIKUTNYA

| Urutan | Aksi | Prasyarat |
|--------|------|-----------|
| 1 | Eksekusi backup `incidents.db` (online backup) | EVIDENCE_PRESERVATION_PLAN |
| 2 | Validasi backup 13/13 checklist | backup selesai |
| 3 | Audit root-cause MITRE enrichment pipeline | backup valid |
| 4 | Validasi Threat Scoring & Pyramid of Pain runtime | akses ES/Kibana |
| 5 | Audit SOAR data flow (fix pagination) | backup valid |
| 6 | Putuskan D1: Selective Cleanup vs Full Rebuild | hasil audit MITRE |

---

## PERNYATAAN PEMBEKUAN

Dokumen ini adalah **referensi kebenaran (ground truth) yang dibekukan** per 21 Juni 2026. Setiap perubahan sistem setelah tanggal ini WAJIB dibandingkan terhadap snapshot ini.

- **Total incident saat freeze:** 540,889
- **MITRE coverage saat freeze:** 1.60%
- **Verdict dataset saat freeze:** TIDAK LAYAK
- **Tindakan dilakukan saat freeze:** TIDAK ADA (READ ONLY murni)

**Auditor:** Kiro (Security Architect / CTI Analyst / SOC Engineer / Research Auditor / Thesis Reviewer)
**Status:** FROZEN — Sistem siap untuk fase backup setelah dokumen ini disahkan.
