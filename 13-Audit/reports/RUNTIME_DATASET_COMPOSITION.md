# LAPORAN KOMPOSISI DATASET RUNTIME

**Tanggal Audit**: 20 Juni 2026, 21:00 WIB  
**Database**: `/home/iqbal/soar-dashboard/app/incidents.db`  
**Metode**: Query langsung ke database SOAR (READ ONLY)  
**Status**: COMPLETED

---

## RINGKASAN EKSEKUTIF

**VERDICT: TIDAK LAYAK UNTUK PENELITIAN**

Dataset operational SOAR mengandung **540,889 incident** yang didominasi oleh **operational noise** dan **system events**. Dataset ini **TIDAK MEMENUHI** standar penelitian akademik karena:

1. **0% Research Event** - Tidak ada data serangan riset (Nmap, Hydra, Nikto) dalam sample
2. **1.60% MITRE Mapped** - Hanya 8,679 dari 540,889 incident yang dipetakan ke MITRE ATT&CK
3. **46% Operational Noise** - Hampir setengah dataset adalah Suricata stream events

---

## A. TOTAL EVENTS

```
Total Incident: 540,889
```

**Analisis**: Database berisi lebih dari setengah juta incident, jauh melebihi estimasi awal (~9,020 dari master context). Ukuran 66 MB database dan 251 MB API response sudah dikonfirmasi.

---

## B. DISTRIBUSI STATUS

| Status          | Count     | Persentase |
|-----------------|-----------|------------|
| New             | 540,868   | 100.00%    |
| Resolved        | 12        | 0.00%      |
| False Positive  | 6         | 0.00%      |
| In Progress     | 4         | 0.00%      |

**Analisis**: 
- Hampir semua incident berstatus "New" (belum ditangani)
- Hanya 22 incident yang pernah ditangani (Resolved + False Positive + In Progress)
- **IMPLIKASI PENELITIAN**: Data MTTR (Mean Time to Respond) hampir tidak ada karena hanya 12 incident Resolved

---

## C. DISTRIBUSI MITRE ATT&CK

| MITRE Status | Count     | Persentase |
|--------------|-----------|------------|
| Unmapped     | 532,225   | 98.40%     |
| Mapped       | 8,679     | 1.60%      |

**Analisis**:
- **98.40% incident TIDAK MEMILIKI MITRE mapping**
- Hanya 8,679 incident (1.60%) yang berhasil dipetakan ke framework MITRE ATT&CK
- **ROOT CAUSE**: Logstash pipeline MITRE enrichment tidak berfungsi optimal atau dictionary mapping tidak lengkap

**IMPLIKASI PENELITIAN**: 
- Dashboard CTI yang menampilkan MITRE technique tidak representatif
- Analisis Cyber Threat Intelligence berbasis MITRE ATT&CK tidak valid dengan data ini

---

## D. TOP 20 ATTACK TYPE

| Rank | Attack Type                                       | Count     | Persentase |
|------|--------------------------------------------------|-----------|------------|
| 1    | IDS event.                                       | 267,542   | 49.46%     |
| 2    | SURICATA STREAM ESTABLISHED packet out of window| 104,437   | 19.31%     |
| 3    | SURICATA STREAM Packet with invalid ack          | 79,745    | 14.74%     |
| 4    | SURICATA STREAM ESTABLISHED invalid ack          | 79,729    | 14.74%     |
| 5    | syslog: User authentication failure.             | 8,662     | 1.60%      |
| 6    | Host Blocked by firewall-drop Active Response    | 139       | 0.03%      |
| 7    | Successful login during weekend.                 | 118       | 0.02%      |
| 8    | Host Unblocked by firewall-drop Active Response  | 91        | 0.02%      |
| 9    | PAM: Login session closed.                       | 82        | 0.02%      |
| 10   | Multiple IDS events from same source ip.         | 79        | 0.01%      |

**Analisis**:
- **Top 4 attack type (98.25% dari total)** adalah:
  - Generic "IDS event" (49.46%)
  - Suricata TCP stream events (48.79% combined)
- **TIDAK ADA** attack type spesifik untuk:
  - Nmap reconnaissance
  - Hydra brute force
  - Nikto web vulnerability scan
- Attack type "CTI-LAB SSH Connection Attempt" (rank 14) dan "CTI-LAB SSH Brute Force Attempt" (rank 20) SANGAT SEDIKIT (26 + 8 = 34 incident)

**KESIMPULAN**: Dataset didominasi oleh **generic IDS alerts** dan **TCP stream noise**, bukan serangan riset yang dikendalikan.

---

## E. TOP 20 SOURCE IP

| Rank | Source IP      | Count     | Persentase |
|------|----------------|-----------|------------|
| 1    | 192.168.56.1   | 317,498   | 58.70%     |
| 2    | 192.168.56.10  | 214,426   | 39.64%     |
| 3    | Unknown        | 8,973     | 1.66%      |
| 4    | 10.0.2.2       | 18        | 0.00%      |
| 5    | 0.0.0.0        | 2         | 0.00%      |
| 6    | 192.168.56.106 | 1         | 0.00%      |

**Analisis**:
- **192.168.56.1** (58.70%): Kemungkinan host Windows (gateway VirtualBox)
- **192.168.56.10** (39.64%): SOC Server (self-traffic atau loopback)
- **192.168.56.106** (0.00%): Victim node - HANYA 1 INCIDENT
- **Attacker node IP TIDAK MUNCUL dalam top 20**

**IMPLIKASI PENELITIAN**:
- Traffic didominasi oleh komunikasi internal SOC dan gateway
- Serangan dari attacker node **TIDAK TERDETEKSI** atau **SANGAT SEDIKIT**
- Dataset tidak merepresentasikan skenario serangan eksternal

---

## F. RENTANG WAKTU DATA

```
Earliest: 2026-06-20 12:32:20 UTC
Latest  : 2026-06-20 21:00:43 UTC
```

**Durasi**: ~8.5 jam (20 Juni 2026, siang hingga malam)

**Analisis**:
- Dataset dikumpulkan dalam **1 hari operasional** (bukan 30 iterasi terkontrol)
- Data operational, bukan research dataset yang direncanakan
- Tidak ada bukti controlled testing protocol (10 Nmap + 10 Hydra + 10 Nikto)

---

## G. KLASIFIKASI 100 SAMPLE ACAK

| Kategori            | Count | Persentase |
|---------------------|-------|------------|
| Research Event      | 0     | 0%         |
| Operational Noise   | 46    | 46%        |
| System Event        | 0     | 0%         |
| Unknown             | 54    | 54%        |

**Analisis**:
- **0% Research Event**: Tidak ada satu pun dari 100 sample yang mengandung keyword riset (nmap, hydra, nikto, brute, scan, web vulnerability)
- **46% Operational Noise**: Suricata stream events, Wazuh events
- **54% Unknown**: Generic "IDS event" yang tidak terklasifikasi

**KONFIRMASI**: Dataset operational ini **BUKAN** dataset penelitian yang valid.

---

## H. PENILAIAN KELAYAKAN DATASET

### Kriteria Kelayakan Penelitian

| Kriteria                               | Target | Aktual | Status |
|----------------------------------------|--------|--------|--------|
| Research Event Dominant                | ≥80%   | 0%     | ❌ FAIL |
| MITRE Mapping Complete                 | ≥80%   | 1.60%  | ❌ FAIL |
| Operational Noise Low                  | ≤20%   | 46%    | ❌ FAIL |

### VERDICT FINAL

```
TIDAK LAYAK - MITRE mapping tidak memadai
```

**Alasan Penolakan**:
1. **Tidak ada data serangan riset** (0% dari sample)
2. **MITRE mapping gagal** (hanya 1.60% berhasil dipetakan)
3. **Terlalu banyak operational noise** (46% dari sample)
4. **Tidak ada controlled testing protocol** (30 iterasi terkontrol tidak ditemukan)
5. **Durasi pengumpulan data hanya 8.5 jam** (bukan penelitian multi-hari yang terencana)

---

## REKOMENDASI

### OPSI A: RESET & REBUILD DATASET (RECOMMENDED)

**Langkah**:
1. Backup database aktif: `cp incidents.db incidents_backup_operational_$(date +%Y%m%d).db`
2. Reset database: `rm incidents.db` → SOAR akan auto-create schema baru
3. Jalankan controlled testing protocol:
   - 10 iterasi Nmap scan (T1046 - Network Service Discovery)
   - 10 iterasi Hydra brute force (T1110.001 - Brute Force Password Guessing)
   - 10 iterasi Nikto scan (T1595.002 - Gather Victim Host Information)
4. Validasi MITRE enrichment pipeline sebelum testing
5. Dokumentasikan setiap iterasi dengan timestamp dan evidence

**Estimasi Waktu**: 2-3 hari (termasuk troubleshooting pipeline)

**KELEBIHAN**:
- Dataset bersih dan terkontrol
- 100% research event
- MITRE mapping dapat divalidasi per iterasi
- Memenuhi standar penelitian akademik
- Reproducible untuk validasi dosen/penguji

**KEKURANGAN**:
- Kehilangan data operational (sudah di-backup)
- Butuh waktu untuk re-collection

---

### OPSI B: FILTERING DATASET AKTIF (NOT RECOMMENDED)

**Langkah**:
1. Buat view atau filtered table untuk research event only
2. Export data dengan `WHERE attack_type LIKE '%CTI-LAB%'` atau `WHERE mitre_status = 'Mapped'`
3. Analisis subset data ini

**KELEBIHAN**:
- Tidak kehilangan data operational
- Lebih cepat daripada rebuild

**KEKURANGAN**:
- Hanya 34 incident "CTI-LAB" (tidak cukup untuk 30 iterasi)
- Hanya 8,679 MITRE Mapped (mayoritas bukan research event)
- Tidak bisa membuktikan controlled testing protocol
- Dosen/penguji dapat mempertanyakan validitas data

---

### OPSI C: PARTIAL RESET + INCREMENTAL COLLECTION

**Langkah**:
1. Backup database operational
2. Reset database
3. Kumpulkan **minimal 30 controlled iterations** (10 per attack type)
4. Stop collection setelah 30 iterasi tercapai
5. Dokumentasikan evidence collection per iterasi

**KELEBIHAN**:
- Dataset minimal namun valid
- Controlled dan reproducible
- Cepat (fokus pada 30 iterasi saja)
- Memenuhi standar minimal penelitian

**KEKURANGAN**:
- Dataset kecil (hanya ~30-90 incident core research)
- Perlu tambahan data supporting (tapi bisa dari operational backup)

---

## EVIDENCE FILES

**Lokasi**: `13-Audit/reports/RUNTIME_DATASET_COMPOSITION.md`

**Raw Output**: Tersimpan dalam laporan ini

**Database Info**:
- Path: `/home/iqbal/soar-dashboard/app/incidents.db`
- Size: 66 MB
- Total Records: 540,889
- API Response: 251 MB JSON

---

## CATATAN METODOLOGI

**Metode Audit**: 
- Query langsung ke database SQLite menggunakan Python sqlite3 module
- 100% READ ONLY - tidak ada modifikasi database
- Sample acak menggunakan `ORDER BY RANDOM() LIMIT 100` (statistik representatif)

**Klasifikasi Keyword**:
- **Research Event**: nmap, hydra, nikto, brute, scan, web vulnerability, reconnaissance
- **Operational Noise**: suricata stream, packet out of window, invalid ack, wazuh, ossec
- **System Event**: pam, session, login, sshd

**Kriteria Kelayakan**:
- Research Event: ≥80% (standar penelitian terkontrol)
- MITRE Mapping: ≥80% (standar CTI enrichment)
- Operational Noise: ≤20% (toleransi noise maksimal)

---

## NEXT STEPS

**MENUNGGU KEPUTUSAN USER**:

1. **Apakah user ingin reset database dan rebuild dataset?**
2. **Apakah user ingin filtering dataset aktif (risiko: tidak valid)?**
3. **Apakah user ingin validasi MITRE pipeline dulu sebelum reset?**

**RULE**: READ ONLY - menunggu approval eksplisit sebelum tindakan destructive.

---

**Timestamp Laporan**: 2026-06-20 21:00 WIB  
**Auditor**: Kiro AI (Dataset Composition Forensic Audit)  
**Status**: COMPLETED - WAITING FOR USER DECISION
