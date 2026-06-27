# MASTER PROJECT STATUS REPORT — CTI-SKRIPSI

**Judul Penelitian:** Optimisasi Visualisasi Data Log dan Alert Siber Melalui Dashboard ELK Stack untuk Mendukung Pengambilan Keputusan Operasional Cyber Threat Intelligence (CTI)
**Institusi:** Politeknik Negeri Malang
**Tanggal Audit:** 21 Juni 2026
**Metode:** Evidence-based. Ground Truth Runtime mengalahkan semua dokumentasi/audit/klaim lama.
**Status Laporan:** COMPLETED

---

## SUMBER EVIDENCE YANG DIGUNAKAN

| Sumber | Tipe | Keandalan |
|--------|------|-----------|
| Runtime Dataset Composition Audit (20 Juni 2026) | RUNTIME | GROUND TRUTH UTAMA |
| SOAR Runtime Forensic (ps, ss, curl API) | RUNTIME | GROUND TRUTH |
| incidents.db query langsung (540,889 record) | RUNTIME | GROUND TRUTH |
| EVIDENCE_SOURCE_CLASSIFICATION.md | REPOSITORY | Pendukung |
| 11-Bab4/laporan_implementasi_lengkap.md | REPOSITORY | Pendukung (MTTD/MTTR) |
| 07-Testing/*/validation_success.txt | REPOSITORY | Pendukung |
| 05-MITRE/mitre-mapping.yml | REPOSITORY | Pendukung |

**PRINSIP:** Jika evidence runtime bertentangan dengan dokumentasi lama, runtime MENANG.

---

## RINGKASAN GROUND TRUTH RUNTIME (WAJIB DIBACA)

```
Total Incident      : 540,889
Status New          : 540,868 (99.996%)
Status Resolved     : 12 (0.002%)
MITRE Mapped        : 8,679 (1.60%)
MITRE Unmapped      : 532,225 (98.40%)
Research Event      : 0% (dari 100 sample acak)
Operational Noise   : 46%
SOAR API Response   : 251 MB JSON
Database Size       : 66 MB
Verdict Dataset     : TIDAK LAYAK UNTUK PENELITIAN
```

**Catatan penting:** Klaim lama "~9,020 incident, 95% noise, MITRE 1:151" terbukti SALAH. Angka aktual jauh berbeda.
