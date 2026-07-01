# R-00 — Project Charter

## Status
LOCKED (Scientific Governance)
<!-- Substansi ilmiah lengkap & konsisten. Metadata administratif (TODO) tidak memblok status LOCKED. -->

## Purpose
Dokumen ini menetapkan **mandat, ruang lingkup makro, dan batas penelitian**
sebagai akar (root) seluruh dokumen governance `R-01` … `R-14`. Charter menjadi
acuan tetap yang menaungi penurunan dari Problem Domain hingga Evaluation Design.

Konteks proyek: penelitian akademik (skripsi) yang menempatkan **Cyber Threat
Intelligence (CTI)** sebagai landasan untuk merancang kapabilitas **pendukung
keputusan operasional** pada lingkungan **Security Operations Center (SOC)**
terkontrol. Charter ini tidak merumuskan masalah/tujuan/pertanyaan formal —
hal tersebut diturunkan pada dokumen R-04/R-05/R-06.

## Scope
**Termasuk dalam lingkup (in-scope):**
- Penelitian terkontrol atas **deteksi dan respons ancaman berbasis CTI** pada
  lingkungan lab host-only.
- Pemetaan aktivitas serangan ke kerangka **MITRE ATT&CK**, agregasi log,
  visualisasi, dan respons otomatis sebagai komponen yang menjadi konteks
  pendukung penelitian.
- Tiga skenario serangan yang menjadi cakupan baseline: Nmap (T1046),
  Hydra (T1110.001), dan Nikto (T1595.002).

**Di luar lingkup (out-of-scope):**
- Penerapan/produksi di lingkungan nyata.
- Fase honeypot / Elastic Cloud (Track 2) — ditunda, bukan bagian hasil inti.
- Rumusan formal masalah, tujuan, dan pertanyaan penelitian (didefinisikan pada
  R-04, R-05, R-06).

## Input
— (dokumen akar; tidak memiliki dokumen pendahulu)

## Output
Project Charter sebagai acuan governance tertinggi yang menaungi R-01 … R-14.

## Dependencies
— (tidak ada dependensi hulu)

## Locked Decisions
Keputusan kerja yang telah dinyatakan eksplisit oleh Research Owner dan berlaku
sebagai bingkai penelitian:
1. **Research Mode** — seluruh implementasi diturunkan dari hasil Research Matrix,
   bukan sebaliknya.
2. **Karakter design science** — artefak dilandasi teori mapan (*kernel theory*)
   sebagai landasan perancangan; penelitian tidak menguji model kausal baru.
3. **Baseline engineering sebagai konteks pendukung** — progres engineering
   (Bab 4/5, dashboard, pipeline, 30 iterasi terkontrol) diperlakukan sebagai
   baseline yang telah selesai pada level yang diperlukan, bukan dasar
   pengambilan keputusan penelitian.
4. **Lingkungan penelitian terkontrol** — lab VirtualBox host-only
   `192.168.56.0/24`, bersifat akademik (skripsi), bukan produksi.

## Traceability
- **Successor Document:** R-01 — Problem Domain.
- Charter menetapkan batas makro yang **diperinci** oleh R-01 (penetapan domain
  persoalan). Tidak ada dokumen pendahulu.
- Konsistensi prinsip kerja dirujuk silang ke `PRINCIPLES.md` (template) dan peta
  alur pada `GOVERNANCE-MAP.md`.

## Notes

### Pemisahan lapisan dokumen
- **Scientific Governance Content (mengikat status LOCKED):** Purpose, Scope
  (in/out), Locked Decisions, dan Traceability. Lapisan ini telah **lengkap dan
  konsisten**.
- **Administrative Metadata (tidak mengikat status LOCKED):** atribut formal/
  administratif yang dapat dilengkapi kapan pun tanpa mengubah substansi ilmiah.

### Administrative Metadata — TODO (tidak memblok LOCKED)
- TODO — Judul resmi penelitian.
- TODO — Identitas penulis, program studi/institusi, dan pembimbing.
- TODO — Periode pelaksanaan / milestone / timeline.
- TODO — Daftar pemangku kepentingan (stakeholders) formal.

### Catatan substansi
- Kriteria keberhasilan tingkat hasil **bukan** TODO charter, melainkan
  diserahterimakan ke R-14 (Evaluation Design) sesuai traceability — bukan
  kekurangan substansi R-00.
- Pernyataan lingkup mengacu pada baseline proyek terdokumentasi; rumusan ilmiah
  formal (masalah/tujuan/pertanyaan) merupakan keluaran dokumen hilir
  (R-03 … R-06).
