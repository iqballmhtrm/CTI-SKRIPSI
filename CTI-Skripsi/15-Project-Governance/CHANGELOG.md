# Governance Changelog

## Status
Draft (scaffold)

## Purpose
Mencatat perubahan struktural pada Research Governance Repository. Hanya memuat
perubahan berkas/struktur, bukan konten ilmiah.

## Format
`[YYYY-MM-DD] — ringkasan perubahan (jenis: ADD/UPDATE/REMOVE)`

## Entri

### 2026-06-27
- ADD — Membangun scaffold awal governance: `README.md`, `INDEX.md`,
  `TRACEABILITY.md` (template), `PRINCIPLES.md` (template), dan dokumen
  `R-00` … `R-14` (template).
- ADD — Menambahkan dokumen meta: `GOVERNANCE-MAP.md`, `STATUS.md`, `CHANGELOG.md`.
- UPDATE — Memperbarui `INDEX.md` dengan metadata minimal per dokumen
  (Purpose, Input, Output, Dependencies, Successor Document, Status).
- UPDATE — Mengisi konten R-00 (Project Charter) dari sumber LOCKED.
- POLICY — Menetapkan pemisahan lapisan **Scientific Governance Content** vs
  **Administrative Metadata**; status LOCKED ditentukan kelengkapan substansi
  ilmiah, bukan metadata administratif.
- STATUS — R-00 dinaikkan `Template` → `LOCKED (Scientific Governance)`; TODO
  tersisa hanya pada metadata administratif. Disinkronkan di `INDEX.md`,
  `STATUS.md`.
- MIGRATE — Memigrasikan pengetahuan LOCKED ke R-01 … R-14:
  - LOCKED (Scientific Governance): R-01 (Problem Domain), R-02 (Author Revision),
    R-09 (Concept Backbone).
  - Draft (substansi parsial LOCKED, output utama menunggu hulu): R-03 (Gap
    Extraction Matrix terisi; gap terpilih TODO), R-07 (kerangka dimensi terisi;
    isi TODO), R-10 (kriteria CTI terisi; operasionalisasi TODO), R-14 (definisi
    metrik & protokol terisi; penautan tujuan TODO).
  - Template (belum ada sumber LOCKED): R-04, R-05, R-06, R-08, R-11, R-12, R-13.
- SYNC — `INDEX.md` & `STATUS.md` diperbarui sesuai status migrasi.

## Notes
Seluruh perubahan terbatas pada folder `15-Project-Governance/`. Tidak ada
konten ilmiah yang diisi pada tahap ini.
