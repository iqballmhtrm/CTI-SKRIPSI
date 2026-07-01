# Governance Document Index

## Status
Draft (scaffold)

## Cara baca
Metadata di bawah bersifat **struktural** (relasi antar dokumen menurut urutan
metodologi), bukan konten ilmiah. Lihat `GOVERNANCE-MAP.md` untuk peta alur dan
`STATUS.md` untuk status terkini.

## Dokumen Governance (R-00 … R-14) — metadata minimal

### R-00 — Project Charter
- **Purpose:** Menetapkan mandat, ruang lingkup, dan batas penelitian.
- **Input:** — (dokumen akar)
- **Output:** Charter acuan seluruh dokumen turunan.
- **Dependencies:** —
- **Successor Document:** R-01
- **Status:** LOCKED (Scientific Governance) — TODO tersisa hanya metadata administratif

### R-01 — Problem Domain
- **Purpose:** Mendefinisikan domain persoalan sebagai akar penalaran.
- **Input:** R-00
- **Output:** Definisi Problem Domain.
- **Dependencies:** R-00
- **Successor Document:** R-02
- **Status:** LOCKED (Scientific Governance)

### R-02 — Author Revision
- **Purpose:** Mencatat penajaman penulis atas Problem Domain.
- **Input:** R-01
- **Output:** Problem Domain ter-revisi.
- **Dependencies:** R-01
- **Successor Document:** R-03
- **Status:** LOCKED (Scientific Governance)

### R-03 — Research Gap
- **Purpose:** Menetapkan kesenjangan penelitian dari domain & literatur.
- **Input:** R-02
- **Output:** Pernyataan Research Gap.
- **Dependencies:** R-01, R-02
- **Successor Document:** R-04
- **Status:** Draft

### R-04 — Research Problem
- **Purpose:** Memformalkan masalah penelitian dari gap.
- **Input:** R-03
- **Output:** Research Problem.
- **Dependencies:** R-03
- **Successor Document:** R-05
- **Status:** Template

### R-05 — Research Objectives
- **Purpose:** Menurunkan tujuan penelitian dari masalah.
- **Input:** R-04
- **Output:** Research Objectives.
- **Dependencies:** R-04
- **Successor Document:** R-06
- **Status:** Template

### R-06 — Research Questions
- **Purpose:** Merumuskan pertanyaan penelitian dari tujuan.
- **Input:** R-05
- **Output:** Research Questions.
- **Dependencies:** R-04, R-05
- **Successor Document:** R-07
- **Status:** Template

### R-07 — Research Matrix
- **Purpose:** Menyatukan gap–masalah–tujuan–pertanyaan ke dalam matriks.
- **Input:** R-03, R-04, R-05, R-06
- **Output:** CTI Research Matrix.
- **Dependencies:** R-03, R-04, R-05, R-06
- **Successor Document:** R-08
- **Status:** Draft

### R-08 — Research Architecture
- **Purpose:** Menetapkan arsitektur/kerangka kerja penelitian dari matriks.
- **Input:** R-07
- **Output:** Research Architecture.
- **Dependencies:** R-07
- **Successor Document:** R-09
- **Status:** Template

### R-09 — Concept Backbone
- **Purpose:** Menetapkan tulang punggung konsep yang melandasi arsitektur.
- **Input:** R-07, R-08
- **Output:** Concept Backbone.
- **Dependencies:** R-07, R-08
- **Successor Document:** R-10
- **Status:** LOCKED (Scientific Governance)

### R-10 — Actionable Intelligence
- **Purpose:** Menjabarkan konsep intelijen yang dapat ditindaklanjuti.
- **Input:** R-09
- **Output:** Definisi Actionable Intelligence.
- **Dependencies:** R-09
- **Successor Document:** R-11
- **Status:** Draft

### R-11 — Artifact Capabilities
- **Purpose:** Menetapkan kapabilitas artefak (AC) yang harus dipenuhi.
- **Input:** R-10
- **Output:** Daftar Artifact Capabilities.
- **Dependencies:** R-09, R-10
- **Successor Document:** R-12
- **Status:** Template

### R-12 — Technical Specification
- **Purpose:** Menerjemahkan kapabilitas ke spesifikasi teknis.
- **Input:** R-11
- **Output:** Technical Specification.
- **Dependencies:** R-11
- **Successor Document:** R-13
- **Status:** Template

### R-13 — Engineering Blueprint
- **Purpose:** Menyusun cetak biru rekayasa dari spesifikasi teknis.
- **Input:** R-12
- **Output:** Engineering Blueprint.
- **Dependencies:** R-12
- **Successor Document:** R-14
- **Status:** Template

### R-14 — Evaluation Design
- **Purpose:** Merancang evaluasi artefak terhadap kapabilitas & tujuan/pertanyaan.
- **Input:** R-11, R-13
- **Output:** Evaluation Design.
- **Dependencies:** R-05, R-06, R-11, R-13
- **Successor Document:** — (terminal)
- **Status:** Draft

## Dokumen Meta

| Dokumen | Fungsi | Status |
|---------|--------|--------|
| README.md | Penjelasan fungsi folder governance | Draft |
| INDEX.md | Daftar dokumen + metadata minimal | Draft |
| GOVERNANCE-MAP.md | Peta alur & dependensi antar dokumen | Draft |
| STATUS.md | Status pengisian setiap dokumen | Draft |
| CHANGELOG.md | Riwayat perubahan struktural | Draft |
| TRACEABILITY.md | Matriks keterlacakan (template) | Template |
| PRINCIPLES.md | Prinsip & aturan main penelitian (template) | Template |

## Dokumen lain yang sudah ada di folder ini (di luar scaffold, tidak diubah)
- CHECKPOINT-DISKUSI-ARAH-2026-06-25.md
- PROJECT-EXECUTION-PLAN-ENGINEERING.md
- prompts/
- roadmaps/
- steering/
