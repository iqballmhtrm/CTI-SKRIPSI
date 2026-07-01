# Governance Status

## Status
Draft (scaffold)

## Purpose
Memantau status pengisian setiap dokumen governance. Status mencerminkan kondisi
**berkas** (terisi/terkunci), bukan status diskusi di luar repository.

## Legenda status
- **Template** — berkas masih kerangka kosong (seksi `(TODO)`).
- **Draft** — sebagian konten sudah diisi, belum diratifikasi.
- **Locked** — substansi ilmiah final, tidak diubah tanpa keputusan eksplisit.

## Prinsip penentuan LOCKED
Status **LOCKED** ditentukan oleh kelengkapan **Scientific Governance Content**,
bukan oleh **Administrative Metadata**. Metadata administratif (judul final,
penulis, pembimbing, timeline, institusi) yang masih `TODO` **tidak memblok**
status LOCKED.

## Status dokumen R-00 … R-14

| ID | Dokumen | Status |
|----|---------|--------|
| R-00 | Project Charter | LOCKED (Scientific Governance) |
| R-01 | Problem Domain | LOCKED (Scientific Governance) |
| R-02 | Author Revision | LOCKED (Scientific Governance) |
| R-03 | Research Gap | Draft |
| R-04 | Research Problem | Template |
| R-05 | Research Objectives | Template |
| R-06 | Research Questions | Template |
| R-07 | Research Matrix | Draft |
| R-08 | Research Architecture | Template |
| R-09 | Concept Backbone | LOCKED (Scientific Governance) |
| R-10 | Actionable Intelligence | Draft |
| R-11 | Artifact Capabilities | Template |
| R-12 | Technical Specification | Template |
| R-13 | Engineering Blueprint | Template |
| R-14 | Evaluation Design | Draft |

## Status dokumen meta

| Dokumen | Status |
|---------|--------|
| README.md | Draft |
| INDEX.md | Draft |
| GOVERNANCE-MAP.md | Draft |
| STATUS.md | Draft |
| CHANGELOG.md | Draft |
| TRACEABILITY.md | Template |
| PRINCIPLES.md | Template |

## Catatan
Dokumen berstatus **LOCKED (Scientific Governance):** R-00, R-01, R-02, R-09.
Dokumen **Draft** (sebagian substansi LOCKED, output utama menunggu hulu): R-03,
R-07, R-10, R-14. Dokumen **Template** (belum ada sumber LOCKED): R-04, R-05,
R-06, R-08, R-11, R-12, R-13. TODO yang tersisa pada dokumen LOCKED hanya bersifat
metadata administratif dan tidak memengaruhi status.
