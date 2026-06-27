# Governance Map

## Status
Draft (scaffold)

## Purpose
Memetakan keterhubungan antar dokumen governance (R-00 … R-14) menurut **urutan
metodologi penelitian**. Peta ini bersifat struktural (alur input → output antar
dokumen), bukan konten ilmiah.

## Rantai metodologi (linear)

```
R-00 Project Charter
  └─> R-01 Problem Domain
        └─> R-02 Author Revision
              └─> R-03 Research Gap
                    └─> R-04 Research Problem
                          └─> R-05 Research Objectives
                                └─> R-06 Research Questions
                                      └─> R-07 Research Matrix
                                            └─> R-08 Research Architecture
                                                  └─> R-09 Concept Backbone
                                                        └─> R-10 Actionable Intelligence
                                                              └─> R-11 Artifact Capabilities
                                                                    └─> R-12 Technical Specification
                                                                          └─> R-13 Engineering Blueprint
                                                                                └─> R-14 Evaluation Design
```

## Pengelompokan lapisan

| Lapisan | Dokumen | Peran struktural |
|---|---|---|
| Fondasi | R-00 | Mandat & ruang lingkup |
| Problem | R-01, R-02, R-03 | Domain → revisi → gap |
| Formalisasi | R-04, R-05, R-06 | Masalah → tujuan → pertanyaan |
| Sintesis | R-07 | Research Matrix |
| Konsep | R-08, R-09, R-10 | Arsitektur → backbone → actionable intelligence |
| Artefak | R-11, R-12, R-13 | Kapabilitas → spesifikasi → blueprint |
| Evaluasi | R-14 | Rancangan evaluasi (terminal) |

## Dependensi balik (terminal → akar)
R-14 bergantung pada kriteria dari R-05, R-06, R-11, dan R-13; rantai keterlacakan
penuh ditelusuri pada `TRACEABILITY.md` (template).

## Notes
Peta ini hanya menggambarkan urutan dan ketergantungan dokumen. Definisi konten
(termasuk AC-1…AC-13 pada R-11) diisi terpisah oleh Research Owner.
