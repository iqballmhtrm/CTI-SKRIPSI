# R-14 — Evaluation Design

## Status
Draft
<!-- Definisi metrik & protokol pengujian LOCKED; penautan ke tujuan/RQ (R-05/R-06) masih TODO. -->

## Purpose
Merancang evaluasi artefak terhadap kapabilitas dan tujuan/pertanyaan penelitian.
Sebagian substansi (definisi metrik & protokol terkontrol) tersedia LOCKED;
penautan ke tujuan/pertanyaan formal menunggu R-05/R-06.

## Scope
Rancangan evaluasi: definisi metrik, protokol pengujian, dan kriteria.

## Input
R-11 (kapabilitas), R-13 (blueprint), serta kriteria dari R-05/R-06.

## Output
- Definisi metrik & protokol pengujian (LOCKED, di bawah).
- Penautan ke tujuan/pertanyaan & kriteria keberhasilan — **TODO**.

## Dependencies
R-05, R-06, R-11, R-13.

## Locked Decisions
**Definisi metrik (dari kerja hasil terkontrol):**
- Penanda waktu: T0 (peluncuran serangan), T1 (alert pertama terindeks),
  T2 (mitigasi *firewall-drop* terindeks).
- **MTTD = T1 − T0**; **MTTR = T2 − T0**.

**Protokol pengujian:**
- 30 iterasi terkontrol = 10 Nmap + 10 Hydra + 10 Nikto.
- Tiga skenario: Nmap (T1046), Hydra (T1110.001), Nikto (T1595.002).
- Independensi antar-iterasi (reset blokir IP di awal tiap iterasi).

## Traceability
- **Predecessor:** R-13. **Successor:** — (terminal).
- Definisi MTTR (T2 − T0) memiliki **inkonsistensi tercatat** dengan sumber lama
  yang memakai T2 − T1 (lihat Notes & isu Research Owner).

## Notes
- Provenance metrik/protokol: kerja hasil terkontrol (baseline) + penundaan
  MTTD/MTTR pada R-02.
- **Inkonsistensi definisi MTTR** (T2 − T0 vs T2 − T1) belum diselaraskan di
  seluruh sumber → memerlukan keputusan Research Owner.
- Penautan evaluasi ke tujuan/pertanyaan formal TODO karena R-05/R-06 belum ada.
