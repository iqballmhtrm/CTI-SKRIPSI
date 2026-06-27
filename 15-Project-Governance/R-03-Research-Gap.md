# R-03 — Research Gap

## Status
Draft
Existing studies have addressed log visualization, threat detection, MITRE ATT&CK mapping, alert prioritization, and operational metrics individually. However, there is still no integrated operational framework that transforms heterogeneous security events into actionable cyber threat intelligence through contextual enrichment, standardized threat mapping, operational prioritization, and measurable detection–response performance within a unified ELK Stack environment.

## Purpose
Menetapkan kesenjangan penelitian dari Problem Domain & sintesis literatur.
Dimigrasikan dari R-03.1 (Gap Extraction Matrix). Pemilihan/formulasi gap final
adalah wewenang Research Owner dan **belum diputuskan**.

## Scope
Ekstraksi kandidat gap (objektif) dan — bila sudah diputuskan — pernyataan
Research Gap terpilih.

## Input
R-02 (Problem Domain ter-revisi) + sintesis literatur R-01.3/R-01.4.

## Output
- Gap Extraction Matrix (LOCKED, di bawah).
- Pernyataan Research Gap terpilih — **TODO** (belum dipilih).

## Dependencies
R-01, R-02.

## Locked Decisions
**Gap Extraction Matrix — 7 kandidat (R-03.1):**
- **G-01** — menengahi volume & heterogenitas data (mereduksi overload).
- **G-02** — mengurangi alert fatigue & prioritisasi pada tataran SOC.
- **G-03** — menaikkan keluaran data → information → intelligence.
- **G-04** — menjamin keluaran memenuhi standar mutu CTI pada volume tinggi.
- **G-05** — kontekstualisasi ancaman via taksonomi terstruktur (MITRE ATT&CK).
- **G-06** — menopang keputusan operasional (decision support / situational awareness).
- **G-07** — pengukuran responsivitas (MTTD/MTTR) — sumber akademik tipis, definisi tak konsisten.

## Traceability
- **Predecessor:** R-02. **Successor:** R-04.
- Gap terpilih → mendasari Research Problem **R-04**.

## Notes
- R-03.1 secara eksplisit **tidak memilih** gap, **tidak** menentukan novelty,
  **tidak** merumuskan Research Problem. Karena itu OUTPUT utama dokumen ini
  ber-status **TODO** hingga Research Owner memutuskan.
- Pola lintas-kelompok (bahan, bukan kesimpulan): K1 viz kuat teknik–lemah tautan
  taksonomi; K2 fokus faktor manusia; K3 mutu CTI turun saat volume naik; K4
  didominasi alat/vendor; K5 didominasi praktisi & definisi tak konsisten.
