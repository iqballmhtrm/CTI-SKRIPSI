# R-01 — Problem Domain

## Status
LOCKED (Scientific Governance)

## Purpose
Menetapkan domain persoalan penelitian sebagai akar penalaran, beserta kajian
konsep dasar yang melandasinya. Dimigrasikan dari hasil Research Mode R-01.1
(kajian konsep) dan R-01.2 (artikulasi domain).

## Scope
Domain persoalan pada tataran **operasional SOC / praktik CTI**: transformasi
data keamanan menjadi intelijen yang menopang keputusan. Tidak mencakup rumusan
gap/masalah/tujuan formal (merupakan keluaran R-03 … R-06).

## Input
R-00 — Project Charter.

## Output
Definisi Problem Domain + kajian konsep dasar (lima konsep).

## Dependencies
R-00.

## Locked Decisions
### Artikulasi Problem Domain (enam elemen)
1. **Field:** operasi keamanan siber, khususnya praktik CTI di lingkungan SOC.
2. **Fenomena luas:** infrastruktur keamanan menghasilkan log & alert dalam
   volume sangat besar dan berkecepatan tinggi.
3. **Ketegangan inti:** volume data mentah ≠ intelijen yang dapat ditindaklanjuti
   (*data-to-decision / actionable intelligence gap*).
4. **Aktor terdampak:** analis SOC dan tim respons insiden; serta pengambil
   keputusan operasional yang bergantung pada hasil tafsir.
5. **Konsekuensi:** *alert fatigue*, prioritas keliru, keterlambatan/ketidaktepatan
   keputusan — memperlebar jendela waktu serangan.
6. **Batas domain:** transformasi data→intelijen kontekstual pada skala SOC
   operasional; mengecualikan kebijakan keamanan organisasi, intelijen strategis
   eksekutif, dan aspek hukum/forensik pasca-insiden.

### Lima konsep dasar (R-01.1)
- **Cyber Threat Intelligence (CTI)** — intelijen berbasis bukti, kontekstual,
  dan *actionable* (McMillan/Gartner; NIST SP 800-150).
- **Information Overload** — tuntutan pemrosesan melampaui kapasitas (Eppler &
  Mengis; Miller).
- **Alert Fatigue** — desensitisasi terhadap peringatan akibat volume/false
  positive (Alahmadi et al.).
- **Transformasi Data → Information → Intelligence** — hierarki DIKW & intelligence
  cycle (Ackoff; NIST SP 800-150).
- **Decision Support** — sistem/penyajian yang menopang keputusan (Simon; Gorry &
  Scott Morton).

## Traceability
- **Predecessor:** R-00. **Successor:** R-02.
- Lima konsep → backbone konsep di **R-09**.
- Ketegangan inti (*transformation gap*) → bahan **R-03** (Research Gap).

## Notes
- Provenance: Research Mode R-01.1 & R-01.2 (dinyatakan LOCKED oleh Research Owner).
- Detail sitasi literatur perlu diverifikasi pada sumber primer untuk naskah final
  (catatan integritas akademik, bukan kekurangan substansi governance).
