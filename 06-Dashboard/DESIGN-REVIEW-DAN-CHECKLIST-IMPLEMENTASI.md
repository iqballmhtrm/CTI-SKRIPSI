# DESIGN REVIEW FINAL + CHECKLIST IMPLEMENTASI — Dashboard Final CTI

> Peran: **Engineering Lead review** (bukan implementer). STATUS: **EXECUTION FREEZE**.
> Tidak ada perubahan sistem (dashboard/panel/MTTD/MTTR/Threat Score/SOAR/Transform)
> sampai **Checklist Implementasi (Bagian 2)** disetujui pemilik penelitian.
> Dashboard V3 (`v3-cti-dashboard-final`) = **GROUND TRUTH / BASELINE — TIDAK DIUBAH.**
> Tanggal: 2026-06-25 · Acuan desain: `06-Dashboard/DESAIN-DASHBOARD-FINAL.md`.

---

# BAGIAN 1 — DESIGN REVIEW (jawaban A–E)

## A. Apakah desain cukup mendukung JUDUL penelitian?
Judul: *Optimisasi Visualisasi … Dashboard ELK … Mendukung Pengambilan Keputusan Operasional CTI.*

**Sebagian besar YA**, dengan satu catatan kritis.
- ✅ Pendekatan 3-layer + label bahasa awam = wujud konkret "optimisasi visualisasi" & "mendukung keputusan operasional".
- ✅ Non-destruktif (V3 baseline aman) = stabil & terdokumentasi.
- ⚠️ **CATATAN KRITIS:** "Optimisasi" pada judul/Bab III diukur lewat **studi responden before–after (10 partisipan; Discover vs Dashboard)** + **Rasio Agregasi**. Desain dashboard sudah bagus sebagai *artefak*, tetapi **belum mengikat dashboard ke metode evaluasinya**. Dashboard adalah ALAT; **buktinya = studi responden** (yang sampai kini KOSONG). Desain final harus menjamin dashboard "siap dipakai untuk uji before–after".

## B. Apakah masih ada GAP terhadap TUJUAN penelitian?
Tujuan: hybrid detection terintegrasi · dashboard CTI · evaluasi MTTD/MTTR.
- **GAP-1 (besar): Studi responden belum dirancang/eksekusi.** Ini bukti utama efektivitas — risiko terbesar untuk sidang, lebih besar daripada poles dashboard.
- **GAP-2: MTTD/MTTR belum di dashboard** (hanya CSV). Sudah dialamatkan desain (N7/N8) tapi butuh index `cti-mttd-mttr-iqbal`.
- **GAP-3: Pilar "Hybrid Detection (NIDS vs HIDS)" belum punya panel bukti.** Judul/Bab menonjolkan hybrid, tapi tak ada panel yang membandingkan deteksi Suricata vs Wazuh. **Rekomendasi: tambah 1 panel "Sumber Deteksi (NIDS/HIDS)".**
- **GAP-4: Atribut "dari mana (geolokasi)"** pada Zero-Query Visibility **tak terpenuhi di lab** (IP privat). Harus dinyatakan sebagai **batasan** di naskah, atau dipenuhi di fase honeypot (future).
- **GAP-5: Detection Rate (variabel kontrol Bab III)** belum tampil. Opsional: indikator kecil "tingkat deteksi 100% (30/30)".
- **GAP-6: Rekonsiliasi naskah↔live (P3)** belum dikerjakan (SID 9000↔1000, index soc-alerts↔cti-logs, .120↔.110, 2↔3 skenario, MTTR definisi, 14↔30 iterasi). Wajib sebelum sidang agar konsisten.

## C. Apakah dashboard benar-benar mendukung PENGAMBILAN KEPUTUSAN operasional CTI?
**Ya secara struktur** (L1 status/penyerang/target/penanganan → keputusan cepat; L2 konteks; L3 kedalaman).
- ⚠️ **Defisit "prioritas/keputusan eksplisit":** belum ada penanda *"IP mana yang harus diblokir lebih dulu"* yang kuat. Threat-score (Endsley) seharusnya mengisi ini, **tetapi Transform threat-score kemungkinan kosong** karena `source.ip` kosong (ia group-by `source.ip.keyword`). → Perlu keputusan: perbaiki Transform (pakai `src_ip.keyword`) ATAU andalkan panel "Penyerang Teratas" + "Status Penanganan" sebagai pengganti keputusan.
- ✅ "Apakah sudah ditangani" (N6) adalah elemen keputusan kunci dan sudah ada.

## D. Apakah ada PANEL yang masih kurang?
Direkomendasikan ditambah (di luar N1–N9 desain):
- **N10. Sumber Deteksi NIDS vs HIDS** (bukti pilar hybrid) — L2/L3.
- **N11. Distribusi Severity** (Low/Med/High/Critical) — bantu triage — L2.
- **N12. Panel "Legenda/Bantuan"** (markdown) menjelaskan istilah untuk non-teknis — L1.
- (Opsional) **N13. Detection Rate indicator** — L1/L3.
- Catatan: panel peta geolokasi **ditunda** (lab IP privat).

## E. Apa yang HARUS selesai sebelum IMPLEMENTATION PHASE? (gerbang)
1. **Persetujuan bentuk dashboard**: 1 dashboard panjang bersekat (rekomendasi) vs 3 dashboard.
2. **Konfirmasi read-only** judul 7 panel `cti-dashboard-main` (agar daftar "dipertahankan" akurat).
3. **Keputusan Top Threat Actors**: filter buang IP infra `.1/.10/.106` (ya/tidak).
4. **Kunci definisi MTTR = T2−T0** (selaras data 30-run) dan **dataset resmi = 30 iterasi**.
5. **Keputusan threat-score**: perbaiki Transform (`src_ip`) atau pensiunkan & ganti narasi keputusan.
6. **Keputusan GeoIP**: nyatakan batasan lab (tanpa peta) atau tunda ke honeypot.
7. **Sikap terhadap GAP-1 (studi responden)**: kapan & bagaimana dijalankan (ini penentu kelulusan, di luar teknis dashboard).
8. **Persetujuan Checklist Implementasi (Bagian 2)** sebagai satu-satunya acuan.

**Kesimpulan review:** Desain dashboard **cukup matang & aman** untuk mulai implementasi bertahap SETELAH gerbang E dipenuhi. Namun sebagai Engineering Lead saya menegaskan: **risiko kelulusan terbesar bukan pada dashboard, melainkan pada GAP-1 (studi responden) dan GAP-6 (rekonsiliasi naskah).** Dashboard yang sempurna tanpa bukti responden + naskah yang konsisten = belum siap sidang.

---

# BAGIAN 2 — CHECKLIST IMPLEMENTASI (SATU-SATUNYA ACUAN)

> Aturan: kerjakan **berurutan**, **satu item satu sesi**, **validasi sebelum lanjut**, **backup sebelum tiap perubahan**. Tanda **[GATE]** = butuh persetujuan eksplisit pemilik sebelum lanjut. Tidak ada langkah dieksekusi sebelum checklist ini disetujui.

## FASE 0 — Prasyarat & Keputusan (tanpa ubah sistem)
- [ ] 0.1 [GATE] Setujui **bentuk dashboard** (1 panjang bersekat / 3 dashboard).
- [ ] 0.2 [GATE] Setujui **filter IP infra** untuk panel penyerang.
- [ ] 0.3 [GATE] Kunci **MTTR = T2−T0** & **dataset resmi = 30 iterasi**.
- [ ] 0.4 [GATE] Keputusan **threat-score** (perbaiki Transform vs pensiun).
- [ ] 0.5 [GATE] Keputusan **GeoIP** (batasan lab / honeypot-future).
- [ ] 0.6 Konfirmasi **read-only** judul 7 panel `cti-dashboard-main`.
- [ ] 0.7 Verifikasi **backup** terbaru objek Kibana ada (`kibana-cti-backup-*.ndjson`).

## FASE 1 — Fondasi data MTTD/MTTR (additive, tak menyentuh panel)
- [ ] 1.1 Index `iterations.csv` → `cti-mttd-mttr-iqbal` (id=iter; field: attack_type, mttd_s, mttr_s, T0/T1/T2, src_ip, status, @timestamp).
  - Validasi: `count` = 30; agg rata-rata MTTD/MTTR per skenario tampil; tak ada error.
- [ ] 1.2 Buat **data view** `cti-mttd-mttr-iqbal` (time field `@timestamp`).
  - Validasi: data view muncul; Discover menampilkan 30 dok.
- [ ] 1.3 (jika 0.4=perbaiki) Perbaiki Transform threat-score group-by `src_ip.keyword` + filter buang IP infra.
  - Validasi: `cti-threat-score-iqbal` terisi IP penyerang (bukan .1/.10).

## FASE 2 — Kerangka Dashboard Final (dashboard BARU; V3 tetap utuh)
- [ ] 2.1 Buat dashboard baru kosong **"Dashboard Final CTI"**.
- [ ] 2.2 Tambah 3 **markdown panel** sekat: "LAYER 1 …", "LAYER 2 …", "LAYER 3 …".
  - Validasi: dashboard tersimpan; V3 baseline tidak berubah (cek panel V3 tetap 9).

## FASE 3 — Layer 3 (salin panel V3 yang sudah terbukti)
- [ ] 3.1 Tambahkan 8 panel V3 (Technique, Tactic, Timeline, Total Mapped, Pyramid, Validasi Nmap/Hydra/Nikto) **by-reference** ke Dashboard Final.
  - Validasi per panel: tidak "No Results" pada rentang waktu data uji.
- [ ] 3.2 Tambah **salinan** Top Threat Actors → terapkan **filter IP infra** (item #1).
  - Validasi: baris teratas = penyerang asli (mis. .110/.108), bukan .1/.10.

## FASE 4 — Layer 2 (operational)
- [ ] 4.1 Tambah panel operasional terpilih dari `cti-dashboard-main` (Timeline, Top Ports, Top Source IP) — pakai `src_ip`.
- [ ] 4.2 Tambah **N8 Tren MTTD/MTTR** (dari `cti-mttd-mttr-iqbal`).
- [ ] 4.3 Tambah **N9 Ringkasan Insiden Terbaru** (tabel).
- [ ] 4.4 Tambah **N10 Sumber Deteksi NIDS vs HIDS** (GAP-3).
- [ ] 4.5 Tambah **N11 Distribusi Severity**.
  - Validasi tiap panel: tidak "No Results"; field benar.

## FASE 5 — Layer 1 (executive, bahasa awam)
- [ ] 5.1 N1 Status Keamanan · 5.2 N2 Total Serangan · 5.3 N3 Jenis Serangan (label awam) · 5.4 N4 Penyerang Teratas · 5.5 N5 Target · 5.6 N6 Status Penanganan · 5.7 N7 MTTD/MTTR (angka besar) · 5.8 N12 Legenda/Bantuan.
  - Validasi tiap panel: tampil; label awam; angka konsisten dengan L2/L3.

## FASE 6 — Validasi Akhir (Priority 2)
- [ ] 6.1 Tidak ada panel "No Results" pada rentang waktu uji (semua layer).
- [ ] 6.2 Jalankan 3 skenario; pastikan tiap panel berubah sesuai serangan.
- [ ] 6.3 Uji dua-user (non-teknis paham L1; teknis dapat L3).
- [ ] 6.4 Screenshot final tiap layer.
- [ ] 6.5 Verifikasi **V3 baseline masih utuh** (9 panel, tak berubah).
- [ ] 6.6 Export Dashboard Final → `.ndjson` (arsip/replikasi).

## FASE 7 — Di luar dashboard (penentu sidang; dijadwalkan terpisah)
- [ ] 7.1 **Rekonsiliasi naskah↔live** (GAP-6): SID, index, IP, jumlah skenario/iterasi, definisi MTTR, jumlah panel.
- [ ] 7.2 **Rancang & jalankan studi responden** before–after (GAP-1) + kuesioner.
- [ ] 7.3 Hitung **Rasio Agregasi** & **Detection Rate** untuk Bab Hasil.

---
**Tanda tangan persetujuan (pemilik penelitian):** ______  Tanggal: ______
Setelah disetujui, implementasi dimulai dari **FASE 1.1**, satu item per sesi.
