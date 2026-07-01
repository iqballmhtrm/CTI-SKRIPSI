# PROJECT EXECUTION PLAN — ROADMAP 1: ENGINEERING (Dashboard Final)

> Acuan implementasi tunggal: `06-Dashboard/DESIGN-REVIEW-DAN-CHECKLIST-IMPLEMENTASI.md` (Bagian 2).
> Desain: **LOCKED**. Mode: **IMPLEMENTATION PHASE**. Tidak ada redesign/checklist/review baru.
> Dokumen ini hanya menambahkan **durasi, dependency, output, kriteria selesai, dan titik FREEZE** —
> TIDAK menambah item kerja baru. Satuan durasi = **sesi** (1 sesi = 1 item dikerjakan + divalidasi).
> Tanggal: 2026-06-25 · Peran: Engineering Lead.

---

## 0. Keputusan default yang diadopsi (konfirmasi cepat di FASE 0 — bukan review baru)
Agar tidak membuka review, gerbang desain dikunci dengan default berikut (ubah hanya bila kamu menolak):
- Bentuk: **1 dashboard panjang bersekat** (markdown pemisah layer).
- Panel penyerang: **filter buang IP infra** `192.168.56.1/.10/.106`.
- Metrik: **MTTR = T2−T0**, **dataset resmi = 30 iterasi**.
- Threat-score: **pensiunkan Transform** (karena `source.ip` kosong); keputusan diwakili panel "Penyerang Teratas" + "Status Penanganan". *(hemat waktu; bisa diaktifkan kembali sebagai future work)*
- GeoIP/peta: **dinyatakan batasan lab** (tanpa peta); peta = fase honeypot (Roadmap Research/future).

## 1. Peta Fase Engineering (FASE 0–6 dari checklist)

| Fase | Isi (ringkas) | Durasi | Dependency | Output | Kriteria Selesai (DoD) |
|---|---|---|---|---|---|
| **F0** Prasyarat | Konfirmasi default §0; read-only judul 7 panel `cti-dashboard-main`; verifikasi backup | **1 sesi** | — | Keputusan terkunci; daftar panel main akurat; backup terverifikasi | Semua [GATE] F0 dijawab; backup `kibana-cti-backup-*.ndjson` ada |
| **F1** Fondasi data MTTD/MTTR | Index `iterations.csv`→`cti-mttd-mttr-iqbal`; buat data view | **1 sesi** | F0 | Index 30 dok + data view | `count=30`; agg MTTD/MTTR per skenario tampil; Discover OK |
| **F2** Kerangka dashboard | Buat dashboard baru "Dashboard Final CTI"; 3 markdown sekat | **1 sesi** | F0 (backup) | Dashboard kosong bersekat | Tersimpan; **V3 baseline tetap 9 panel (tak berubah)** |
| **F3** Layer 3 | Salin 8 panel V3 + salinan Top Threat Actors (filter infra) | **1–2 sesi** | F2; V3 utuh | Layer 3 terisi | Tiap panel **tidak "No Results"**; Top Threat Actors tampil penyerang asli |
| **F4** Layer 2 | Timeline, Top Ports, Top Source IP, N8 Tren MTTD/MTTR, N9 Insiden, N10 NIDS/HIDS, N11 Severity | **1–2 sesi** | F1 (utk N8), F2 | Layer 2 terisi | Tiap panel valid & berisi data; field benar (`src_ip`) |
| **F5** Layer 1 | N1–N7 (status, total, jenis-awam, penyerang, target, penanganan, MTTD/MTTR) + N12 legenda | **2 sesi** | F1, F4 | Layer 1 terisi (bahasa awam) | Tiap panel valid; label awam; angka konsisten dgn L2/L3 |
| **F6** Validasi akhir | No "No-Results"; uji 3 skenario; uji dua-user; screenshot; cek V3 utuh; export `.ndjson` | **1–2 sesi** | F3–F5 | Dashboard Final stabil + arsip + screenshot | Semua butir validasi §10 checklist ✓ |

**Estimasi total Engineering: ~8–11 sesi.** (Wall-clock mengikuti ritme kerjamu; tiap sesi 1 item + validasi.)

## 2. Dependency antar fase (ringkas)
```
F0 ──> F1 ──┐
F0 ──> F2 ──┼─> F3 ──┐
            ├─> F4 ──┼─> F5 ──> F6 (FREEZE)
F1 ────────┘         │
F4 ──────────────────┘
```
- F1 & F2 bisa paralel setelah F0 (beda domain: data vs dashboard).
- F3 butuh F2 (dashboard ada) + V3 utuh.
- F4 butuh F2; panel N8 butuh F1.
- F5 butuh F1 (MTTD) + F4 (konsistensi angka).
- F6 butuh F3–F5 selesai.

## 3. Definisi "ENGINEERING FREEZE"
Engineering dinyatakan **FREEZE** ketika SEMUA terpenuhi:
1. F0–F6 selesai (DoD tiap fase ✓).
2. **Tidak ada panel "No Results"** pada rentang waktu uji (semua layer).
3. Uji 3 skenario lulus: tiap panel berubah sesuai serangan.
4. **V3 baseline terverifikasi utuh** (9 panel, tak berubah).
5. Dashboard Final **diekspor** ke `.ndjson` (arsip & replikasi).
6. Screenshot final tiap layer tersimpan.

Setelah FREEZE: **tidak ada perubahan sistem lagi** (dashboard/panel/pipeline/index/transform/SOAR). Perubahan hanya bila ada **bug/blocker** kritis (dengan backup + validasi).

## 4. Transisi ke ROADMAP 2 — RESEARCH (setelah FREEZE)
Peran saya berubah: **Engineering Lead → Research Auditor**. Tidak ada perubahan sistem. Fokus:
- Rekonsiliasi naskah↔live (GAP-6), studi responden before–after (GAP-1), Rasio Agregasi & Detection Rate, Bab IV/V, kuesioner, analisis, kesimpulan.
- (Ini = FASE 7 di checklist + pekerjaan Bab — dijadwalkan saat Roadmap Research, bukan sekarang.)

## 5. Aturan eksekusi (mengikat)
- Kerjakan **berurutan**, **satu item per sesi**, **validasi sebelum lanjut**, **backup sebelum tiap perubahan**.
- Tidak ada item di luar checklist. Tidak ada redesign.
- Setiap awal sesi: sebut item checklist yang dikerjakan + lokasi eksekusi (SOC/victim/attacker).

---
**Titik mulai eksekusi:** FASE 0 (konfirmasi default §0 + read-only panel main + cek backup).
**Persetujuan untuk mulai F0:** ______
