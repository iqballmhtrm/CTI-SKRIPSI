# DESAIN DASHBOARD FINAL — CTI ELK (DESIGN PHASE)

> STATUS: **DESIGN PHASE** — dokumen ini HANYA rancangan. Tidak ada perubahan pada
> dashboard/panel/visualisasi sampai desain ini disetujui. Implementasi nanti
> dilakukan **satu panel per satu waktu** setelah persetujuan.
> Dashboard V3 (`v3-cti-dashboard-final`) ditetapkan sebagai **BASELINE / GROUND TRUTH** dan TIDAK diubah.
> Tanggal: 2026-06-25 · Penyusun: asistensi teknis · Persetujuan: (menunggu)

---

## 1. Tujuan Dashboard
Menyediakan satu antarmuka visual yang **mendukung pengambilan keputusan operasional CTI**
(sesuai judul penelitian), yang:
- Mengubah data log/alert mentah menjadi informasi yang **dapat ditindaklanjuti** dan **mudah dipahami**.
- Menjawab pertanyaan operasional inti dalam satu layar (Zero-Query Visibility): **Apa** yang terjadi, **jenis** serangan, **siapa** penyerang, **siapa** target, **apakah sudah ditangani**, dan **seberapa cepat** (MTTD/MTTR).
- Melayani **dua tipe pengguna** sekaligus melalui pendekatan **berlapis (tiered)**, sehingga non-teknis tidak kewalahan dan teknis tetap mendapat kedalaman analitik.

Prinsip desain (mewarisi prinsip Bab IV): **non-destruktif** (V3 baseline tetap utuh; Dashboard Final dibangun sebagai dashboard BARU yang menggunakan/menyalin panel), **fail-safe** (tidak ada panel "No Results"), **ECS-aware** namun **sesuai realita field live**.

## 2. Target User
| Tipe | Contoh | Kebutuhan | Tidak paham |
|---|---|---|---|
| **Non-Technical** | Dosen penguji, manajemen, operator | Status ringkas, bahasa awam, "apa & siapa", status penanganan | kode `T1046`, `T1110.001`, SID, istilah Pyramid |
| **Technical** | Analis SOC, security engineer | MITRE ATT&CK, Pyramid of Pain, threat actor, timeline, validasi per-SID | — |

## 3. Struktur Dashboard (3 Layer)
Dirancang sebagai alur baca **atas→bawah**: makin ke bawah makin teknis.

- **LAYER 1 — Executive Summary** (untuk non-teknis; bahasa awam, angka besar, status warna)
  - Menjawab: Apa yang terjadi? Jenis serangan? Siapa penyerang/target? Sudah ditangani? Secepat apa?
- **LAYER 2 — Operational Monitoring** (untuk analis harian)
  - Timeline serangan, penyerang & target teratas, volume alert, tabel insiden terbaru, status deteksi↔respons, **MTTD/MTTR**.
- **LAYER 3 — CTI Technical Analysis** (untuk teknis lanjutan = mayoritas panel V3 baseline)
  - MITRE Technique/Tactic distribution, Pyramid of Pain, Top Threat Actors, Validasi per-SID (T1046/T1110.001/T1595.002).

> Catatan UX: bisa diwujudkan sebagai **satu dashboard panjang bersekat** (markdown panel sebagai pemisah layer) ATAU **tiga dashboard tertaut** (drill-down). Rekomendasi: satu dashboard panjang bersekat (paling sederhana untuk sidang, satu layar gulir).

### Tabel terjemahan istilah (komponen kunci Layer 1 untuk non-teknis)
| Kode teknis | Bahasa awam (label panel) |
|---|---|
| T1046 (Nmap) | **Pemindaian Jaringan** (pemetaan port/layanan) |
| T1110.001 (Hydra) | **Serangan Tebak Password** (brute force SSH) |
| T1595.002 (Nikto) | **Pemindaian Kerentanan Web** |
| firewall-drop / active-response | **Otomatis Diblokir** |
| MTTD | **Waktu Deteksi** |
| MTTR | **Waktu Penanganan** |

## 4. Daftar Panel yang DIPERTAHANKAN (dari V3 baseline → Layer 3)
Seluruh 9 panel V3 dipertahankan **apa adanya** di Layer 3 (baseline tidak diubah; di Dashboard Final mereka disalin/di-embed):
1. V3 - MITRE ATT&CK Technique Distribution
2. V3 - MITRE ATT&CK Tactic Distribution
3. V3 - MITRE Alert Timeline by Tactic
4. V3 - Total Mapped MITRE Alerts
5. V3 - Pyramid of Pain Layer Distribution
6. V3 - Validasi Nmap (T1046)
7. V3 - Validasi Hydra (T1110.001)
8. V3 - Validasi Nikto (T1595.002)
9. V3 - Top Threat Actors Table *(dipertahankan, tapi DIUSULKAN dimodifikasi — lihat §5)*

Dari `cti-dashboard-main` (7 panel, **judul persis perlu dikonfirmasi read-only**), kandidat dipertahankan untuk Layer 2: Total Alerts, Attack Volume Timeline, Top Target Ports, Forensic/Detail table, Port Scanning Detection, Top Source IP.

## 5. Daftar Panel yang DIUBAH (usulan)
| Panel | Perubahan diusulkan | Alasan (ringkas) |
|---|---|---|
| **V3 - Top Threat Actors Table** | Tambah filter **buang IP infrastruktur** (`192.168.56.1`, `.10`, `.106`) | Saat ini didominasi IP host/SOC sendiri (.1=639k, .10=438k) → "top threat actor = server sendiri", tidak profesional. Penyerang asli (.110) tertutup. |
| Panel apa pun yang memakai `source.ip` | Ganti ke **`src_ip` / `src_ip.keyword`** | Fakta live: `source.ip` KOSONG; field terisi = `src_ip`. |
| Label panel MITRE (Layer 1 mirror) | Tambah **label bahasa awam** (lihat tabel terjemahan) | Non-teknis tidak paham kode T-number. |

> Catatan: perubahan dilakukan pada **salinan** di Dashboard Final, **bukan** pada V3 baseline.

## 6. Panel BARU yang Direkomendasikan
### Layer 1 — Executive Summary (semua bahasa awam, fitur Basic)
- **N1. Status Keamanan** (Metric/teks besar): "AMAN" / "SEDANG DISERANG" berdasarkan ada/tidak alert dalam rentang waktu.
- **N2. Total Serangan (periode)** (Metric): jumlah alert.
- **N3. Jenis Serangan** (Donut/Bar) — pakai **label awam** (Pemindaian Jaringan / Tebak Password / Pemindaian Web), sumber `data.alert.signature_id` → dipetakan.
- **N4. Penyerang Teratas** (Tabel ringkas): IP penyerang + jumlah (sudah difilter infra IP). *(Geolokasi/negara = N/A di lab IP privat; relevan saat fase honeypot — tandai future.)*
- **N5. Target Diserang** (Tabel/Bar): IP/port target (`dest_ip`/`destination.port`).
- **N6. Status Penanganan** (Metric/Pie): jumlah serangan **Otomatis Diblokir** vs belum (sumber event firewall-drop / `rule.description`).
- **N7. Waktu Deteksi (MTTD) & Waktu Penanganan (MTTR)** (Metric besar): rata-rata, dari index baru `cti-mttd-mttr-iqbal`.

### Layer 2 — Operational Monitoring
- **N8. Tren MTTD/MTTR** (Line/Bar per skenario) dari `cti-mttd-mttr-iqbal`.
- **N9. Ringkasan Insiden Terbaru** (Tabel): waktu, jenis (awam), penyerang, target, status.

> **Dependensi data:** N7/N8 butuh index **`cti-mttd-mttr-iqbal`** (saat ini MTTD/MTTR hanya ada di `iterations.csv`). Pengindeksan = langkah implementasi pertama (lihat §8), bukan sekarang.

## 7. Alasan Setiap Perubahan (justifikasi)
- **Pendekatan 3 layer** → memenuhi kebutuhan dua tipe user tanpa mengorbankan kedalaman teknis; sesuai prinsip Situational Awareness (Endsley: perception→comprehension→projection) yang sudah jadi landasan Bab II.
- **Label bahasa awam** → mengurangi beban kognitif non-teknis (alert fatigue), inti dari "optimisasi visualisasi".
- **Filter IP infrastruktur** → akurasi "Threat Actor" (Pyramid of Pain: fokus indikator yang bermakna, bukan noise internal).
- **MTTD/MTTR di dashboard** → menutup **GAP Pilar 4** (saat ini metrik hanya di CSV) — wajib karena judul menjanjikan MTTD/MTTR.
- **`src_ip` bukan `source.ip`** → menyesuaikan realita field live agar tidak "No Results".
- **Dashboard Final = dashboard baru** → melindungi V3 baseline (ground truth) dari kerusakan; menghindari "terlalu banyak perubahan sekaligus".

## 8. Prioritas Implementasi (satu langkah per satu waktu, setelah disetujui)
0. **(Prasyarat) Konfirmasi read-only** judul 7 panel `cti-dashboard-main`.
1. **Fondasi data**: index `iterations.csv` → `cti-mttd-mttr-iqbal` + buat data view-nya. *(tanpa menyentuh panel)*
2. **Buat dashboard baru kosong** "Dashboard Final CTI" (V3 tetap utuh).
3. **Layer 3**: salin/embed 9 panel V3 (paling cepat, sudah terbukti).
4. **Perbaiki Top Threat Actors** (salinan): filter infra IP.
5. **Layer 2**: tambah N8, N9 + panel operasional terpilih dari main.
6. **Layer 1**: tambah N1–N7 (executive, bahasa awam).
7. **Sekat layer** (markdown panel) + tata letak.
8. **Validasi** (lihat §10).

Setiap nomor = **satu sesi implementasi + satu validasi** sebelum lanjut.

## 9. Risiko Perubahan & Mitigasi
| Risiko | Dampak | Mitigasi |
|---|---|---|
| Mengubah panel V3 baseline | Ground truth rusak | **Bangun dashboard BARU**; V3 read-only. Backup sudah ada (`kibana-cti-backup-*.ndjson`). |
| Data view `cti-logs` dipakai bersama | Edit DV memengaruhi banyak panel | Jangan ubah DV `7afca9a4`; hanya tambah DV baru (mttd). |
| Panel "No Results" saat sidang | Demo gagal | Validasi §10 + panduan rentang waktu + uji dengan serangan segar (P2). |
| Field salah (`source.ip` kosong) | Panel kosong | Pakai `src_ip` (sudah diverifikasi terisi). |
| Geolokasi kosong di lab (IP privat) | Peta kosong | Tunda panel peta ke fase honeypot; di lab pakai tabel IP. |
| Terlalu banyak perubahan sekaligus | Inkonsistensi (kesalahan lama) | **Satu panel per satu waktu + validasi**. |

## 10. Validasi Setelah Implementasi (per panel & akhir)
Per panel:
- [ ] Panel TIDAK "No Results" pada rentang waktu yang mencakup data uji.
- [ ] Field sumber benar (`src_ip`, `data.alert.signature_id`, `mitre.technique_id`, dst).
- [ ] Label sesuai layer (awam untuk L1, teknis untuk L3).

Akhir (Priority 2 — Validation Dashboard):
- [ ] Jalankan **3 skenario** (Nmap/Hydra/Nikto); set time-picker ke rentang uji.
- [ ] Pastikan **setiap panel berubah** sesuai serangan (deteksi muncul, status "Diblokir" berubah, MTTD/MTTR terisi).
- [ ] **Uji dua-user**: non-teknis paham Layer 1 tanpa bertanya; teknis dapat detail di Layer 3.
- [ ] Ambil **screenshot final** tiap layer.
- [ ] V3 baseline diverifikasi **masih utuh** (tidak berubah).

---

## Lampiran A — Pemetaan panel → layer → pilar penelitian
| Panel | Layer | Pilar |
|---|---|---|
| N1 Status, N2 Total, N3 Jenis(awam), N4 Penyerang, N5 Target, N6 Penanganan, N7 MTTD/MTTR | L1 | 1 (visualisasi) + 4 (MTTD/MTTR) |
| Timeline, Top Ports, Top Source IP, N8 Tren MTTD/MTTR, N9 Insiden | L2 | 1 + 3 + 4 |
| MITRE Technique/Tactic/Timeline, Total Mapped, Pyramid, Top Threat Actors, Validasi Nmap/Hydra/Nikto | L3 | 2 (MITRE) + 3 (hybrid) |

## Lampiran B — Catatan realita data (untuk implementasi)
- Field penyerang terisi: **`src_ip` / `src_ip.keyword`** (BUKAN `source.ip`).
- Filter alert Suricata: `event_type.keyword: "alert"`.
- Teknik MITRE: `mitre.technique_id` (mis. T1046/T1110.001/T1595.002), `mitre.tactic`.
- SID: `data.alert.signature_id` (1000010/1000020/1000030).
- IP infrastruktur yang perlu diabaikan di panel "penyerang": `192.168.56.1`, `192.168.56.10`, `192.168.56.106`.
- MTTD/MTTR: belum di ES → butuh index `cti-mttd-mttr-iqbal` (impl langkah 1).
- Geolokasi: kosong untuk IP privat lab → panel peta = fase honeypot (future).
