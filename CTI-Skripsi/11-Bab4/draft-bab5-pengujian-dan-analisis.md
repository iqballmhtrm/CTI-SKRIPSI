# Draft Konten Bab 5 — Hasil Pengujian & Analisis Kesesuaian

> Draft akademik untuk diintegrasikan ke naskah skripsi. Seluruh angka MTTD/MTTR/T0/T1/T2
> bersumber dari data riil `~/research-archive/2026-06-21_controlled-run/iterations.csv`
> (30 iterasi terkontrol, dijalankan 2026-06-24). Tidak ada angka yang difabrikasi.
> Catatan: T0/T1/T2 dinyatakan dalam detik Unix epoch (UTC); MTTD = T1 − T0; MTTR = T2 − T0
> (definisi yang dipakai orchestrator; lihat klarifikasi pada Bagian C).

---

## 5.5 Hasil Pengujian Sistem (30 Iterasi Terkontrol)

Pengujian dilakukan secara terkontrol sebanyak 30 iterasi yang terbagi atas tiga skenario
serangan, masing-masing 10 iterasi: pemindaian jaringan (Nmap), serangan brute force SSH
(Hydra), dan pemindaian kerentanan web (Nikto). Setiap iterasi mencatat tiga penanda waktu:
T0 (saat serangan diluncurkan dari mesin penyerang), T1 (saat alert pertama terindeks di
Elasticsearch), dan T2 (saat peristiwa mitigasi *firewall-drop* terindeks). Dari ketiga
penanda tersebut diturunkan dua metrik utama, yaitu *Mean Time To Detect* (MTTD = T1 − T0)
dan *Mean Time To Respond* (MTTR = T2 − T0). Untuk menjamin independensi antar-iterasi,
pemblokiran alamat IP penyerang direset di awal setiap iterasi.

### Tabel 5.x Hasil Pengujian per Iterasi

| Iter | Skenario | SID | T0 (epoch) | T1 (epoch) | T2 (epoch) | MTTD (s) | MTTR (s) | Status |
|----:|--------|-------|-----------:|-----------:|-----------:|--------:|--------:|--------|
| 1  | Nmap  | 1000010 | 1782303972 | 1782303974 | — | 2 | — | Terdeteksi |
| 2  | Nmap  | 1000010 | 1782304132 | 1782304134 | — | 2 | — | Terdeteksi |
| 3  | Nmap  | 1000010 | 1782304293 | 1782304294 | — | 1 | — | Terdeteksi |
| 4  | Nmap  | 1000010 | 1782304648 | 1782304650 | — | 2 | — | Terdeteksi |
| 5  | Nmap  | 1000010 | 1782304816 | 1782304818 | — | 2 | — | Terdeteksi |
| 6  | Nmap  | 1000010 | 1782304981 | 1782304984 | — | 3 | — | Terdeteksi |
| 7  | Nmap  | 1000010 | 1782305144 | 1782305150 | — | 6 | — | Terdeteksi |
| 8  | Nmap  | 1000010 | 1782305316 | 1782305317 | — | 1 | — | Terdeteksi |
| 9  | Nmap  | 1000010 | 1782305484 | 1782305489 | — | 5 | — | Terdeteksi |
| 10 | Nmap  | 1000010 | 1782305655 | 1782305656 | — | 1 | — | Terdeteksi |
| 11 | Hydra | 1000020 | 1782305821 | 1782305822 | 1782305830 | 1 | 9 | Terdeteksi+Mitigasi |
| 12 | Hydra | 1000020 | 1782305991 | 1782305993 | 1782305993 | 2 | 2 | Terdeteksi+Mitigasi |
| 13 | Hydra | 1000020 | 1782306070 | 1782306071 | 1782306079 | 1 | 9 | Terdeteksi+Mitigasi |
| 14 | Hydra | 1000020 | 1782306149 | 1782306150 | 1782306151 | 1 | 2 | Terdeteksi+Mitigasi |
| 15 | Hydra | 1000020 | 1782306229 | 1782306230 | 1782306237 | 1 | 8 | Terdeteksi+Mitigasi |
| 16 | Hydra | 1000020 | 1782306321 | 1782306323 | 1782306323 | 2 | 2 | Terdeteksi+Mitigasi |
| 17 | Hydra | 1000020 | 1782306405 | 1782306406 | 1782306409 | 1 | 4 | Terdeteksi+Mitigasi |
| 18 | Hydra | 1000020 | 1782306486 | 1782306488 | 1782306489 | 2 | 3 | Terdeteksi+Mitigasi |
| 19 | Hydra | 1000020 | 1782306571 | 1782306572 | 1782306577 | 1 | 6 | Terdeteksi+Mitigasi |
| 20 | Hydra | 1000020 | 1782306659 | 1782306663 | 1782306667 | 4 | 8 | Terdeteksi+Mitigasi |
| 21 | Nikto | 1000030 | 1782306739 | 1782306741 | 1782306742 | 2 | 3 | Terdeteksi+Mitigasi |
| 22 | Nikto | 1000030 | 1782307246 | 1782307249 | 1782307249 | 3 | 3 | Terdeteksi+Mitigasi |
| 23 | Nikto | 1000030 | 1782307736 | 1782307737 | 1782307738 | 1 | 2 | Terdeteksi+Mitigasi |
| 24 | Nikto | 1000030 | 1782308222 | 1782308226 | 1782308226 | 4 | 4 | Terdeteksi+Mitigasi |
| 25 | Nikto | 1000030 | 1782308709 | 1782308711 | 1782308712 | 2 | 3 | Terdeteksi+Mitigasi |
| 26 | Nikto | 1000030 | 1782309198 | 1782309200 | 1782309201 | 2 | 3 | Terdeteksi+Mitigasi |
| 27 | Nikto | 1000030 | 1782309687 | 1782309690 | 1782309690 | 3 | 3 | Terdeteksi+Mitigasi |
| 28 | Nikto | 1000030 | 1782310094 | 1782310096 | 1782310097 | 2 | 3 | Terdeteksi+Mitigasi |
| 29 | Nikto | 1000030 | 1782310581 | 1782310582 | 1782310584 | 1 | 3 | Terdeteksi+Mitigasi |
| 30 | Nikto | 1000030 | 1782311072 | 1782311074 | 1782311076 | 2 | 4 | Terdeteksi+Mitigasi |

Seluruh 30 iterasi berhasil terdeteksi (tingkat deteksi 100%, tanpa *false negative*).

### Tabel 5.y Rekapitulasi MTTD dan MTTR per Skenario

| Skenario | MITRE | n | MTTD rata² (s) | MTTD min–max | MTTD σ | MTTR rata² (s) | MTTR min–max | MTTR σ |
|--------|-------|--:|--------------:|:-----------:|------:|--------------:|:-----------:|------:|
| Nmap  | T1046     | 10 | 2,5 | 1 – 6 | 1,72 | — (tidak ada) | — | — |
| Hydra | T1110     | 10 | 1,6 | 1 – 4 | 0,92 | 5,3 | 2 – 9 | 3,00 |
| Nikto | T1595.002 | 10 | 2,2 | 1 – 4 | 0,92 | 3,1 | 2 – 4 | 0,57 |

Keterangan: σ = simpangan baku sampel. Nilai rata-rata dihitung dari 10 iterasi tiap skenario.

### Analisis Hasil

Berdasarkan Tabel 5.y, sistem menunjukkan kemampuan deteksi yang sangat cepat dan konsisten
pada ketiga skenario, dengan MTTD rata-rata berkisar 1,6–2,5 detik. MTTD terendah dicapai
skenario Hydra (1,6 detik), sedangkan Nmap memiliki MTTD rata-rata tertinggi (2,5 detik)
dengan variasi paling besar (σ = 1,72 detik), yang disebabkan oleh sifat pemindaian SYN yang
memerlukan akumulasi paket hingga ambang *threshold* terpenuhi.

Pada aspek respons, mitigasi otomatis hanya tercatat pada skenario Hydra (MTTR rata-rata
5,3 detik) dan Nikto (MTTR rata-rata 3,1 detik). Kedua skenario tersebut memicu *active
response* pada Wazuh sehingga alamat IP penyerang diblokir melalui *firewall-drop*. Nilai
MTTR Hydra cenderung lebih bervariasi (σ = 3,00 detik) karena mekanisme deteksi *brute force*
(rule Wazuh 5763) memerlukan akumulasi sejumlah kegagalan autentikasi sebelum *active
response* dipicu, sedangkan MTTR Nikto lebih stabil (σ = 0,57 detik).

### Penjelasan Ketiadaan MTTR pada Skenario Nmap

Skenario Nmap tidak memiliki nilai MTTR, dan hal ini terjadi **secara sengaja sesuai
rancangan (by design)**, bukan akibat kegagalan sistem. Pemindaian Nmap merupakan aktivitas
*reconnaissance* murni pada lapisan jaringan: penyerang hanya mengirim paket SYN untuk
memetakan *port* terbuka tanpa berinteraksi dengan layanan pada *host* korban. Akibatnya,
aktivitas ini hanya terlihat oleh sensor jaringan (Suricata) dan tidak menghasilkan jejak
pada *log* tingkat *host* (auth.log maupun *log* akses web) yang dipantau oleh Wazuh.

Mekanisme *active response* (firewall-drop) pada sistem ini dipicu oleh *rule* HIDS Wazuh —
yaitu *rule* 5763 untuk *brute force* SSH dan *rule* 31151 untuk banjir kode kesalahan HTTP
400 (Nikto). Karena Nmap tidak memicu *rule* HIDS apa pun, tidak ada *active response* yang
dijalankan, sehingga T2 tidak terbentuk dan MTTR tidak dapat dihitung. Perilaku ini justru
mengonfirmasi kebenaran logika sistem: respons otomatis hanya diberikan terhadap serangan
yang berinteraksi langsung dengan layanan korban dan berpotensi menimbulkan dampak (brute
force dan pemindaian kerentanan web), sedangkan aktivitas *reconnaissance* pasif cukup
didokumentasikan sebagai *alert* untuk keperluan analisis intelijen ancaman tanpa pemblokiran
otomatis. Dalam konteks operasional SOC, status "terdeteksi tanpa mitigasi otomatis" pada
Nmap merupakan keluaran yang sah dan dapat dipertanggungjawabkan.

---

## 5.6 Analisis Kesesuaian Implementasi terhadap Rancangan

Secara arsitektural, implementasi sistem telah sesuai dengan rancangan konseptual: deteksi
hibrida (Suricata NIDS + Wazuh HIDS), *pipeline* Logstash lima tahap (Drop Stats → GeoIP →
MITRE Enricher → Pyramid Classifier → keluaran Elasticsearch), pengayaan MITRE ATT&CK,
penyimpanan dan visualisasi pada Elasticsearch/Kibana, serta pengukuran MTTD dan MTTR.
Namun, selama proses implementasi terdapat sejumlah penyesuaian terhadap rancangan awal yang
dilakukan atas dasar pertimbangan teknis. Ringkasan penyesuaian disajikan berikut.

### Ringkasan Sembilan Penyesuaian terhadap Rancangan Awal

1. Model respons diubah dari semi-otomatis (*one-click* SOAR) menjadi **otomatis** (Wazuh *active response*).
2. Sumber *webhook* SOAR berasal dari **Logstash langsung**, bukan dari Kibana Alerting.
3. Definisi **MTTR** menggunakan **T2 − T0** (bukan T2 − T1 sebagaimana rancangan awal).
4. Deteksi Nikto menggunakan **pendekatan perilaku** (laju permintaan HTTP), bukan tanda tangan *User-Agent*.
5. Cakupan skenario difokuskan pada **tiga skenario** (Nmap, Hydra, Nikto); skenario *Lateral Movement* (T1021) dan *Exfiltration* (T1041) belum diimplementasikan.
6. Perhitungan MTTD/MTTR dilakukan melalui **skrip orkestrasi** (curl + Bash), bukan kueri ES|QL.
7. Pengayaan MITRE dilakukan pada **Logstash** (filter `translate`), bukan pada *Ingest Pipeline* Elasticsearch.
8. Penamaan indeks memakai **`cti-logs-iqbal-*`** (bukan `soc-alerts-*`).
9. Penyelarasan pemetaan MITRE Nikto pada **T1595.002** (*Active Scanning*).

Penyesuaian nomor 4–9 bersifat teknis/penamaan dan tidak mengubah substansi pencapaian
keempat pilar penelitian. Tiga penyesuaian pertama bersifat substantif dan dijelaskan secara
khusus pada subbagian berikut.

### Justifikasi Tiga Penyesuaian Substantif

**(1) Respons otomatis (Wazuh active response) menggantikan respons one-click SOAR.**
Rancangan awal memosisikan SOAR sebagai pusat respons dengan intervensi manual analis melalui
tombol *Block IP*. Pada implementasi, fungsi respons utama dialihkan ke mekanisme *active
response* bawaan Wazuh yang menjalankan *firewall-drop* secara otomatis ketika *rule* HIDS
terpenuhi. Penyesuaian ini dilandasi tiga pertimbangan. Pertama, dari sudut pandang efektivitas
keamanan, respons otomatis menghilangkan ketergantungan pada waktu reaksi manusia sehingga
menekan jendela waktu serangan secara signifikan; hal ini tercermin pada MTTR yang konsisten di
bawah sepuluh detik. Kedua, mekanisme ini lebih merepresentasikan praktik SOC modern yang
mengarah pada otomasi respons (*Security Orchestration, Automation, and Response*). Ketiga,
antarmuka SOAR tetap dipertahankan sebagai sarana pemantauan insiden dan opsi respons manual,
sehingga kapabilitas rancangan awal tidak hilang melainkan dilengkapi. Dengan demikian,
penyesuaian ini memperkuat, bukan mengurangi, nilai penelitian.

**(2) Webhook SOAR dikirim langsung dari Logstash, bukan melalui Kibana Alerting.**
Rancangan awal mengarahkan integrasi SOAR melalui *connector webhook* pada Kibana Alerting.
Pada implementasi, notifikasi insiden dikirim langsung dari keluaran HTTP Logstash ke
*endpoint* `/webhook` SOAR. Pertimbangan utamanya adalah pengurangan latensi dan kompleksitas:
mekanisme Kibana Alerting bekerja berbasis penjadwalan kueri periodik (misalnya setiap satu
menit) yang menambahkan jeda struktural antara kemunculan *alert* dan notifikasi, sedangkan
pengiriman langsung dari Logstash bersifat *event-driven* sehingga insiden tercatat di SOAR
nyaris seketika pada saat *event* diproses. Penyesuaian ini selaras dengan tujuan penelitian
untuk meminimalkan waktu deteksi-ke-pencatatan dan menyederhanakan rantai integrasi tanpa
mengorbankan akurasi data insiden.

**(3) Definisi MTTR menggunakan T2 − T0 (peluncuran serangan hingga mitigasi).**
Rancangan awal mendefinisikan MTTR sebagai selisih waktu antara terdeteksinya serangan dan
dilakukannya respons (T2 − T1). Pada implementasi, MTTR diukur sebagai selisih antara
peluncuran serangan dan termitigasinya serangan (T2 − T0). Pertimbangannya adalah bahwa
T2 − T0 merepresentasikan **waktu tanggap total** yang dialami sistem dari sudut pandang
korban, yaitu durasi keseluruhan sejak serangan dimulai hingga ancaman dinetralkan, sehingga
lebih bermakna sebagai indikator perlindungan menyeluruh. Definisi ini juga konsisten dengan
cara MTTD diukur (T1 − T0), sehingga kedua metrik berbagi titik acuan awal yang sama (T0) dan
dapat dibandingkan secara langsung. Perlu ditekankan bahwa seluruh penanda waktu (T0, T1, T2)
terekam utuh pada berkas data, sehingga MTTR menurut definisi rancangan awal (T2 − T1) tetap
dapat dihitung ulang apabila diperlukan untuk pembanding (lihat Bagian C).

---

## C. Klarifikasi dan Konsistensi Definisi MTTR pada Naskah

### Temuan pemeriksaan

Pemeriksaan terhadap sumber-sumber dalam repositori menunjukkan adanya **dua definisi MTTR**
yang berbeda:

| Sumber | Definisi MTTD | Definisi MTTR | Acuan |
|--------|---------------|---------------|-------|
| Orchestrator `run_controlled_iterations.sh` & `iterations.csv` (sumber Tabel 4.8/5.x) | T1 − T0 | **T2 − T0** | komentar skrip: "MTTR = T2 - T0 (Tabel 4.8 naskah)" |
| `MASTER_PROMPT_CTI_ELK.md` (Fase 4A, skema SOAR) | timestamp_detected − timestamp_attack (= T1 − T0) | **timestamp_responded − timestamp_detected (= T2 − T1)** | definisi field `mttr_seconds` |
| `AUDIT_REPORT_GROUND_TRUTH.md` (skema `soar_app.py`) | T1 − T0 | **T2 − T1** | kolom `mttr_seconds` |

Dengan demikian, **MTTD konsisten** di seluruh sumber (T1 − T0), tetapi **MTTR tidak
konsisten**: data hasil (Tabel 5.x) memakai T2 − T0, sedangkan aplikasi SOAR dan dokumen
konsep memakai T2 − T1.

### Status Bab III dan Bab IV

- **Bab III — `10-Bab3/perancangan.md`**: pada sumber Markdown yang dapat diperiksa, **tidak
  ditemukan rumus eksplisit MTTR** (T2 − T0 maupun T2 − T1). Dokumen ini hanya memuat desain
  *rule* deteksi dan pemetaan MITRE. Definisi formal MTTR kemungkinan berada di berkas
  `Bab3.docx` (format biner) yang tidak dapat diperiksa otomatis.
- **Bab IV — `11-Bab4/implementasi_dan_pengujian.md` dan `laporan_implementasi_lengkap.md`**:
  pada sumber Markdown yang dapat diperiksa, **tidak ditemukan rumus eksplisit MTTR**. Definisi
  formal kemungkinan berada di `Bab4.docx` (format biner).

> Catatan keterbatasan: berkas `.docx` Bab III dan Bab IV berformat biner dan tidak dapat
> dibaca otomatis pada sesi ini. Verifikasi akhir pada kedua `.docx` perlu dilakukan manual.

### Lokasi yang perlu diperiksa/diselaraskan secara manual

Karena rumus MTTR pada naskah utama berada di `.docx`, periksa manual bagian-bagian berikut:

1. **`10-Bab3/Bab3.docx`** — subbab Metodologi/Definisi Operasional Variabel: cari rumus
   "MTTR = ...". Pastikan tertulis **T2 − T0** (sesuai data) atau, bila dipertahankan T2 − T1,
   data harus dihitung ulang.
2. **`11-Bab4/Bab4.docx`** — subbab pengujian/hasil yang memuat definisi atau keterangan kolom
   tabel MTTR.
3. **Sumber yang sudah pasti memakai T2 − T1 dan perlu diselaraskan bila naskah final memilih T2 − T0:**
   - `15-Project-Governance/prompts/MASTER_PROMPT_CTI_ELK.md`, baris pada Tugas 4A:
     `Field mttr_seconds: dihitung otomatis = timestamp_responded - timestamp_detected`.
   - `AUDIT_REPORT_GROUND_TRUTH.md`, deskripsi kolom `mttr_seconds` (skema `soar_app.py`).
   - Implementasi `soar_app.py` (kolom `mttr_seconds`) — jika SOAR ikut dipakai sebagai sumber
     metrik dalam naskah, perhitungannya perlu disamakan dengan definisi final.

### Rekomendasi

Pilih **satu** definisi MTTR dan terapkan konsisten di seluruh naskah:

- **Opsi A (disarankan, sesuai data Tabel 5.x):** MTTR = **T2 − T0**. Keunggulan: tidak perlu
  menghitung ulang data; konsisten dengan acuan T0 yang sama dengan MTTD; bermakna sebagai
  waktu tanggap total. Tindakan: selaraskan definisi pada `MASTER_PROMPT`, `AUDIT_REPORT`, dan
  keterangan SOAR agar memakai T2 − T0.
- **Opsi B (sesuai konsep awal):** MTTR = **T2 − T1**. Konsekuensi: nilai MTTR pada tabel perlu
  dihitung ulang (data tersedia karena T0/T1/T2 terekam). Sebagai referensi, MTTR (T2 − T1)
  hasil hitung ulang adalah **Hydra rata-rata 3,7 detik** dan **Nikto rata-rata 0,9 detik**.

Apa pun opsi yang dipilih, definisi tersebut harus dinyatakan eksplisit pada Bab III
(Definisi Operasional) dan dirujuk konsisten pada Bab IV/V.

---

## D. Catatan Tambahan — Inkonsistensi Spesifikasi Rule pada Bab III

Selain MTTR, pemeriksaan `10-Bab3/perancangan.md` menemukan spesifikasi *rule* yang **tidak
lagi sesuai** dengan implementasi final (perlu diperbarui di naskah agar konsisten):

| Item | Tertulis di `perancangan.md` | Implementasi final | Tindakan |
|------|------------------------------|--------------------|----------|
| Hydra SSH | "10 percobaan koneksi SSH dalam 10 detik" | `threshold count 5, seconds 60` (sid 1000020 rev:2) | perbarui angka ambang |
| Nikto | "Mendeteksi string `Nikto` pada User-Agent" | deteksi perilaku `threshold count 20, seconds 10` (sid 1000030 rev:3) | perbarui metode deteksi + justifikasi evasion UA |
| Nmap | "50 paket SYN dalam 5 detik" | `threshold count 50, seconds 5` (sid 1000010) | sudah sesuai |

Pembaruan ini penting agar Bab III (Perancangan) selaras dengan Bab IV/V (Implementasi & Hasil).
