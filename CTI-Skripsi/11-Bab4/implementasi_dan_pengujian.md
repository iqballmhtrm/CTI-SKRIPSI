# BAB 4 — IMPLEMENTASI DAN PENGUJIAN

## 4.1 Lingkungan Implementasi

Implementasi sistem CTI Dashboard dibangun dalam lingkungan laboratorium tervirtualisasi
menggunakan VirtualBox dengan jaringan *host-only* `192.168.56.0/24`. Tiga *virtual machine*
membentuk topologi penelitian sebagai berikut.

**Tabel 4.1 — Spesifikasi Node Implementasi**

| Node | IP | User | Peran | Layanan Utama |
|------|-----|------|-------|---------------|
| SOC-SERVER | 192.168.56.10 | iqbal | Pusat Operasi Keamanan | Elasticsearch 8.19.12, Logstash, Kibana, Wazuh Manager, SOAR Dashboard |
| VICTIM-NODE | 192.168.56.106 | korban | Target yang Dipantau | Suricata 8.0.3 (NIDS), Wazuh Agent (HIDS), Filebeat |
| ATTACKER-NODE | 192.168.56.110 | kali | Mesin Penyerang | Nmap, Hydra, Nikto |

Alur data sistem mengikuti urutan berikut:

```
ATTACKER (192.168.56.110) — Nmap / Hydra / Nikto
      ↓
VICTIM (192.168.56.106) — Sensor Hybrid
   ├─ Suricata 8.0.3 (NIDS) → eve.json
   └─ Wazuh Agent (HIDS) → active-responses.log + Wazuh Manager
      ↓ Filebeat → Logstash :5044
SOC (192.168.56.10)
   ├─ Logstash: MITRE Enricher + Pyramid Classifier + SOAR Normalization
   ├─ Elasticsearch: cti-logs-iqbal-*
   ├─ Kibana: CTI Dashboard
   └─ SOAR Dashboard (Flask :5000)
```

---

## 4.2 Implementasi Sistem Deteksi Hybrid

### 4.2.1 Suricata NIDS (VICTIM-NODE)

Suricata 8.0.3 dikonfigurasi pada VICTIM-NODE untuk memantau antarmuka jaringan `enp0s8`
(jaringan *host-only*). Tiga *custom rule* berbasis ambang (*threshold*) dideploy ke
`/var/lib/suricata/rules/custom.rules` untuk mendeteksi tiga skenario penelitian.

**Tabel 4.2 — Custom Rule Suricata**

| SID | Nama Alert | Ambang Deteksi | Teknik MITRE | Rev |
|-----|-----------|----------------|--------------|-----|
| 1000010 | [CTI] Nmap SYN Stealth Scan Detected | 50 SYN paket / 5 detik, *stateless* | T1046 | 1 |
| 1000020 | [CTI] Hydra SSH Brute Force Attempt | 5 koneksi TCP / 60 detik, port 22 | T1110.001 | 2 |
| 1000030 | [CTI] Nikto Web Vulnerability Scan Detected | 20 permintaan HTTP / 10 detik, *behavioral* | T1595.002 | 3 |

SID 1000020 (Hydra) direvisi dari ambang awal `10 koneksi/10 detik` menjadi `5 koneksi/60 detik`
(rev:2) karena ambang awal terlalu ketat — Hydra mengirimkan ~17–20 percobaan per menit sehingga
tidak selalu melampaui 10 koneksi dalam jendela 10 detik. SID 1000030 (Nikto) direvisi dari
pencocokan *User-Agent* menjadi ambang berbasis perilaku (rev:3) karena Nikto mampu menyamarkan
*User-Agent* sebagai peramban umum, sehingga deteksi berbasis konten *header* tidak andal terhadap
teknik penghindaran tersebut.

### 4.2.2 Wazuh HIDS + Active Response (VICTIM-NODE)

Wazuh Agent dikonfigurasi pada VICTIM-NODE dengan Wazuh Manager di SOC-SERVER. Dua *rule* HIDS
memicu *active response* (firewall-drop) secara otomatis:

- **Rule 5763** — mendeteksi pola *brute force* SSH pada `auth.log` → memblokir IP penyerang via
  `iptables DROP` ketika Hydra melewati ambang kegagalan autentikasi.
- **Rule 31151** — mendeteksi banjir kode HTTP 400 (*Multiple web server 400 error codes*, level 10)
  → memblokir IP penyerang ketika Nikto menghasilkan banyak respons kesalahan dari aplikasi web.

Skenario Nmap tidak memicu *rule* HIDS karena *port scan* murni tidak berinteraksi dengan layanan
di *host* korban, sehingga tidak ada *active response* yang dijalankan. Perilaku ini merupakan
rancangan yang disengaja (*by design*), bukan kegagalan sistem.

SOC-SERVER dan VICTIM-NODE di-*whitelist* di `ossec.conf` untuk mencegah blokir-diri (*self-block*)
akibat trafik manajemen SSH yang wajar antara node-node lab.

---

## 4.3 Implementasi Pipeline Pengayaan Intelijen (Logstash)

Pipeline Logstash (`/etc/logstash/conf.d/soc-pipeline.conf`) menjalankan tahap-tahap transformasi
pada setiap *security event* yang masuk melalui port 5044:

1. **Time Parser** — standarisasi `@timestamp` ke ISO8601.
2. **Wazuh & Suricata JSON Parser** — penguraian *nested* JSON dari kedua sensor.
3. **Wazuh Active-Response Block** — menangkap event `firewall-drop` dari `active-responses.log`
   (label `log_type: wazuh-ar`), mengekstrak waktu eksekusi blokir sebagai `@timestamp` (T2/MTTR).
   Event ini tidak memicu webhook SOAR.
4. **Drop Suricata Stats** — membuang event bertipe `stats` untuk mengurangi *noise*.
5. **Ensure Source IP** — normalisasi field `source.ip` dari berbagai sumber field.
6. **GeoIP Enrichment** — penambahan atribut geolokasi berdasarkan IP sumber.
7. **Drop STREAM Noise** — membuang alert Suricata bertipe "STREAM" dari trafik manajemen.
8. **NORMALIZE** — penyalinan `alert.* → data.alert.*` untuk konsistensi query orkestrator.
9. **Extract Signature ID** — ekstraksi `data.alert.signature_id` dari berbagai jalur field
   (fallback 4-path untuk kompatibilitas format Filebeat SOC dan Filebeat Victim).
10. **MITRE ATT&CK Enricher** — translasi SID → `mitre.technique_id` (via `mitre-mapping.yml`)
    → `mitre.technique_name` (via `mitre-id-to-name.yml`).
11. **Pyramid of Pain Classifier** — klasifikasi ke lapisan TTPs, Tools, atau IP_Address
    berdasarkan ketersediaan pengayaan MITRE.
12. **SOAR Normalization + Webhook** — normalisasi field untuk antarmuka SOAR dan pengiriman
    *event-driven* ke endpoint `/webhook` SOAR (Flask :5000).

Seluruh event tersimpan ke indeks `cti-logs-iqbal-%{+YYYY.MM.dd}` di Elasticsearch.

**Tabel 4.3 — Pemetaan SID ke MITRE ATT&CK**

| SID | Technique ID | Technique Name | Taktik |
|-----|-------------|----------------|--------|
| 1000010 | T1046 | Network Service Scanning | Discovery |
| 1000020 | T1110.001 | Brute Force: Password Guessing | Credential Access |
| 1000030 | T1595.002 | Active Reconnaissance: Vulnerability Scanning | Reconnaissance |

---

## 4.4 Implementasi SOAR Dashboard

SOAR Dashboard diimplementasikan sebagai aplikasi web Flask yang berjalan di SOC-SERVER pada
port 5000, menggunakan SQLite sebagai basis data insiden (`incidents.db`). Setiap insiden
mencatat atribut `timestamp_alert`, `src_ip`, `attack_type`, `severity`, `mitre_technique`,
dan `mitre_status`.

Notifikasi insiden dikirim langsung dari keluaran HTTP Logstash ke endpoint `/webhook` SOAR
secara *event-driven* — tidak bergantung pada penjadwalan periodik Kibana Alerting. Pendekatan
ini menghilangkan jeda struktural (misalnya interval satu menit pada Kibana Alerting) sehingga
insiden tercatat di SOAR nyaris seketika pada saat *event* diproses pipeline.

---

## 4.5 Implementasi Visualisasi Kibana CTI Dashboard

Dashboard CTI Kibana dengan ID `dashboard-final-cti` dibangun di atas indeks `cti-logs-iqbal-*`
dan terdiri dari 21 panel yang diorganisasikan dalam lima lapisan analisis berurutan.

**Tabel 4.6 — Inventaris Panel Dashboard CTI (21 Panel)**

| No | ID Panel | Tipe | Lapisan | Konten Visualisasi |
|---:|----------|------|---------|-------------------|
| 1 | `cti-dashboard-title` | Markdown | Header | Judul dan identitas penelitian |
| 2 | `v3-mttd-metric` | Metric | Layer 1: KPI | Rata-rata MTTD (avg 2,0 s) |
| 3 | `v3-mttr-metric` | Metric | Layer 1: KPI | Rata-rata MTTR (avg 4,2 s) |
| 4 | `cti-kpi-total-alerts` | Metric | Layer 1: KPI | Total alert masuk |
| 5 | `cti-kpi-unique-ip` | Metric | Layer 1: KPI | Jumlah IP penyerang unik |
| 6 | `cti-kpi-mapped-mitre` | Metric | Layer 1: KPI | Persentase alert ter-*mapping* MITRE |
| 7 | `cti-kpi-active-sources` | Metric | Layer 1: KPI | Jumlah sumber serangan aktif |
| 8 | `cti-divider-l2` | Markdown | Divider | Pemisah lapisan Layer 2 |
| 9 | `cti-alert-timeline-all` | Area Chart | Layer 2: Timeline | *Timeline* frekuensi alert per taktik MITRE |
| 10 | `cti-divider-l3` | Markdown | Divider | Pemisah lapisan Layer 3 |
| 11 | `cti-mitre-technique-bar` | Bar Chart | Layer 3: MITRE | Distribusi teknik ATT&CK per SID |
| 12 | `v3-pyramid-layer-bar` | Bar Chart | Layer 3: Pyramid | Distribusi lapisan Pyramid of Pain |
| 13 | `cti-validation-combined-bar` | Bar Chart | Layer 3: Validasi | Perbandingan MTTD/MTTR antar skenario |
| 14 | `cti-divider-l4` | Markdown | Divider | Pemisah lapisan Layer 4 |
| 15 | `v3-threat-score-table` | Data Table | Layer 4: Intelijen | Tabel ancaman berperingkat (*Threat Score*) |
| 16 | `cti-mttd-mttr-benchmark-bar` | Bar Chart | Layer 4: Intelijen | Benchmark MTTD & MTTR per iterasi |
| 17 | `cti-soar-divider` | Markdown | Divider | Pemisah SOAR Response |
| 18 | `cti-soar-research-count` | Metric | SOAR | Jumlah insiden SOAR penelitian |
| 19 | `cti-soar-action-bar` | Bar Chart | SOAR | Distribusi tindakan respons SOAR |
| 20 | `cti-map-divider` | Markdown | Divider | Pemisah Layer 5 (Dari Mana?) |
| 21 | `cti-attack-origin-map` | **Kibana Maps** | Layer 5: Geo | *Attack Origin Map*: sebaran geografis sumber serangan |

Panel ke-21 (`cti-attack-origin-map`) menggunakan tipe objek `map` dari Kibana Maps,
bukan tipe `visualization` biasa. Peta ini menampilkan titik serangan dari IP publik
eksternal yang diperoleh dari proses *GeoIP enrichment* Logstash pada field `source.geo.location`.
Dalam data penelitian, terdapat 36 dokumen dengan koordinat GeoIP valid: 20 dari Amerika Serikat
dan 16 dari Singapura — trafik eksternal yang masuk ke VICTIM-NODE sebelum jaringan
*host-only* dikunci. Peta menggunakan basemap EMS (Elastic Maps Service) dengan layer
dokumen ES jenis `GEOJSON_VECTOR` pada field `source.geo.location`.

Lima *saved search* Discover tersedia sebagai pendukung investigasi ad-hoc:
`discover-all-alerts`, `discover-nmap-only`, `discover-hydra-only`, `discover-nikto-only`,
dan `discover-mitre-mapped`.

---

## 4.6 Pengujian: 30 Iterasi Terkontrol

### 4.6.1 Protokol Pengujian

Pengujian dilaksanakan dalam 30 iterasi terkontrol: 10 iterasi per skenario (Nmap, Hydra,
Nikto). Skenario dieksekusi berurutan: Nmap (iterasi 1–10) → Hydra (iterasi 11–20) →
Nikto (iterasi 21–30), menggunakan skrip orkestrasi `run_controlled_iterations.sh`.

Untuk menjamin independensi antar-iterasi, blokir IP penyerang (192.168.56.110) di iptables
VICTIM-NODE di-*reset* di awal setiap iterasi menggunakan skrip `cti-unblock.sh`. Tiga
penanda waktu direkam per iterasi:

| Simbol | Definisi |
|--------|----------|
| T0 | Waktu peluncuran serangan dari ATTACKER-NODE |
| T1 | Waktu alert pertama terindeks di Elasticsearch |
| T2 | Waktu event firewall-drop (Wazuh active response) terindeks |

**MTTD = T1 − T0** (detik sejak serangan hingga deteksi pertama di Elasticsearch)
**MTTR = T2 − T0** (detik sejak serangan hingga mitigasi otomatis teraplikasi)

### 4.6.2 Hasil Pengujian per Iterasi

**Tabel 4.4 — Hasil Pengujian 30 Iterasi Terkontrol**

| Iter | Skenario | SID | T0 (epoch) | T1 (epoch) | T2 (epoch) | MTTD (s) | MTTR (s) | Status |
|-----:|----------|-----|-----------:|-----------:|-----------:|--------:|--------:|--------|
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

Sumber: `~/research-archive/2026-06-21_controlled-run/iterations.csv` (dijalankan 2026-06-24).
Seluruh 30 iterasi berhasil terdeteksi (tingkat deteksi 100%, tanpa *false negative*).

### 4.6.3 Rekapitulasi MTTD dan MTTR

**Tabel 4.5 — Rekapitulasi MTTD dan MTTR per Skenario**

| Skenario | MITRE | n | MTTD rata² (s) | MTTD min–max | MTTD σ | MTTR rata² (s) | MTTR min–max | MTTR σ |
|----------|-------|--:|---------------:|:------------:|-------:|---------------:|:------------:|-------:|
| Nmap  | T1046     | 10 | 2,5 | 1 – 6 | 1,72 | — (tidak ada) | — | — |
| Hydra | T1110.001 | 10 | 1,6 | 1 – 4 | 0,92 | 5,3 | 2 – 9 | 3,00 |
| Nikto | T1595.002 | 10 | 2,2 | 1 – 4 | 0,92 | 3,1 | 2 – 4 | 0,57 |

Keterangan: σ = simpangan baku sampel. Nilai rata-rata dihitung dari 10 iterasi tiap skenario.

### 4.6.4 Ketiadaan MTTR pada Skenario Nmap

Skenario Nmap tidak menghasilkan nilai MTTR. Hal ini merupakan **hasil yang disengaja sesuai
rancangan (*by design*)**, bukan kegagalan sistem. Pemindaian Nmap merupakan aktivitas
*reconnaissance* murni pada lapisan jaringan — penyerang hanya mengirim paket SYN untuk memetakan
*port* terbuka tanpa berinteraksi dengan layanan di *host* korban. Akibatnya, aktivitas ini hanya
terdeteksi oleh Suricata (sensor jaringan) dan tidak menghasilkan jejak pada log tingkat *host*
yang dipantau Wazuh (`auth.log` maupun log akses web). Tanpa pemicu *rule* HIDS, tidak ada
*active response* yang dijalankan dan T2 tidak terbentuk.

Perilaku ini mengonfirmasi kebenaran logika sistem: *active response* (firewall-drop) hanya
diberikan terhadap serangan yang berinteraksi langsung dengan layanan korban — *brute force* SSH
(Wazuh rule 5763) dan pemindaian kerentanan web (Wazuh rule 31151) — sedangkan *reconnaissance*
jaringan cukup didokumentasikan sebagai *alert* untuk keperluan analisis intelijen ancaman.

---

## 4.7 Penyesuaian Implementasi terhadap Rancangan Awal

Selama implementasi terdapat sembilan penyesuaian terhadap rancangan awal. Tiga penyesuaian
pertama bersifat substantif dan dijelaskan berikut.

**(1) Respons otomatis (Wazuh active response) menggantikan respons one-click SOAR.**
Rancangan awal memosisikan SOAR sebagai pusat respons dengan intervensi manual analis. Pada
implementasi, fungsi respons utama dialihkan ke mekanisme *active response* bawaan Wazuh yang
menjalankan *firewall-drop* secara otomatis ketika *rule* HIDS terpenuhi. SOAR tetap dipertahankan
sebagai antarmuka pemantauan insiden dan opsi respons manual. Penyesuaian ini menekan *window*
kerentanan secara signifikan, tercermin pada MTTR yang konsisten di bawah sepuluh detik.

**(2) Webhook SOAR dikirim langsung dari Logstash, bukan dari Kibana Alerting.**
Logstash HTTP output mengirim notifikasi *event-driven* ke SOAR segera setelah *event* diproses,
menghilangkan jeda penjadwalan periodik yang melekat pada mekanisme Kibana Alerting.

**(3) Definisi MTTR menggunakan T2 − T0.**
MTTR diukur sebagai selisih antara peluncuran serangan (T0) dan mitigasi otomatis (T2),
merepresentasikan *total response time* dari sudut pandang korban. Definisi ini konsisten dengan
cara MTTD diukur (T1 − T0), sehingga kedua metrik berbagi titik acuan awal yang sama (T0).

Enam penyesuaian teknis lainnya: (4) deteksi Nikto berbasis perilaku bukan *User-Agent*;
(5) cakupan tiga skenario (*Lateral Movement* T1021 dan *Exfiltration* T1041 belum diimplementasikan);
(6) kalkulasi MTTD/MTTR via skrip orkestrasi; (7) MITRE *enrichment* via Logstash `translate`;
(8) penamaan indeks `cti-logs-iqbal-*`; (9) penyelarasan pemetaan Nikto ke T1595.002.
