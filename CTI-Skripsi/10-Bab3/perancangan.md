# BAB 3 - METODOLOGI PENELITIAN

## 3.1 Skenario Topologi

Penelitian ini membangun Cyber Threat Intelligence berbasis ELK Stack, Suricata, dan Wazuh
dalam lingkungan laboratorium tervirtualisasi menggunakan VirtualBox dengan jaringan
*host-only* `192.168.56.0/24`. Lingkungan terisolasi dipilih untuk menjamin reprodusibilitas
percobaan dan independensi antar-iterasi pengujian. Tiga node membentuk topologi penelitian
sebagai berikut.

- **SOC-SERVER** (IP `192.168.56.10`) — Node pusat operasi keamanan. Menjalankan
  Elasticsearch sebagai mesin penyimpanan dan pencarian event, Logstash sebagai pipeline
  pengayaan intelijen, Kibana sebagai antarmuka visualisasi CTI Dashboard, Wazuh Manager
  sebagai koordinator HIDS, dan SOAR Dashboard sebagai antarmuka respons insiden.

- **VICTIM-NODE** (IP `192.168.56.106`) — Node target yang dipantau. Menjalankan Suricata
  8.0.3 sebagai *Network Intrusion Detection System* (NIDS) yang memantau trafik jaringan
  masuk, serta Wazuh Agent sebagai *Host-based Intrusion Detection System* (HIDS) yang
  memantau log aktivitas pada tingkat sistem operasi. Wazuh Agent pada node ini juga
  menjalankan mekanisme mitigasi otomatis (*active response*) berupa pemblokiran alamat IP
  penyerang ketika *rule* HIDS terpenuhi.

- **ATTACKER-NODE** (IP `192.168.56.110`) — Node penyerang yang digunakan untuk
  menjalankan tiga skenario serangan terkontrol: pemindaian jaringan (Nmap), *brute force*
  SSH (Hydra), dan pemindaian kerentanan web (Nikto).

Pendekatan deteksi yang diterapkan adalah **deteksi hibrida** (NIDS + HIDS): Suricata
mendeteksi anomali pada lapisan jaringan, sedangkan Wazuh mendeteksi anomali pada lapisan
host. Kedua sensor bersifat komplementer — serangan *port scan* hanya terlihat pada lapisan
jaringan, sedangkan *brute force* dan pemindaian web juga meninggalkan jejak pada log host
sehingga dapat memicu respons otomatis.

Alur data keseluruhan sistem mengikuti lima tahap konseptual:

```
ATTACKER (192.168.56.110)
      │ tiga skenario: Nmap / Hydra / Nikto
      ▼
VICTIM (192.168.56.106) — Sensor Hybrid
 ├─ Suricata 8.0.3 (NIDS) — deteksi anomali jaringan
 └─ Wazuh Agent  (HIDS) — deteksi anomali host + mitigasi otomatis
      │ pengumpulan dan pengiriman log ke SOC
      ▼
SOC (192.168.56.10) — Pipeline Pengayaan Intelijen
 ├─ Pengayaan MITRE ATT&CK (SID → Technique ID + Technique Name)
 ├─ Klasifikasi Pyramid of Pain (TTPs / Tools / IP Address)
 └─ Pencatatan penanda waktu deteksi (T1) dan mitigasi (T2)
      │ penyimpanan event terpadu
      ▼
Elasticsearch — indeks event tunggal
      │ visualisasi dan respons
      ▼
 ├─ Kibana CTI Dashboard (visualisasi ancaman)
 └─ SOAR Dashboard + Respons Otomatis (firewall-drop Wazuh)
```

Desain lima tahap ini memastikan setiap *security event* yang masuk melewati seluruh
tahap transformasi dari *raw log* menjadi *actionable intelligence* sebelum disimpan,
konsisten dengan model konseptual penelitian (R-09).

---

## 3.2 Desain Deteksi dan Rule (Suricata)

### Rasional Pemilihan Tiga Skenario

Tiga skenario serangan dipilih untuk merepresentasikan tahapan awal *cyber kill chain*:
*reconnaissance* (Nmap), *credential access* (Hydra), dan *active reconnaissance* (Nikto).
Ketiganya memetakan ke teknik MITRE ATT&CK yang berbeda sehingga memungkinkan validasi
kemampuan sistem dalam melakukan pengayaan intelijen lintas taktik. Suricata 8.0.3
dikonfigurasi dengan tiga *custom rule* berbasis ambang (*threshold*) untuk mendeteksi
masing-masing skenario.

### Rule 1 — Nmap SYN Stealth Scan (SID 1000010)

**Apa yang dirancang:** Rule ini mendeteksi pemindaian port SYN yang berasal dari satu
sumber dengan ambang **50 paket SYN dalam 5 detik**. Rule bersifat *stateless* karena
Nmap tidak menyelesaikan *three-way handshake*.

**Mengapa dirancang demikian:** Ambang 50 paket / 5 detik dipilih untuk meminimalkan
*false positive* dari koneksi TCP normal yang sporadis, sekaligus cukup sensitif untuk
menangkap pemindaian cepat seperti Nmap dengan opsi `-T4` terhadap ratusan *port*.
Dipetakan ke MITRE ATT&CK **T1046 (Network Service Scanning)** karena tujuan serangan
adalah memetakan layanan yang aktif pada host target.

**Bagaimana dievaluasi:** Keberhasilan deteksi diukur melalui kemunculan *alert* di
Elasticsearch dan penghitungan MTTD (T1 − T0) per iterasi pengujian.

### Rule 2 — Hydra SSH Brute Force (SID 1000020)

**Apa yang dirancang:** Rule ini mendeteksi percobaan koneksi SSH berulang dari satu
sumber dengan ambang **5 percobaan koneksi SSH dalam 60 detik** pada port 22.

**Mengapa dirancang demikian:** Ambang berbasis laju koneksi TCP (bukan konten) dipilih
karena Hydra membuka sejumlah koneksi TCP ke port 22 secara paralel dalam waktu singkat,
pola yang secara statistik tidak mungkin terjadi pada penggunaan SSH normal. Pendekatan
ini tidak bergantung pada dekripsi konten sehingga tetap berlaku meskipun koneksi
terenkripsi. Dipetakan ke MITRE ATT&CK **T1110.001 (Brute Force: Password Guessing)**
karena tujuan serangan adalah menebak kredensial secara otomatis.

**Bagaimana dievaluasi:** Keberhasilan deteksi diukur melalui MTTD; keberhasilan respons
diukur melalui MTTR (T2 − T0) karena skenario ini memicu *active response* Wazuh.

### Rule 3 — Nikto Web Vulnerability Scan (SID 1000030)

**Apa yang dirancang:** Rule ini mendeteksi pemindaian kerentanan web menggunakan
pendekatan **berbasis perilaku** (laju permintaan HTTP), dengan ambang **20 permintaan
HTTP dalam 10 detik** ke port 80 atau 443.

**Mengapa dirancang demikian:** Pendekatan *signature User-Agent* tidak andal untuk
mendeteksi Nikto karena alat ini memiliki kemampuan menyamarkan *User-Agent* sebagai
peramban web umum, sehingga deteksi berbasis konten *header* dapat dielakkan. Deteksi
berbasis laju permintaan HTTP bersifat lebih tahan terhadap teknik penghindaran tersebut
karena perilaku pemindaian menghasilkan volume permintaan yang jauh melebihi pola
penelusuran web normal, terlepas dari *header* yang digunakan. Dipetakan ke MITRE ATT&CK
**T1595.002 (Active Reconnaissance: Vulnerability Scanning)** karena tujuan serangan
adalah mengidentifikasi kerentanan pada aplikasi web target.

**Bagaimana dievaluasi:** Sama dengan Hydra — MTTD untuk deteksi, MTTR untuk respons
otomatis via *active response* Wazuh.

### Ringkasan Desain Rule

| SID     | Skenario | Ambang Deteksi | Metode | Teknik MITRE |
|---------|----------|----------------|--------|--------------|
| 1000010 | Nmap     | 50 SYN / 5 detik | Laju paket SYN jaringan | T1046 |
| 1000020 | Hydra    | 5 koneksi SSH / 60 detik | Laju koneksi TCP port 22 | T1110.001 |
| 1000030 | Nikto    | 20 req HTTP / 10 detik | Laju permintaan HTTP (perilaku) | T1595.002 |

---

## 3.3 Desain Pipeline Pengayaan Intelijen

### Pengayaan MITRE ATT&CK

**Apa yang dirancang:** Setiap *security event* yang masuk ke pipeline diperiksa keberadaan
*signature ID* Suricata-nya. Bila SID dikenali, dua atribut intelijen ditambahkan ke event:
*Technique ID* (contoh: T1046) dan *Technique Name* (contoh: "Network Service Scanning")
berdasarkan MITRE ATT&CK Enterprise. Pemetaan SID ke TechniqueID disimpan dalam kamus
yang dapat diperbarui secara independen dari logika pipeline.

**Mengapa dirancang demikian:** Pendekatan *lookup dictionary* memisahkan logika deteksi
(rule Suricata) dari logika pengayaan (pemetaan MITRE), sehingga pemetaan baru dapat
ditambahkan tanpa mengubah konfigurasi sensor. Ini mendukung prinsip *separation of
concerns* dan mempermudah perluasan ke skenario serangan baru. Tabel pemetaan SID untuk
tiga skenario penelitian adalah sebagai berikut.

| SID     | Technique ID | Technique Name | Taktik |
|---------|-------------|----------------|--------|
| 1000010 | T1046       | Network Service Scanning | Discovery |
| 1000020 | T1110.001   | Brute Force: Password Guessing | Credential Access |
| 1000030 | T1595.002   | Active Reconnaissance: Vulnerability Scanning | Reconnaissance |

**Bagaimana dievaluasi:** Keberhasilan pengayaan diverifikasi dengan memeriksa keberadaan
atribut *Technique ID* dan *Technique Name* MITRE pada event Suricata yang tersimpan di
Elasticsearch untuk ketiga SID penelitian.

### Klasifikasi Pyramid of Pain

**Apa yang dirancang:** Setelah pengayaan MITRE, setiap event diklasifikasikan ke salah
satu lapisan *Pyramid of Pain* (Bianco, 2013). Lapisan ditentukan berdasarkan jenis
intelijen yang dapat diekstrak dari event: event yang berhasil dipetakan ke teknik MITRE
ditempatkan pada lapisan **TTPs** (tingkat tertinggi, paling sulit dihindari penyerang);
event yang mengandung pola nama alat serangan pada atribut *signature*-nya ditempatkan
pada lapisan **Tools**; event lainnya diklasifikasikan pada lapisan **IP Address** (paling
mudah dihindari penyerang).

**Mengapa dirancang demikian:** Klasifikasi ini memungkinkan analis SOC memprioritaskan
respons berdasarkan nilai operasional intelijen: ancaman yang teridentifikasi pada lapisan
TTPs mencerminkan pola perilaku penyerang yang sulit diubah, sehingga lebih bernilai
sebagai *actionable intelligence* dibanding sekadar daftar alamat IP. Distribusi lapisan
pada dashboard CTI merupakan salah satu indikator kualitas intelijen yang dihasilkan sistem.

**Bagaimana dievaluasi:** Distribusi lapisan Pyramid of Pain divisualisasikan pada Kibana
CTI Dashboard dan diperiksa kesesuaiannya dengan jenis serangan yang diujikan.

---

## 3.4 Definisi Metrik Pengukuran (MTTD dan MTTR)

### Penanda Waktu

Penelitian menggunakan dua metrik utama untuk mengevaluasi performa sistem deteksi dan
respons otomatis: *Mean Time To Detect* (MTTD) dan *Mean Time To Respond* (MTTR).
Keduanya diturunkan dari tiga penanda waktu yang direkam secara otomatis per iterasi
pengujian.

| Simbol | Definisi |
|--------|----------|
| T0 | Waktu peluncuran serangan dari ATTACKER-NODE |
| T1 | Waktu *alert* pertama terindeks di Elasticsearch setelah serangan dimulai |
| T2 | Waktu peristiwa mitigasi *firewall-drop* (Wazuh *active response*) terindeks |

### Definisi Metrik

**MTTD (Mean Time To Detect) = T1 − T0**

Mengukur durasi dari peluncuran serangan hingga sistem pertama kali mendeteksi dan
mengindeks *alert*. MTTD mencerminkan kecepatan respons sensor (Suricata) dan pipeline
pengayaan secara keseluruhan. Seluruh skenario menghasilkan nilai MTTD karena Suricata
selalu menghasilkan *alert* untuk ketiga *rule* penelitian.

**MTTR (Mean Time To Respond) = T2 − T0**

Mengukur durasi dari peluncuran serangan hingga mitigasi otomatis diterapkan dan terindeks.
MTTR mencerminkan kecepatan sistem secara *end-to-end* dari sudut pandang korban, yaitu
berapa lama sejak serangan dimulai hingga ancaman dinetralkan. MTTR hanya tersedia untuk
skenario yang memicu *active response* Wazuh — yaitu Hydra dan Nikto, karena keduanya
menghasilkan jejak pada log host yang memicu *rule* HIDS. Skenario Nmap tidak menghasilkan
MTTR karena *reconnaissance* jaringan murni tidak berinteraksi dengan layanan host dan
tidak memicu *rule* HIDS, sehingga tidak ada *active response* yang dijalankan. Perilaku
ini merupakan rancangan yang disengaja (*by design*) dan mengonfirmasi bahwa sistem hanya
memberikan respons otomatis terhadap serangan yang memiliki dampak langsung pada host.

### Justifikasi Definisi MTTR = T2 − T0

Definisi MTTR = T2 − T0 dipilih karena merepresentasikan *total response time* yang
dialami sistem dari titik awal serangan hingga mitigasi. Dibandingkan dengan definisi
alternatif T2 − T1 (waktu dari deteksi ke respons), definisi T2 − T0 memberikan gambaran
menyeluruh yang lebih bermakna bagi pengambil keputusan operasional: berapa lama jendela
kerentanan (*exposure window*) terbuka sejak serangan diluncurkan. Selain itu, kedua
metrik berbagi titik acuan awal yang sama (T0), sehingga MTTD dan MTTR dapat
dibandingkan secara langsung sebagai bagian dari evaluasi sistem yang terintegrasi.

### Protokol Pengujian

Pengujian dilaksanakan dalam **30 iterasi terkontrol**: 10 iterasi untuk setiap skenario
(Nmap, Hydra, Nikto). Independensi antar-iterasi dijamin dengan mereset pemblokiran
alamat IP penyerang di awal setiap iterasi sehingga setiap percobaan dimulai dari kondisi
sistem yang identik. Nilai T0, T1, dan T2 direkam per iterasi; MTTD dan MTTR dihitung
dari selisih penanda waktu tersebut dan dianalisis secara statistik (rata-rata, rentang,
simpangan baku) per skenario.
