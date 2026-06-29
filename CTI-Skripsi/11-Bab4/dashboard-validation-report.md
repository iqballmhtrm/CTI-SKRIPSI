# Laporan Validasi Dashboard dan Pemetaan Serangan

## 1. Tujuan Dashboard
Dashboard Kibana dibangun sebagai pusat _Cyber Threat Intelligence_ (CTI) untuk memvisualisasikan
data keamanan secara *real-time*. Tujuan utamanya adalah mempermudah analis SOC dalam mengenali,
merespons, dan menelusuri ancaman menggunakan kerangka kerja MITRE ATT&CK.

## 2. Dashboard Architecture
Arsitektur Dashboard terdiri dari:
- **Index Pattern:** `cti-logs-iqbal-*` yang memuat data pengayaan dari Logstash.
- **Data Source:** Suricata (NIDS di VICTIM-NODE) mendeteksi di jaringan, Wazuh Agent (HIDS)
  memantau log host, dan Logstash memberikan anotasi teknik MITRE ATT&CK serta klasifikasi
  Pyramid of Pain.
- **Panel Utama:** CTI Dashboard memuat visualisasi distribusi teknik MITRE ATT&CK, distribusi
  lapisan Pyramid of Pain, *timeline* serangan, serta tabel *Top Threat Actors* (sumber IP).

## 3. Alert Validation
Sistem mendeteksi tiga jenis perilaku penyerangan (Nmap, Hydra, Nikto) berdasarkan *Custom Rules*
Suricata (SID 1000010/1000020/1000030) dan event ter-enrich MITRE ATT&CK tersimpan di indeks
`cti-logs-iqbal-*`. Status validasi: **100% SUCCESS** (30/30 iterasi terdeteksi).

## 4. MITRE Validation
Mapping berjalan sempurna. Field `mitre.technique_id` dan `mitre.technique_name` berhasil
diekstrak via filter `translate` Logstash dan dapat diagregasi untuk visualisasi distribusi
teknik dan taktik pada dashboard.

## 5. Nmap Result
- **Alert Name:** `[CTI] Nmap SYN Stealth Scan Detected`
- **Tactic:** Discovery
- **Technique:** Network Service Scanning (T1046)
- **Ambang:** 50 SYN paket / 5 detik, *stateless* (SID 1000010, rev:1)
- **Status:** Panel Validasi T1046 menampilkan hitungan deteksi positif.

## 6. Hydra Result
- **Alert Name:** `[CTI] Hydra SSH Brute Force Attempt`
- **Tactic:** Credential Access
- **Technique:** Brute Force: Password Guessing (T1110.001)
- **Ambang:** 5 koneksi TCP / 60 detik, port 22 (SID 1000020, rev:2)
- **Status:** Panel Validasi T1110.001 menampilkan hitungan deteksi positif.

## 7. Nikto Result
- **Alert Name:** `[CTI] Nikto Web Vulnerability Scan Detected`
- **Tactic:** Reconnaissance
- **Technique:** Active Reconnaissance: Vulnerability Scanning (T1595.002)
- **Ambang:** 20 permintaan HTTP / 10 detik, *behavioral* (SID 1000030, rev:3)
- **Metode deteksi:** berbasis laju permintaan HTTP (perilaku), bukan tanda tangan *User-Agent*
- **Status:** Panel Validasi T1595.002 menampilkan hitungan deteksi positif.

## 8. Dashboard Result
Dashboard final menampilkan ringkasan ekstensif. Visualisasi menunjukkan korelasi antara
*Threat Actor* (IP penyerang `192.168.56.110`) dengan teknik MITRE ATT&CK yang digunakan
(T1046/T1110.001/T1595.002) dan lapisan Pyramid of Pain yang sesuai (TTPs untuk event
ter-*mapping* MITRE). Catatan: IP `192.168.56.1` yang tampak pada beberapa visualisasi
merupakan sumber *noise* trafik manajemen (*Suricata STREAM events*) yang telah diredam
oleh filter Logstash; bukan *threat actor* penelitian.

## 9. Analisis Hasil
Deteksi berhasil di-trigger tanpa *false negative* pada seluruh 30 iterasi terkontrol.
Logstash terbukti *reliable* dalam mengekstraksi metadata Suricata dan memetakannya ke
teknik MITRE ATT&CK pada sub-teknik level yang presisi (T1110.001, T1595.002). Visualisasi
Kibana merespons data enriched dengan akurat dan informatif untuk keperluan analisis CTI.

## 10. Kesimpulan
Seluruh tumpukan ELK, Wazuh, dan Suricata telah dikonfigurasi dengan tepat. Dashboard CTI
yang dibangun siap memenuhi standar *Cyber Threat Intelligence* dan berhasil memvalidasi
seluruh tujuan penelitian. Indeks `cti-logs-iqbal-*` menyimpan seluruh event ter-*enrich*
sebagai basis data intelijen ancaman terpadu.
