# BAB 3 - METODOLOGI PENELITIAN

## 3.1 Skenario Topologi

Penelitian ini membangun Cyber Threat Intelligence berbasis ELK Stack, Suricata, dan Wazuh
dalam lingkungan laboratorium tervirtualisasi menggunakan VirtualBox dengan jaringan
host-only `192.168.56.0/24`. Tiga node berperan sebagai berikut.

- **SOC-SERVER** — IP `192.168.56.10` (antarmuka `enp0s8`). Node pusat operasi keamanan.
  Menjalankan Elasticsearch 8.19.12, Logstash, Kibana, Wazuh Manager, dan SOAR Dashboard
  (Flask, port 5000).

- **VICTIM-NODE** — IP `192.168.56.106` (user: `korban`). Node target yang dipantau.
  Menjalankan Suricata 8.0.3 (NIDS), Filebeat, dan Wazuh Agent. Suricata membaca trafik
  jaringan dan menghasilkan `eve.json`; Wazuh Agent memantau log tingkat host (`auth.log`,
  akses web) dan menjalankan mekanisme *active response* (*firewall-drop*).

- **ATTACKER-NODE** — IP `192.168.56.110` (user: `kali`). Node penyerang. Menjalankan
  alat serangan Nmap, Hydra, dan Nikto untuk tiga skenario pengujian terkontrol.

Alur data keseluruhan:

```
ATTACKER .110  →  VICTIM .106 (Suricata + Wazuh-Agent)
                       │
              eve.json + active-responses.log
                       │
              Filebeat → Logstash :5044 (SOC .10)
                       │
           [Pipeline: Time Parser → Wazuh/Suricata JSON Parser
            → Ensure source.ip → GeoIP → Drop Noise → Normalize
            → Extract SID → MITRE Enricher → Pyramid Classifier
            → SOAR Normalization → Wazuh AR Parser (T2/MTTR)]
                       │
              Elasticsearch `cti-logs-iqbal-*`
              + Webhook → SOAR Dashboard
                       │
              Kibana Dashboard (visualisasi)
```

---

## 3.2 Desain Deteksi dan Rule (Suricata)

Suricata 8.0.3 dikonfigurasi dengan tiga *custom rules* pada
`/var/lib/suricata/rules/custom.rules` untuk mendeteksi tiga skenario serangan penelitian.

### Rule 1 — Nmap SYN Stealth Scan (SID 1000010)

Mendeteksi pemindaian port SYN dari satu sumber dengan ambang **50 paket SYN dalam
5 detik**. Dipetakan ke MITRE ATT&CK T1046.

```
alert tcp any any -> $HOME_NET any (
  msg:"[CTI] Nmap SYN Stealth Scan Detected";
  flags:S; flow:stateless;
  threshold:type both, track by_src, count 50, seconds 5;
  classtype:attempted-recon; sid:1000010; rev:1;
  metadata:mitre_tactic_name Discovery;)
```

### Rule 2 — Hydra SSH Brute Force (SID 1000020)

Mendeteksi percobaan koneksi SSH berulang dari satu sumber dengan ambang **5 percobaan
koneksi SSH dalam 60 detik**. Ambang ini berbeda dari rancangan awal (10/10 detik) karena
disesuaikan dengan perilaku aktual Hydra pada lab (rev:2). Dipetakan ke T1110.001.

```
alert tcp any any -> $HOME_NET 22 (
  msg:"[CTI] Hydra SSH Brute Force Attempt";
  flow:stateless; flags:S;
  threshold:type both, track by_src, count 5, seconds 60;
  classtype:attempted-admin; sid:1000020; rev:2;
  metadata:mitre_tactic_name Credential_Access;)
```

### Rule 3 — Nikto Web Vulnerability Scan (SID 1000030)

Mendeteksi pemindaian kerentanan web menggunakan pendekatan **perilaku** (laju permintaan
HTTP), bukan tanda tangan *User-Agent*. Alasannya: Nikto versi yang digunakan menyamar
menggunakan *string* User-Agent browser sehingga pencocokan *User-Agent* tidak andal.
Ambang yang digunakan adalah **20 permintaan HTTP dalam 10 detik** ke port 80/443 (rev:3).
Dipetakan ke T1595.002.

```
alert http any any -> $HOME_NET [80,443] (
  msg:"[CTI] Nikto Web Vulnerability Scan Detected";
  flow:established,to_server;
  threshold:type both, track by_src, count 20, seconds 10;
  classtype:web-application-attack; sid:1000030; rev:3;
  metadata:mitre_tactic_name Reconnaissance;)
```

### Ringkasan Rule Deteksi

| SID     | Skenario | Threshold | Metode Deteksi | MITRE |
|---------|----------|-----------|----------------|-------|
| 1000010 | Nmap     | 50 SYN / 5 s | Paket SYN jaringan | T1046 |
| 1000020 | Hydra    | 5 koneksi SSH / 60 s | Koneksi TCP port 22 | T1110.001 |
| 1000030 | Nikto    | 20 req HTTP / 10 s | Laju permintaan HTTP (perilaku) | T1595.002 |

---

## 3.3 Integrasi MITRE ATT&CK

Setiap *rule* Suricata dipetakan ke teknik MITRE ATT&CK Enterprise melalui filter
`translate` pada pipeline Logstash. Pemetaan menggunakan dua file kamus YAML yang
tersimpan di `/etc/logstash/dictionaries/`:

- `mitre-mapping.yml` — SID → Technique ID
- `mitre-id-to-name.yml` — Technique ID → Technique Name

Tabel pemetaan SID tiga skenario penelitian:

| SID     | Technique ID | Technique Name | Taktik |
|---------|-------------|----------------|--------|
| 1000010 | T1046       | Network Service Scanning | Discovery |
| 1000020 | T1110.001   | Brute Force: Password Guessing | Credential Access |
| 1000030 | T1595.002   | Active Reconnaissance: Vulnerability Scanning | Reconnaissance |

Pipeline Logstash (`soc-pipeline.conf`) meng-ekstrak `signature_id` dari event Suricata
dan menjalankan `translate` untuk mengisi field `mitre.technique_id` dan
`mitre.technique_name`. File kamus sekunder (`99-mitre-normalize.conf`) menangani
empat jalur field alternatif agar SID dari berbagai format Filebeat (Victim flat vs.
SOC nested) selalu terpetakan.

Selain pengayaan MITRE, pipeline mengklasifikasikan setiap IOC ke lapisan Pyramid of Pain:
event dengan `mitre.technique_id` valid diberi label `TTPs`; event dengan pola alat
serangan pada signature diberi `Tools`; event lainnya diberi `IP_Address`.

---

## 3.4 Definisi Metrik Pengukuran (MTTD dan MTTR)

Penelitian menggunakan dua metrik utama untuk mengevaluasi performa sistem deteksi dan
respons. Keduanya diturunkan dari tiga penanda waktu yang direkam per iterasi pengujian.

**Penanda waktu:**

| Simbol | Definisi |
|--------|----------|
| T0 | Waktu peluncuran serangan dari mesin penyerang (ATTACKER-NODE) |
| T1 | Waktu *alert* pertama terindeks di Elasticsearch setelah serangan |
| T2 | Waktu peristiwa mitigasi *firewall-drop* (Wazuh *active response*) terindeks |

**Definisi metrik:**

- **MTTD (Mean Time To Detect)** = T1 − T0

  Mengukur durasi dari peluncuran serangan hingga sistem pertama kali mendeteksi dan
  mengindeks *alert* di Elasticsearch. Seluruh skenario menghasilkan MTTD karena Suricata
  selalu menghasilkan *alert*.

- **MTTR (Mean Time To Respond)** = T2 − T0

  Mengukur durasi dari peluncuran serangan hingga mitigasi otomatis (*firewall-drop*)
  terindeks. MTTR hanya tersedia untuk skenario yang memicu *active response* Wazuh
  (Hydra dan Nikto). Skenario Nmap tidak menghasilkan MTTR karena *reconnaissance* jaringan
  murni tidak memicu *rule* HIDS Wazuh (perilaku *by design*).

Definisi MTTR = T2 − T0 dipilih karena merepresentasikan waktu tanggap total yang
dirasakan sistem dari sudut pandang korban, yaitu durasi keseluruhan sejak serangan
dimulai hingga ancaman dinetralkan. Kedua metrik berbagi titik acuan awal yang sama (T0)
sehingga dapat dibandingkan secara langsung.

T2 direkam dari peristiwa `active_response` pada indeks `cti-logs-iqbal-*`, yang diisi
oleh blok filter Wazuh AR di pipeline Logstash (`field [event_type] = "active_response"`).
