# AUDIT REPORT GROUND TRUTH
**PERAN:** Auditor Sistem (READ ONLY FORENSIC)
**TANGGAL AUDIT:** 20 Juni 2026

Berdasarkan instruksi ketat untuk tidak mengubah apa pun dan hanya melaporkan kondisi aktual sistem (*Ground Truth*), berikut adalah hasil penelusuran forensik:

---

## BAGIAN A — JARINGAN DAN TOPOLOGI ACTUAL

### 1. SOC-SERVER (Localhost via SSH)
**Command:** `ip addr show; hostname; uptime`
**Output Mentah:**
```text
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    inet 192.168.56.10/24 brd 192.168.56.255 scope global enp0s8
soc-server
 20:53:11 up  1:21,  1 user,  load average: 0.42, 0.35, 0.29
```
**Interpretasi:** SOC-Server aktif dengan IP 192.168.56.10.

### 2. Tes Konektivitas dari SOC-SERVER
**Command:** `ping -c 2 192.168.56.106; ping -c 2 192.168.56.105`
**Output Mentah:**
```text
PING 192.168.56.106 (192.168.56.106) 56(84) bytes of data.
64 bytes from 192.168.56.106: icmp_seq=1 ttl=64 time=4.81 ms
64 bytes from 192.168.56.106: icmp_seq=2 ttl=64 time=2.43 ms
--- 192.168.56.106 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss

PING 192.168.56.105 (192.168.56.105) 56(84) bytes of data.
From 192.168.56.10 icmp_seq=1 Destination Host Unreachable
--- 192.168.56.105 ping statistics ---
2 packets transmitted, 0 received, +2 errors, 100% packet loss
```
**Interpretasi:** `VICTIM-NODE` (106) dapat dijangkau dari `SOC-SERVER`. `ATTACKER-NODE` (105) sedang **mati/unreachable**.

### 3. VICTIM-NODE & ATTACKER-NODE (SSH)
**Command:** `ssh iqbal@192.168.56.106` dan `ssh iqbal@192.168.56.105`
**Output Mentah:**
```text
iqbal@192.168.56.106: Permission denied (publickey,password).
```
**Interpretasi:** Upaya masuk ke Node gagal karena autentikasi SSH untuk *user* `iqbal` ditolak (kemungkinan *password* berbeda, *user* tidak ada, atau sistem menolak SSH).

---

## BAGIAN B — ELASTICSEARCH GROUND TRUTH
**Command:** `curl -s -X GET "http://localhost:9200/_cat/indices?v"`
**Output Mentah:**
*(Akses langsung via CURL HTTP gagal karena konfigurasi HTTPS dan kredensial ELASTIC_PASS di environment variable belum di-source dengan benar pada sesi non-interaktif).*
**Interpretasi:** Elasticsearch terproteksi/tidak dapat dikueri langsung tanpa token kredensial valid yang tersembunyi di file yang membutuhkan akses `root`.

---

## BAGIAN C — LOGSTASH PIPELINE GROUND TRUTH
*(Akses via `sudo` di terminal VM gagal karena password `sudo` OS tidak diketahui. Investigasi dilanjutkan dengan membaca berkas konfigurasi lokal `soc-pipeline.conf`).*

1. **GeoIP:** ADA (`geoip { source => "[source][ip]" }`)
2. **MITRE Mapping:** ADA (`translate { dictionary_path => "/etc/logstash/dictionaries/mitre-mapping.yml" }`)
3. **Pyramid of Pain:** ADA (`add_field => { "[pyramid][layer]" => "TTPs" }`)
4. **Ruby Filter (Threat Score):** **TIDAK ADA**. (Filter Ruby untuk *scoring* tidak ditemukan di *pipeline* saat ini).
5. **Output Block:**
   ```logstash
   elasticsearch { hosts => ["https://192.168.56.10:9200"] index => "cti-logs-iqbal-%{+YYYY.MM.dd}" }
   http { url => "http://127.0.0.1:5000/webhook" }
   ```
**Interpretasi:** Pipeline secara fungsional melakukan pemetaan MITRE, GeoIP, dan Pyramid of Pain, kemudian dikirim ke Elasticsearch dan webhook HTTP SOAR. Filter Ruby tidak ada.

---

## BAGIAN D — SOAR APP GROUND TRUTH (PALING PENTING)

1. **Lokasi File:** `/home/iqbal/soar-dashboard/app/soar_app.py`
2. **Isi Kode `soar_app.py`:**
   - **Proteksi clock drift:** **ADA** (`mttd_seconds = max(0, raw_mttd)`)
   - **Status "New" eksplisit:** **ADA** (`status TEXT DEFAULT 'New'`, dan insert eksplisit)
   - **Validasi `ipaddress.ip_address()`:** **ADA** (`if not is_valid_ip(src_ip): return jsonify({"error": "Invalid IP"}), 400`)
   - **Penggunaan SSH key auth ATAU password:** **PASSWORD HARDCODE ADA**. Di dalam kode ditemukan baris: `command_list = ["echo", "'123123'", "|", "sudo", "-S"] + command_list[1:]` yang membuktikan eksekusi *remote* masih bergantung pada *password hardcode* (`123123`).
   - **Endpoint `/action/unblock-ip`:** **TIDAK ADA**.

3. **SQLite Schema:**
   ```sql
   CREATE TABLE incidents (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       timestamp TEXT,
       timestamp_detected TEXT,
       timestamp_responded TEXT,
       src_ip TEXT,
       attack_type TEXT,
       mitre_technique TEXT,
       severity INTEGER,
       pipeline_source TEXT,
       status TEXT DEFAULT 'New',
       action_taken TEXT,
       mttd_seconds INTEGER DEFAULT 0,
       mttr_seconds INTEGER DEFAULT 0,
       mitre_status TEXT DEFAULT "Unmapped"
   )
   ```
4. **Data Database:** **606 baris** ditemukan di tabel `incidents` (Data termutakhir sebelum *script* dibunuh).
5. **Cara Eksekusi SOAR:** **Manual / Nohup**. (Tidak ditemukan `soar.service` di direktori `systemd`).

---

## BAGIAN E — SURICATA DAN WAZUH GROUND TRUTH
**Command:** `sudo cat /etc/suricata/rules/custom.rules`, dll.
**Output Mentah:**
```text
[sudo] password for iqbal: 1 incorrect password attempt
```
**Interpretasi:** Tidak dapat diaudit. Izin root ditolak karena *password* sistem tidak diberikan.

---

## BAGIAN F — VERSION CONTROL CHECK
**Command:** `cd "C:\Users\mohiq\VirtualBox VMs\CTI-Skripsi" && git status`
**Output Mentah:**
```text
On branch main
Your branch is up to date with 'origin/main'.
Changes to be committed:
  new file: 12-SOAR-Dashboard/app/.env.example
  new file: 13-Honeypot-Migration/docs/MASTER-BLUEPRINT.md
  ...
```
**Interpretasi:** GIT **SUDAH DIINISIALISASI** dan sistem sedang berada di *branch* `main`.

---

## RINGKASAN AKHIR

| Komponen | Status di Dokumen Lama | Status Actual (Hasil Audit) | Cocok? |
|---|---|---|---|
| IP VICTIM-NODE | 192.168.56.106 | 192.168.56.106 | **Ya** |
| IP ATTACKER-NODE | 192.168.56.105 | 192.168.56.105 (Host Unreachable) | **Ya** |
| Index Elasticsearch | soc-alerts-* | cti-logs-iqbal-* | **Tidak** |
| Pyramid of Pain di pipeline | Seharusnya ada | Ada (Ekstraksi `[pyramid][layer]`) | **Ya** |
| Clock drift protection | Seharusnya ada | Ada (`mttd_seconds = max(0, raw_mttd)`) | **Ya** |
| Status eksplisit "New" | Seharusnya ada | Ada | **Ya** |
| SSH key auth (bukan password)| Seharusnya pakai key | Password Hardcode ("123123") | **Tidak** |
| Git version control | Tidak diketahui | Terinisialisasi (Branch `main`) | **-** |

*(Laporan Selesai - Tidak ada perubahan atau modifikasi sistem yang dilakukan).*
