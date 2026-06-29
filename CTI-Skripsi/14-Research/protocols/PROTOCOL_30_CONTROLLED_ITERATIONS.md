# PROTOKOL 30 CONTROLLED ITERATIONS — CTI-SKRIPSI

**Tanggal desain:** 2026-06-21
**Status:** DESAIN — BELUM DIEKSEKUSI (menunggu konfirmasi eksplisit per langkah)
**Tujuan:** Menghasilkan dataset penelitian bersih & terkontrol (Full Rebuild, keputusan D1) berisi
30 iterasi serangan terukur (10 Nmap, 10 Hydra, 10 Nikto), dengan pencatatan T0/T1/T2 per iterasi,
**terpisah** dari `incidents.db` lama yang sudah diarsipkan (753.358 record, FROZEN).

> Prasyarat WAJIB sebelum protokol ini: Backup tervalidasi 13/13 → **SUDAH ✅ (2026-06-21)**.

---

## 0. TOPOLOGI & PARAMETER

| Peran | Host | Catatan |
|-------|------|---------|
| Attacker | `192.168.56.110` | Kali — sumber serangan terkontrol (ssh key dari SOC sudah terpasang) |
| Victim | `192.168.56.106` | target Nmap/Hydra/Nikto |
| SOC Server | `192.168.56.10` | Suricata + ELK + SOAR + orchestrator |

| SID | Serangan | MITRE (granularity B) |
|-----|----------|------------------------|
| 1000010 | Nmap SYN scan | T1046 |
| 1000020 | Hydra SSH brute force | T1110.001 |
| 1000030 | Nikto web scan | T1595.002 |

Definisi metrik (samakan dengan Tabel 4.9 naskah):
- **T0** = waktu serangan diluncurkan (clock SOC, diambil tepat sebelum launch).
- **T1** = waktu alert pertama untuk SID terkait muncul di Elasticsearch (`@timestamp`).
- **T2** = waktu mitigasi (event active-response `firewall-drop` untuk src attacker, atau status incident → mitigated).
- **MTTD** = T1 − T0
- **MTTR** = T2 − T0  *(sesuai Tabel 4.8 naskah)*

---

## 1. PRE-FLIGHT (P0–P4) — dijalankan SEKALI sebelum iterasi

### P0 — QUIESCE INGESTION LIVE (WAJIB PERTAMA)
Tujuan: hentikan aliran noise ke `incidents.db` agar baseline lama tetap beku & dataset riset mulai bersih.

```bash
# Di SOC Server. Hentikan konsumen webhook (SOAR) dan pipeline agar tidak ada tulisan baru.
sudo systemctl stop logstash          # stop enrichment + webhook ke SOAR
# Hentikan SOAR app (jalan manual via venv, pid terlihat di ps). Sesuaikan cara stop:
pkill -f 'soar_app.py' || echo "SOAR sudah berhenti / sesuaikan manual"
# Verifikasi tidak ada lagi proses SOAR & port 5000 bebas:
ps aux | grep -i soar | grep -v grep ; ss -tulnp 2>/dev/null | grep 5000 || echo "port 5000 bebas"
```

### P1 — FREEZE DB LAMA, SIAPKAN DB RISET TERPISAH
```bash
APPDIR=/home/iqbal/soar-dashboard/app
TS=$(date +%Y%m%d_%H%M%S)
# Arsipkan (rename) DB lama -> tidak dihapus, hanya disisihkan
mv $APPDIR/incidents.db $APPDIR/incidents_legacy_${TS}.db
ls -lh $APPDIR/incidents_legacy_${TS}.db
# SOAR akan auto-create schema baru saat start (DB riset kosong & bersih)
```
> DB lama TIDAK dihapus (backup tervalidasi + arsip legacy). DB riset = file baru `incidents.db` bersih.

### P2 — PERBAIKI DICTIONARY MITRE (granularity B)
```bash
# Baca dulu versi runtime (JANGAN timpa dari repo — runtime 1071B berbeda dari repo)
sudo cat /etc/logstash/dictionaries/mitre-mapping.yml
# Tambahkan 3 baris (append; pastikan format LF, tanpa CR):
sudo tee -a /etc/logstash/dictionaries/mitre-mapping.yml >/dev/null <<'EOF'

# Research CTI-LAB custom rules (granularity B)
1000010: T1046
1000020: T1110.001
1000030: T1595.002
EOF
# Verifikasi entri & tidak ada CR
sudo grep -nE "100001[0]|1000020|1000030" /etc/logstash/dictionaries/mitre-mapping.yml
file /etc/logstash/dictionaries/mitre-mapping.yml   # harus "ASCII text"
```
> `mitre-id-to-name.yml` sudah memuat T1046/T1110.001/T1595.002 → tidak perlu diubah (terverifikasi FASE 2).

### P3 — START ULANG PIPELINE & SOAR (DB riset aktif)
```bash
sudo systemctl start logstash
sudo journalctl -u logstash -n 30 --no-pager | tail -n 15   # pastикан tanpa error config
cd /home/iqbal/soar-dashboard/app && nohup ./venv/bin/python soar_app.py >/tmp/soar.log 2>&1 &
sleep 3 ; ss -tulnp 2>/dev/null | grep 5000 && echo "SOAR up"
```

### P4 — VERIFIKASI CLOCK SYNC (T0/T1/T2 lintas mesin harus akurat)
```bash
# Di SOC + attacker + victim, pastikan NTP sinkron (gunakan test-clock-sync-v2.sh bila ada)
timedatectl | grep -E 'synchronized|NTP'
# Cek selisih waktu attacker vs SOC (jalankan dari SOC, ssh key sudah terpasang):
echo "SOC : $(date -u +%s.%N)" ; ssh kali@192.168.56.110 "date -u +%s.%N" 2>/dev/null
```
> Jika selisih > 1 detik, perbaiki NTP dulu — kalau tidak, MTTD bisa bias.

---

## 2. LOOP ITERASI (30×) — orchestrator dijalankan DI SOC SERVER

Pola tiap iterasi: catat T0 → luncurkan serangan (via ssh ke attacker) → poll ES untuk T1 →
poll ES untuk event mitigasi (T2) → hitung MTTD/MTTR → tulis ke CSV riset terpisah.

Output disimpan di **`/home/iqbal/research-archive/2026-06-21_controlled-run/iterations.csv`**
(dan DB riset terisi otomatis lewat pipeline normal — keduanya terpisah dari DB lama).

Lihat skrip orchestrator: `run_controlled_iterations.sh` (di folder ini).

Urutan eksekusi serangan (protokol utama 30 iterasi, `RUN_NIKTO=1` default):
- Iterasi 1–10  : Nmap  — Skenario A (`nmap -sS -T4 -p 1-1000 192.168.56.106`)
- Iterasi 11–20 : Hydra — Skenario B (`hydra -l <user> -P <wordlist-kecil> ssh://192.168.56.106 -t 4 -f`)
- Iterasi 21–30 : Nikto — Skenario C (`nikto -h http://192.168.56.106`)  *(set `RUN_NIKTO=0` bila ingin 20 saja)*

Antar iterasi diberi jeda (mis. 60 dtk) agar threshold rule reset & alert tidak tumpang tindih.

---

## 3. ARTEFAK OUTPUT (terpisah dari incidents.db lama)

| Artefak | Lokasi | Isi |
|---------|--------|-----|
| `iterations.csv` | `/home/iqbal/research-archive/2026-06-21_controlled-run/` | iter#, type, sid, T0, T1, T2, MTTD, MTTR, src_ip, status |
| DB riset baru | `/home/iqbal/soar-dashboard/app/incidents.db` (fresh) | hanya event sejak P3 |
| Raw evidence per iterasi | `.../controlled-run/raw/iter_NN.json` | hit ES mentah utk audit |
| `RUN_MANIFEST.md` | `.../controlled-run/` | ringkasan + checksum |

---

## 4. VALIDASI DATASET BARU (setelah 30 iterasi)
- Coverage MITRE pada event riset = 100% (semua SID 1000010/20/30 → Mapped).
- 30 baris MTTD/MTTR lengkap (tidak ada T1/T2 kosong).
- src_ip dominan = `192.168.56.110` (attacker hadir — membantah temುan lama "attacker absen").
- Simpan ringkasan ke `RUN_MANIFEST.md` + checksum.

---

## 5. ROLLBACK / SAFETY
- DB lama: `incidents_legacy_<TS>.db` (arsip) + backup tervalidasi di `research-archive/...snapshot/`.
- Dictionary: `.bak` sudah ada di `/etc/logstash/dictionaries/`. Untuk batalkan P2: hapus 3 baris tambahan, restart logstash.
- Semua langkah P0–P4 reversible.

**TIDAK ADA langkah di dokumen ini yang boleh dijalankan tanpa konfirmasi eksplisit per fase.**
