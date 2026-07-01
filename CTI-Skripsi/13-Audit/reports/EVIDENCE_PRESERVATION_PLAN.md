# EVIDENCE PRESERVATION PLAN — CTI-SKRIPSI

**Tanggal:** 21 Juni 2026
**Fase:** EXECUTION PHASE — Prioritas 1 (Backup DB) & Prioritas 2 (Arsip Evidence)
**Prinsip:** READ ONLY. Hanya operasi COPY (non-destruktif). TIDAK ADA reset/truncate/rebuild/delete.
**Tujuan:** Mengamankan seluruh evidence penelitian sebelum tindakan lanjutan apapun.

---

## RUANG LINGKUP PRESERVASI

| Aset | Lokasi Sumber | Tipe | Prioritas |
|------|---------------|------|-----------|
| `incidents.db` (540,889 record, 66 MB) | SOC Server `/home/iqbal/soar-dashboard/app/` | Database runtime | 1 (KRITIS) |
| Audit reports | Repo `13-Audit/reports/` | Markdown | 2 |
| Screenshots | Repo `08-Screenshots/` | PNG | 2 |
| Konfigurasi ELK | Repo `02-ELK/` + runtime `/etc/` | YAML/conf | 2 |
| MITRE mapping | Repo `05-MITRE/` + runtime `/etc/logstash/dictionaries/` | YAML | 2 |
| Suricata rules | Repo `03-Suricata/` | rules | 2 |
| Wazuh config | Repo `04-Wazuh/ossec.conf` | conf | 2 |
| SOAR app code | Repo `12-SOAR-Dashboard/app/` | Python | 2 |
| Evidence JSON/report | Repo `09-Evidence/` | JSON/MD | 2 |

---

## CATATAN KEAMANAN OPERASI

- Semua command di bawah hanya **membaca dan menyalin** (`cp`, `tar`, `scp`, `sha256sum`).
- TIDAK ada `rm`, `DROP`, `DELETE`, `TRUNCATE`, atau restart service.
- Backup database menggunakan **SQLite `.backup`** (online backup, aman saat DB sedang dipakai SOAR).
- Verifikasi integritas wajib via checksum SHA-256.

---

## 1. FOLDER STRUCTURE ARSIP PENELITIAN

Struktur arsip dibuat di **dua lokasi**: SOC Server (untuk DB) dan Repository Windows (untuk dokumen).

### Di SOC Server (Linux) — untuk database runtime

```
/home/iqbal/research-archive/
└── 2026-06-21_ground-truth-snapshot/
    ├── database/
    │   ├── incidents_backup_20260621.db        # hasil SQLite .backup
    │   └── incidents_backup_20260621.db.sha256 # checksum
    ├── runtime-config/
    │   ├── logstash/                            # /etc/logstash (read-copy)
    │   ├── dictionaries/                        # mitre-mapping.yml runtime
    │   ├── elasticsearch.yml
    │   ├── kibana.yml
    │   └── filebeat.yml
    ├── runtime-evidence/
    │   ├── ground_truth_query_output.txt        # output minimal_ground_truth.py
    │   ├── soar_api_header.txt                  # curl -i header (251 MB proof)
    │   └── ps_ss_soar.txt                        # ps aux + ss -tulnp
    └── MANIFEST.txt                              # daftar isi + checksum + timestamp
```

### Di Repository (Windows) — untuk dokumen & evidence statis

```
CTI-Skripsi/
└── 14-Research/
    └── archive/
        └── 2026-06-21_evidence-snapshot/
            ├── audit-reports/        # salinan 13-Audit/reports/*
            ├── screenshots/          # salinan 08-Screenshots/*
            ├── evidence/             # salinan 09-Evidence/*
            ├── config/               # salinan 02-ELK, 03-Suricata, 04-Wazuh, 05-MITRE
            ├── soar-code/            # salinan 12-SOAR-Dashboard/app (tanpa .db besar)
            ├── database/             # incidents_backup_20260621.db (ditarik via scp)
            └── ARCHIVE_MANIFEST.md   # daftar isi + checksum + tanggal
```

**Alasan dua lokasi:** DB hanya ada di runtime SOC Server; dokumen ada di repo. Arsip final menggabungkan keduanya di `14-Research/archive/`.

---

## 2. COMMAND BACKUP

### PRIORITAS 1 — Backup `incidents.db` (jalankan di SOC Server)

> Gunakan SQLite online backup agar aman walau SOAR sedang berjalan. JANGAN `cp` mentah saat DB aktif (risiko korup WAL).

```bash
# (a) Buat struktur folder arsip
mkdir -p /home/iqbal/research-archive/2026-06-21_ground-truth-snapshot/database
mkdir -p /home/iqbal/research-archive/2026-06-21_ground-truth-snapshot/runtime-config
mkdir -p /home/iqbal/research-archive/2026-06-21_ground-truth-snapshot/runtime-evidence

# (b) Online backup database via Python sqlite3 (AMAN, READ ONLY terhadap data)
ARCHIVE=/home/iqbal/research-archive/2026-06-21_ground-truth-snapshot
SRC=/home/iqbal/soar-dashboard/app/incidents.db
DST=$ARCHIVE/database/incidents_backup_20260621.db

python3 - <<'PYEOF'
import sqlite3
src = "/home/iqbal/soar-dashboard/app/incidents.db"
dst = "/home/iqbal/research-archive/2026-06-21_ground-truth-snapshot/database/incidents_backup_20260621.db"
con = sqlite3.connect(src)
bck = sqlite3.connect(dst)
with bck:
    con.backup(bck)          # online backup API - tidak mengubah sumber
bck.close(); con.close()
print("Backup selesai:", dst)
PYEOF

# (c) Buat checksum SHA-256
sha256sum $DST > $DST.sha256
cat $DST.sha256
```

### PRIORITAS 1b — Simpan evidence runtime (jalankan di SOC Server)

```bash
# Simpan ulang output ground truth (READ ONLY query)
python3 /home/iqbal/minimal_ground_truth.py > $ARCHIVE/runtime-evidence/ground_truth_query_output.txt

# Simpan header API sebagai bukti payload 251 MB (READ ONLY, hanya header)
curl -i -s http://localhost:5000/api/incidents | head -c 1000 > $ARCHIVE/runtime-evidence/soar_api_header.txt

# Simpan snapshot proses & port
{ ps aux | grep -i soar; echo "----"; ss -tulnp | grep 5000; } > $ARCHIVE/runtime-evidence/ps_ss_soar.txt
```

### PRIORITAS 1c — Salin konfigurasi runtime (READ-COPY)

```bash
cp -a /etc/logstash $ARCHIVE/runtime-config/logstash 2>/dev/null || echo "skip logstash (perm)"
cp -a /etc/logstash/dictionaries $ARCHIVE/runtime-config/dictionaries 2>/dev/null || echo "skip dict"
cp /etc/elasticsearch/elasticsearch.yml $ARCHIVE/runtime-config/ 2>/dev/null || echo "skip es"
cp /etc/kibana/kibana.yml $ARCHIVE/runtime-config/ 2>/dev/null || echo "skip kibana"
cp /etc/filebeat/filebeat.yml $ARCHIVE/runtime-config/ 2>/dev/null || echo "skip filebeat"
```

### PRIORITAS 1d — Buat MANIFEST di SOC Server

```bash
{
  echo "GROUND TRUTH SNAPSHOT MANIFEST"
  echo "Tanggal: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Host: $(hostname)"
  echo "Total incident (saat backup):"
  python3 -c "import sqlite3;c=sqlite3.connect('$SRC');print(c.execute('SELECT COUNT(*) FROM incidents').fetchone()[0])"
  echo "----- CHECKSUM -----"
  cat $DST.sha256
  echo "----- ISI ARSIP -----"
  find $ARCHIVE -type f -exec ls -lh {} \;
} > $ARCHIVE/MANIFEST.txt
cat $ARCHIVE/MANIFEST.txt
```

### PRIORITAS 2 — Tarik DB ke Repository & arsipkan dokumen (jalankan di Windows PowerShell)

```powershell
# (a) Tarik backup DB dari SOC Server ke repo arsip
$dest = "c:\Users\mohiq\VirtualBox VMs\CTI-Skripsi\14-Research\archive\2026-06-21_evidence-snapshot"
New-Item -ItemType Directory -Force -Path "$dest\database" | Out-Null
scp iqbal@192.168.56.10:/home/iqbal/research-archive/2026-06-21_ground-truth-snapshot/database/incidents_backup_20260621.db "$dest\database\"
scp iqbal@192.168.56.10:/home/iqbal/research-archive/2026-06-21_ground-truth-snapshot/database/incidents_backup_20260621.db.sha256 "$dest\database\"

# (b) Salin dokumen repo ke arsip (COPY, sumber tetap utuh)
$base = "c:\Users\mohiq\VirtualBox VMs\CTI-Skripsi"
Copy-Item "$base\13-Audit\reports\*"   "$dest\audit-reports\" -Recurse -Force
Copy-Item "$base\08-Screenshots\*"     "$dest\screenshots\"   -Recurse -Force
Copy-Item "$base\09-Evidence\*"        "$dest\evidence\"      -Recurse -Force
Copy-Item "$base\02-ELK\*"             "$dest\config\02-ELK\" -Recurse -Force
Copy-Item "$base\03-Suricata\*"        "$dest\config\03-Suricata\" -Recurse -Force
Copy-Item "$base\04-Wazuh\*"           "$dest\config\04-Wazuh\" -Recurse -Force
Copy-Item "$base\05-MITRE\*"           "$dest\config\05-MITRE\" -Recurse -Force
Copy-Item "$base\12-SOAR-Dashboard\app\*.py" "$dest\soar-code\" -Recurse -Force
```

> Catatan: buat dulu sub-folder tujuan bila `Copy-Item` mengeluh path tidak ada (gunakan `New-Item -ItemType Directory -Force`).

---

## 3. VERIFICATION COMMAND

### Verifikasi di SOC Server

```bash
# (a) Verifikasi file backup ada dan ukurannya wajar (~66 MB)
ls -lh $ARCHIVE/database/incidents_backup_20260621.db

# (b) Verifikasi integritas checksum
sha256sum -c $ARCHIVE/database/incidents_backup_20260621.db.sha256

# (c) Verifikasi DB backup BISA dibuka & jumlah record SAMA dengan sumber
python3 - <<'PYEOF'
import sqlite3
src="/home/iqbal/soar-dashboard/app/incidents.db"
dst="/home/iqbal/research-archive/2026-06-21_ground-truth-snapshot/database/incidents_backup_20260621.db"
a=sqlite3.connect(src).execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
b=sqlite3.connect(dst).execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
print(f"Sumber={a:,}  Backup={b:,}  MATCH={'YA' if a==b else 'TIDAK'}")
PYEOF

# (d) Integrity check internal SQLite
python3 -c "import sqlite3;print(sqlite3.connect('$ARCHIVE/database/incidents_backup_20260621.db').execute('PRAGMA integrity_check').fetchone()[0])"
```

### Verifikasi di Windows

```powershell
# (a) Verifikasi checksum DB hasil tarik scp cocok dengan dari server
Get-FileHash "$dest\database\incidents_backup_20260621.db" -Algorithm SHA256
Get-Content "$dest\database\incidents_backup_20260621.db.sha256"

# (b) Verifikasi jumlah file arsip dokumen
Get-ChildItem "$dest" -Recurse -File | Measure-Object | Select-Object Count
```

---

## 4. CHECKLIST VALIDASI BACKUP

Tandai setiap item setelah dijalankan dan terbukti:

| # | Item Validasi | Status | Bukti |
|---|---------------|--------|-------|
| 1 | Folder arsip SOC Server dibuat | ☐ | output `mkdir` |
| 2 | `incidents_backup_20260621.db` terbentuk (~66 MB) | ☐ | `ls -lh` |
| 3 | Checksum SHA-256 DB dibuat | ☐ | file `.sha256` |
| 4 | `sha256sum -c` → OK | ☐ | output verifikasi |
| 5 | COUNT(*) backup == sumber (540,889) | ☐ | output Python MATCH=YA |
| 6 | `PRAGMA integrity_check` → ok | ☐ | output `ok` |
| 7 | Evidence runtime (query, header, ps/ss) tersimpan | ☐ | isi `runtime-evidence/` |
| 8 | Konfigurasi runtime tersalin | ☐ | isi `runtime-config/` |
| 9 | MANIFEST.txt dibuat | ☐ | isi `MANIFEST.txt` |
| 10 | DB ditarik ke repo via scp | ☐ | `Get-FileHash` |
| 11 | Checksum DB di Windows == di server | ☐ | hash cocok |
| 12 | Dokumen repo (audit/screenshot/evidence/config) tersalin | ☐ | `Measure-Object Count` |
| 13 | `ARCHIVE_MANIFEST.md` dibuat di repo | ☐ | file ada |

**Backup dinyatakan VALID hanya jika item 1–13 = ✅.**

---

## RINGKASAN EKSEKUSI

1. **SOC Server dulu:** Prioritas 1 (a→d) — backup DB + evidence + config + manifest.
2. **Windows kedua:** Prioritas 2 (a→b) — tarik DB + arsip dokumen.
3. **Verifikasi:** jalankan semua command Bagian 3.
4. **Validasi:** lengkapi checklist Bagian 4 hingga 13/13.

**RULE DIPATUHI:** Semua operasi adalah COPY/READ. TIDAK ADA reset, truncate, delete, atau rebuild. Database sumber tetap utuh 540,889 record.

**Status:** PLAN SIAP DIEKSEKUSI — menunggu Anda menjalankan command di SOC Server.
