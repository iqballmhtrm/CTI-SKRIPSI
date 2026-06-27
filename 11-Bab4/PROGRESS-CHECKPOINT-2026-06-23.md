# PROGRESS CHECKPOINT — 2026-06-23 (lanjut besok)

Lab lokal VirtualBox. Node: SOC `192.168.56.10` (iqbal) · Victim `192.168.56.106` (korban) · Attacker/Kali `192.168.56.110` (kali).
Tujuan sesi: tuntaskan MTTD/MTTR terkontrol (30 iterasi) → lalu fase honeypot/Elastic Cloud.

## SUDAH SELESAI (jangan diulang)
- [x] Custom rule Suricata `1000010/1000020/1000030` ter-deploy di victim (`/var/lib/suricata/rules/custom.rules`, terdaftar di `rule-files`).
- [x] RAM VM victim dinaikkan 1GB→**3GB** (VBoxManage modifyvm) → Suricata bisa muat ET ruleset penuh (50k rule) tanpa timeout. Override `TimeoutStartSec=600` terpasang.
- [x] SOAR fd-leak diperbaiki (`contextlib.closing`), skema DB diperbaiki (kolom `mitre_technique`,`mitre_status`), webhook balas **201**. `incidents.db` dibuat ulang.
- [x] Logstash pipeline (`/etc/logstash/conf.d/soc-pipeline.conf`) ditambah:
  - DROP noise STREAM (trafik manajemen), dan
  - NORMALISASI `alert.* → data.alert.*` (agar query orchestrator cocok).
  - Validasi `Configuration OK`, Logstash `active`.
- [x] Filebeat **victim** dialihkan dari ES-langsung → **Logstash 5044** (`output.logstash`); eve.json dirotasi bersih; registry reset.
- [x] **T1 LULUS**: nmap → `data.alert.signature_id:1000010` muncul di `cti-logs-iqbal-*` + `mitre.technique_id:T1046`, latensi ~2 dtk.
- [x] wazuh-manager diperbaiki (hapus lock dir `/var/ossec/var/start-script-lock`) → `active` & menganalisis.
- [x] **Whitelist** `192.168.56.10` & `192.168.56.106` di `ossec.conf` (cegah self-block) → Wazuh restart.
- [x] SOC Filebeat (Wazuh `alerts.json`) di-set `tail_files: true` + registry reset → `active`, tidak flood.
- [x] Self-block lama dihapus (`iptables -D INPUT -s 192.168.56.10 -j DROP`).

## UPDATE 2026-06-24 — FASE 1 (T1/MTTD Hydra) LULUS
- [x] Ambang sid 1000020 diturunkan `count 10/10s` → **`count 5/60s` (rev:2)**; di-deploy ke victim `/var/lib/suricata/rules/custom.rules` (+backup `custom.rules.bak_thr`), Suricata restart (restart pertama gagal `result 'protocol'` Type=notify, auto-restart systemd berhasil → active).
- [x] Verifikasi: eve.json victim ada alert sid 1000020 rev:2 dari `.110`→22; ES `cti-logs-iqbal-*` count=3 (5 mnt). **T1 Hydra OK.**
- Warning Suricata `rule 1000020 SYN-only ... disabling for toclient` = TIDAK masalah (rule tetap aktif arah toserver = arah serangan).

## UPDATE 2026-06-24 — FASE 2 (T2/MTTR firewall-drop) LULUS
- [x] **Filebeat victim** ditambah input ke-3 `wazuh-ar-victim` baca `/var/ossec/logs/active-responses.log` → label `log_type: wazuh-ar` (deploy via rewrite penuh metode printf kebal-whitespace; `filebeat.yml.bak_ar_*` + `.broken_*` tersimpan). `Config OK`, active.
- [x] **Logstash** (`/etc/logstash/conf.d/soc-pipeline.conf`) ditambah blok `if [log_type]=="wazuh-ar"`: grok pisah prefix waktu + JSON, ambil entri `"command":"add"`, set `rule.description="Host Blocked by firewall-drop Active Response"` + `data.srcip`/`source.ip` + `@timestamp`=waktu eksekusi blokir (tz Asia/Jakarta). Sengaja TIDAK set signature_id → tidak memicu webhook SOAR. Backup `soc-pipeline.conf.bak_ar_*`. Patcher arsip: `02-ELK/patch_logstash_ar.py`, `02-ELK/patch_filebeat_ar.py`.
- [x] **VERIFIKASI T2**: Hydra → Wazuh 5763 (brute) → firewall-drop "add" `.110` (17:50:26) → ter-index di `cti-logs-iqbal-*` dengan `rule.description` persis + `srcip 192.168.56.110`. **Query orchestrator T2 sekarang akan menemukan event.**

## UPDATE 2026-06-24 — FASE 3 (independensi iterasi) + FASE 4 (pra-terbang) SELESAI
- [x] Script `/usr/local/sbin/cti-unblock.sh` (loop hapus DROP `.110`) + sudoers NOPASSWD `/etc/sudoers.d/cti-unblock` di victim → uji `UNBLOCK OK (passwordless)`. Arsip repo `14-Research/protocols/cti-unblock.sh`.
- [x] Orchestrator `/home/iqbal/run_controlled_iterations.sh` dipatch: var `VICTIM_SSH` + panggilan unblock di awal tiap `run_one` (skip saat DRY_RUN). `SYNTAX OK`. (repo `14-Research/protocols/run_controlled_iterations.sh` ikut diupdate.)
- [x] Offset jam OK: victim↔SOC 0.59s, kali↔SOC 0.25s (<1s, tak perlu sync).
- [x] **Rule Nikto 1000030 diganti behavioral** (`count 20/10s`, rev:3) karena Nikto versi ini menyamar UA browser (bukan string "Nikto"). Deploy ke victim + restart. Verifikasi: eve.json + ES `count=3` sid 1000030. **Deteksi Nikto OK.**
- [x] 3 rule deteksi terverifikasi end-to-end: 1000010 Nmap, 1000020 Hydra, 1000030 Nikto.

## ✅✅ 2026-06-24 — 30-RUN SELESAI (30/30 OK, 0 NO_DETECT) — HASIL FINAL
CSV: `~/research-archive/2026-06-21_controlled-run/iterations.csv` (backup `_FINAL_*`).

| Skenario (iter) | MITRE | MTTD rata² (rentang) | MTTR rata² (rentang) | Mitigasi |
|---|---|---|---|---|
| Nmap (1–10)   | T1046     | **2,5 s** (1–6) | — (NO_MITIG) | tidak (recon jaringan, tak ada rule host Wazuh) |
| Hydra (11–20) | T1110     | **1,6 s** (1–4) | **5,3 s** (2–9) | ya — Wazuh 5763 (sshd brute) → firewall-drop |
| Nikto (21–30) | T1595.002 | **2,2 s** (1–4) | **3,1 s** (2–4) | ya — Wazuh **31151** (banjir 400 web) → firewall-drop |

- Verifikasi pemicu mitigasi Nikto = rule **31151** "Multiple web server 400 error codes" (level 10) → **MTTR Nikto VALID**, bukan artefak Hydra.
- SOAR `incidents.db` di-reset (823.263 baris noise historis → 0; backup `incidents.db.bak_preclean_*`). Noise STREAM tak akan terbentuk lagi (filter DROP Logstash aktif).
- Kesehatan akhir: SOC (ES, Kibana, Logstash, SOAR, wazuh-manager, filebeat) semua `active`; Victim (suricata, filebeat, wazuh-agent) semua `active`; `.110` di-unblock.

### SISA ITEM KECIL (non-blok)
- [ ] Integrasi hasil ke `DRAFT-SKRIPSI-FINAL-IQBAL.docx` (Tabel 4.8 + narasi dari `remediasi-pipeline-troubleshooting.md` §7).
- [ ] Rotasi kredensial `elastic` & `testuser`; tinjau sudoers `clocksync`(Kali)/`cti-unblock`(victim) setelah riset.
- [ ] (Track 2, ditunda) migrasi honeypot/Elastic Cloud.

## (HISTORIS) SIAP 30-RUN — sisa langkah
1. (opsi) Kurangi MITIG_TIMEOUT 180→90 agar run lebih cepat (hanya waktu tunggu, tak ubah data).
2. DRY_RUN=1 (validasi query ES semua SID) → 30/30 DRYRUN_OK.
3. Full 30-run → `~/research-archive/2026-06-21_controlled-run/iterations.csv` → Tabel 4.8.
4. (poles) reset SOAR incidents.db, update dokumentasi Bab4.

## (HISTORIS) BLOKER independensi antar-iterasi — SUDAH DIATASI di atas
Active-response mem-blok `.110` di iptables victim. Urutan orchestrator: nmap(1-10) → hydra(11-20) → nikto(21-30). Setelah hydra iter-11 mem-blok `.110`, iterasi 12-30 GAGAL konek (`.110` masih ter-DROP) → NO_DETECT beruntun. SOLUSI: orchestrator harus meng-UNBLOCK `.110` di awal tiap iterasi.
- Rencana: pasang script root `/usr/local/bin/cti-unblock.sh` (loop `iptables -D INPUT -s 192.168.56.110 -j DROP`) di victim + sudoers NOPASSWD untuk `korban`; lalu patch orchestrator panggil unblock sebelum luncurkan serangan tiap iterasi (run_one).

## (HISTORIS) T2 sebelum diperbaiki
Hydra 6 percobaan TERLALU SEDIKIT (< ambang sid 1000020 = 10 koneksi/10dtk). Wordlist diperbesar. (SUDAH DIATASI via ambang 5/60s.)

### LANGKAH BESOK (mulai dari sini)
Step A (SOC) — wordlist 21 baris (password benar di akhir):
```
printf '123456\npassword\nadmin\nletmein\nqwerty\ntest123\nroot\ntoor\n12345678\nabc123\npassword1\nwelcome\nmonkey\ndragon\nmaster\nlogin\npassw0rd\nhello123\nsecret\nchangeme\nTestLab2026!\n' | ssh kali@192.168.56.110 'cat > ~/cti_small.txt && wc -l ~/cti_small.txt'
```
Step B (SOC) — Hydra ulang (~20 percobaan):
```
ssh kali@192.168.56.110 "hydra -l testuser -P /home/kali/cti_small.txt ssh://192.168.56.106 -t 4 -f" 2>&1 | tail -4
```
Step C (SOC) — cek ES (jalankan `read` SENDIRI dulu):
```
read -s -p "Elastic password: " ESPASS; echo
sleep 30
curl -s -k -u elastic:"$ESPASS" "https://192.168.56.10:9200/cti-logs-iqbal-*/_count" -H 'Content-Type: application/json' -d '{"query":{"bool":{"must":[{"term":{"data.alert.signature_id":1000020}},{"range":{"@timestamp":{"gte":"now-5m"}}}]}}}'
curl -s -k -u elastic:"$ESPASS" "https://192.168.56.10:9200/cti-logs-iqbal-*/_search?pretty" -H 'Content-Type: application/json' -d '{"size":3,"sort":[{"@timestamp":{"order":"desc"}}],"query":{"bool":{"must":[{"match_phrase":{"rule.description":"Host Blocked by firewall-drop Active Response"}},{"range":{"@timestamp":{"gte":"now-5m"}}}]}}}' | grep -aE "@timestamp|rule.description|srcip|source"
unset ESPASS
```
Step D (SOC) — iptables victim: `ssh -t korban@192.168.56.106 "sudo iptables -S INPUT | grep DROP"`
Target T2 LULUS: T1 hydra count≥1 + event firewall-drop `.110` + iptables victim DROP `.110` (tanpa `.10`/`.106`).

## SETELAH T2 LULUS — sisa untuk garis finish
1. Reset SOAR `incidents.db` (buang baris uji): stop SOAR → arsip/`DELETE FROM incidents` → start.
2. Sinkron jam Kali↔SOC (offset <2dtk): `ssh kali@192.168.56.110 "sudo date -s @$(date -u +%s)"`.
3. Upload orchestrator (sudah dipatch DRY_RUN) bila perlu, jalankan **DRY_RUN=1** lalu **30 iterasi** → `iterations.csv` → Tabel 4.8.

## PERIKSA DULU BESOK (karena VM sering resume dari saved-state)
- Status: `systemctl is-active suricata` (victim), `logstash soar-dashboard wazuh-manager filebeat` (SOC), `filebeat suricata` (victim).
- Offset jam Kali/victim↔SOC (<2 dtk) — resync bila perlu.
- ES masih hidup; tidak ada flood (count `cti-logs-iqbal-*` stabil).

## CATATAN KEAMANAN (untuk dirotasi setelah riset)
- Password `elastic` & password `testuser` sempat tampil saat troubleshooting → rotasi setelah penelitian.
- Sudoers `clocksync` (NOPASSWD date/timedatectl) di Kali masih aktif.

## BACKUP yang dibuat (untuk rollback)
- `soc-pipeline.conf.bak_remediasi_20260623`, `filebeat.yml.bak_remediasi_20260623` (victim), `suricata.yaml.bak_minrules_20260623` (TIDAK jadi dipakai — kita pilih tambah RAM), `ossec.conf.bak_whitelist_20260623`, `soar_app.py.bak_fdfix_20260623`, `soar_app.py.bak_schema_20260623`.
