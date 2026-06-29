#!/usr/bin/env bash
# =====================================================================
# run_controlled_iterations.sh  — ORCHESTRATOR 30 CONTROLLED ITERATIONS
# PROTOKOL UTAMA: 30 iterasi (10 Nmap + 10 Hydra + 10 Nikto/Skenario C).
# Nikto AKTIF secara default (RUN_NIKTO=1); set RUN_NIKTO=0 untuk melewatinya.
# Jalankan DI SOC SERVER (192.168.56.10) SETELAH pre-flight P0-P4.
# STATUS: TEMPLATE — JANGAN jalankan tanpa konfirmasi & penyesuaian variabel.
#
# Usage:  ./run_controlled_iterations.sh <ELASTIC_PASSWORD>            # 30 iterasi (default)
#         RUN_NIKTO=0 ./run_controlled_iterations.sh <ELASTIC_PASSWORD> # hanya 20 (Nmap+Hydra)
#
# Metrik (Tabel 4.8 naskah):  MTTD = T1 - T0 ;  MTTR = T2 - T0
# T1: data.alert.signature_id == SID ; T2: rule.description == "Host Blocked by firewall-drop Active Response"
# Mengukur T0 (launch), T1 (alert pertama di ES), T2 (mitigasi firewall-drop)
# per iterasi, lalu menulis ke iterations.csv TERPISAH dari incidents.db lama.
# =====================================================================
set -euo pipefail

if [ "$#" -lt 1 ]; then echo "Usage: $0 <ELASTIC_PASSWORD>" >&2; exit 2; fi
ESPASS="$1"
DRY_RUN="${DRY_RUN:-0}"   # 1 = verifikasi query ES saja, tanpa serangan nyata

# ---------------- KONFIGURASI (sesuaikan) ----------------
ES="https://localhost:9200"
INDEX="cti-logs-iqbal-*"
ATTACKER_SSH="kali@192.168.56.110"     # ssh key SOC->Kali sudah terpasang (passwordless)
ATTACKER_IP="192.168.56.110"
VICTIM="192.168.56.106"
VICTIM_SSH="korban@192.168.56.106"     # ssh key SOC->victim sudah terpasang (untuk reset blokir antar-iterasi)
if [ "$DRY_RUN" = "1" ]; then
  OUTDIR="/home/iqbal/research-archive/2026-06-21_controlled-run_DRYRUN"
else
  OUTDIR="/home/iqbal/research-archive/2026-06-21_controlled-run"
fi
CSV="$OUTDIR/iterations.csv"
RAW="$OUTDIR/raw"
DETECT_TIMEOUT=120     # detik tunggu T1
MITIG_TIMEOUT=90      # detik tunggu T2 (firewall-drop); hydra blokir ~30-50s, nmap/nikto tanpa mitigasi
GAP=60                 # jeda antar iterasi (reset threshold rule)
SSH_WORDLIST="/home/kali/cti_small.txt"   # wordlist KECIL terkontrol (dibuat saat pre-flight)
SSH_USER="testuser"                                  # akun uji di victim
RUN_NIKTO="${RUN_NIKTO:-1}"                          # default 1 (Nikto = Skenario C resmi); set 0 utk lewati
# ---------------------------------------------------------

mkdir -p "$RAW"
[ -f "$CSV" ] || echo "iter,type,sid,T0_epoch,T1_epoch,T2_epoch,MTTD_s,MTTR_s,src_ip,status" > "$CSV"

es() { curl -s -k --connect-timeout 5 --max-time 20 -u elastic:"$ESPASS" "$@"; }

# Ambil epoch @timestamp event pertama utk SID & src tertentu sejak since_epoch
first_alert_epoch() {
  local sid="$1" since="$2" rawfile="$3"
  local body
  body=$(cat <<JSON
{ "size":1, "sort":[{"@timestamp":{"order":"asc"}}],
  "query":{"bool":{"must":[
    {"term":{"data.alert.signature_id":$sid}},
    {"range":{"@timestamp":{"gte":"$since"}}}
  ],"should":[
    {"term":{"source.ip":"$ATTACKER_IP"}}
  ]}},
  "_source":["@timestamp","data.alert.signature_id","source.ip","mitre"] }
JSON
)
  local resp; resp=$(es "$ES/$INDEX/_search" -H 'Content-Type: application/json' -d "$body")
  echo "$resp" > "$rawfile"
  local ts; ts=$(echo "$resp" | jq -r '.hits.hits[0]._source["@timestamp"] // empty')
  [ -n "$ts" ] && date -u -d "$ts" +%s || echo ""
}

# Ambil epoch event mitigasi firewall-drop utk src attacker sejak since_epoch
first_mitigation_epoch() {
  local since="$1" rawfile="${2:-}"
  local body
  body=$(cat <<JSON
{ "size":1, "sort":[{"@timestamp":{"order":"asc"}}],
  "query":{"bool":{"must":[
    {"match_phrase":{"rule.description":"Host Blocked by firewall-drop Active Response"}},
    {"range":{"@timestamp":{"gte":"$since"}}}
  ]}}, "_source":["@timestamp"] }
JSON
)
  local resp; resp=$(es "$ES/$INDEX/_search" -H 'Content-Type: application/json' -d "$body")
  if [ -n "$rawfile" ]; then echo "$resp" > "$rawfile"; fi
  local ts; ts=$(echo "$resp" | jq -r '.hits.hits[0]._source["@timestamp"] // empty')
  [ -n "$ts" ] && date -u -d "$ts" +%s || echo ""
}

run_one() {
  local iter="$1" type="$2" sid="$3" cmd="$4"
  echo "=== ITER $iter | $type | SID $sid ==="
  # Reset blokir attacker di victim agar tiap iterasi independen (skip saat DRY_RUN)
  if [ "$DRY_RUN" != "1" ]; then ssh -o StrictHostKeyChecking=no "$VICTIM_SSH" "sudo -n /usr/local/sbin/cti-unblock.sh" >/dev/null 2>&1 || true; sleep 2; fi
  local T0 T0_iso; T0=$(date -u +%s); T0_iso=$(date -u -d "@$T0" +%Y-%m-%dT%H:%M:%S.000Z)

  if [ "$DRY_RUN" = "1" ]; then
    local d1="$RAW/dryrun_iter_$(printf %02d $iter)_T1.json"
    local d2="$RAW/dryrun_iter_$(printf %02d $iter)_T2.json"
    echo "  [DRY_RUN] WOULD RUN on $ATTACKER_SSH :: $cmd"
    echo "  [DRY_RUN] cek query ES T1 (sid=$sid) & T2 (firewall-drop) ..."
    local r1 r2; r1=$(first_alert_epoch "$sid" "$T0_iso" "$d1"); r2=$(first_mitigation_epoch "$T0_iso" "$d2")
    if grep -q '"error"' "$d1" "$d2" 2>/dev/null; then
      echo "  [DRY_RUN] ES ERROR (cek auth/index/field):"; head -c 400 "$d1"; echo; head -c 400 "$d2"; echo
      echo "$iter,$type,$sid,$T0,,,,,$ATTACKER_IP,DRYRUN_ES_ERROR" >> "$CSV"
    else
      echo "  [DRY_RUN] ES OK (T1&T2 JSON valid; T1_found=${r1:-none} T2_found=${r2:-none})"
      echo "$iter,$type,$sid,$T0,,,,,$ATTACKER_IP,DRYRUN_OK" >> "$CSV"
    fi
    return 0
  fi

  # Luncurkan serangan async dari attacker
  ssh "$ATTACKER_SSH" "$cmd" >/dev/null 2>&1 &
  local atk_pid=$!

  # Poll T1
  local T1=""; local waited=0
  while [ -z "$T1" ] && [ $waited -lt $DETECT_TIMEOUT ]; do
    sleep 2; waited=$((waited+2))
    T1=$(first_alert_epoch "$sid" "$T0_iso" "$RAW/iter_$(printf %02d $iter).json")
  done

  # Poll T2 (mitigasi) sejak T1 (atau T0 bila T1 kosong)
  local since_iso; since_iso=$([ -n "$T1" ] && date -u -d "@$T1" +%Y-%m-%dT%H:%M:%S.000Z || echo "$T0_iso")
  local T2=""; waited=0
  while [ -z "$T2" ] && [ $waited -lt $MITIG_TIMEOUT ]; do
    sleep 3; waited=$((waited+3))
    T2=$(first_mitigation_epoch "$since_iso")
  done

  wait "$atk_pid" 2>/dev/null || true

  local mttd="" mttr="" status="OK"
  [ -n "$T1" ] && mttd=$((T1-T0)) || status="NO_DETECT"
  # MTTR = T2 - T0 (Tabel 4.8 naskah)
  [ -n "$T2" ] && mttr=$((T2-T0)) || status="${status};NO_MITIG"
  echo "$iter,$type,$sid,$T0,${T1:-},${T2:-},${mttd:-},${mttr:-},$ATTACKER_IP,$status" >> "$CSV"
  echo "  T0=$T0 T1=${T1:-NA} T2=${T2:-NA} MTTD=${mttd:-NA}s MTTR=${mttr:-NA}s status=$status"
  echo "  (jeda ${GAP}s)"; sleep "$GAP"
}

# ---------------- 20 ITERASI UTAMA (Nmap + Hydra) ----------------
for i in $(seq 1 10);  do run_one "$i"  "nmap"  1000010 "nmap -sS -T4 -p 1-1000 $VICTIM"; done
for i in $(seq 11 20); do run_one "$i"  "hydra" 1000020 "hydra -l $SSH_USER -P $SSH_WORDLIST ssh://$VICTIM -t 4 -f"; done

# ---------------- 10 ITERASI SKENARIO C (Nikto) — default aktif, RUN_NIKTO=0 utk lewati ----------------
if [ "$RUN_NIKTO" = "1" ]; then
  echo "### Skenario C (Nikto) — bagian protokol utama ###"
  for i in $(seq 21 30); do run_one "$i" "nikto" 1000030 "nikto -h http://$VICTIM"; done
else
  echo "### Skenario C (Nikto) DILEWATI (RUN_NIKTO=0) — hanya 20 iterasi ###"
fi

echo "=== SELESAI. Hasil: $CSV ==="
column -t -s, "$CSV"
