#!/usr/bin/env python3
# Patcher DRY_RUN untuk run_controlled_iterations.sh
# Membaca dari .bak (asli pristine) -> menulis ke file target. .bak tidak pernah tertimpa.
src = "run_controlled_iterations.sh.bak_20260621"
dst = "run_controlled_iterations.sh"
s = open(src, encoding="utf-8").read(); orig = s

# 1) DRY_RUN var
a = 'ESPASS="$1"\n'
assert s.count(a) == 1, "anchor1"
s = s.replace(a, 'ESPASS="$1"\nDRY_RUN="${DRY_RUN:-0}"   # 1 = verifikasi query ES saja, tanpa serangan nyata\n', 1)

# 5) OUTDIR terpisah saat dry-run
a = 'OUTDIR="/home/iqbal/research-archive/2026-06-21_controlled-run"\n'
assert s.count(a) == 1, "anchor5"
s = s.replace(a,
  'if [ "$DRY_RUN" = "1" ]; then\n'
  '  OUTDIR="/home/iqbal/research-archive/2026-06-21_controlled-run_DRYRUN"\n'
  'else\n'
  '  OUTDIR="/home/iqbal/research-archive/2026-06-21_controlled-run"\n'
  'fi\n', 1)

# 2) wordlist path
a = 'SSH_WORDLIST="/usr/share/wordlists/cti_small.txt"   # wordlist KECIL terkontrol'
assert s.count(a) == 1, "anchor2"
s = s.replace(a, 'SSH_WORDLIST="/home/kali/cti_small.txt"   # wordlist KECIL terkontrol (dibuat saat pre-flight)', 1)

# 4) timeout es()
a = 'es() { curl -s -k -u elastic:"$ESPASS" "$@"; }'
assert s.count(a) == 1, "anchor4"
s = s.replace(a, 'es() { curl -s -k --connect-timeout 5 --max-time 20 -u elastic:"$ESPASS" "$@"; }', 1)

# 6a) first_mitigation_epoch: tambah param rawfile opsional (kompatibel mundur)
a = 'first_mitigation_epoch() {\n  local since="$1"\n  local body\n'
assert s.count(a) == 1, "anchor6a"
s = s.replace(a, 'first_mitigation_epoch() {\n  local since="$1" rawfile="${2:-}"\n  local body\n', 1)

# 6b) tulis raw response secara aman (Opsi B: if...fi, aman di set -e)
a = ('  local resp; resp=$(es "$ES/$INDEX/_search" -H \'Content-Type: application/json\' -d "$body")\n'
     '  local ts; ts=$(echo "$resp" | jq -r \'.hits.hits[0]._source["@timestamp"] // empty\')\n')
assert s.count(a) == 1, "anchor6b (harus unik utk mitigation, alert punya baris echo di antaranya)"
s = s.replace(a,
     '  local resp; resp=$(es "$ES/$INDEX/_search" -H \'Content-Type: application/json\' -d "$body")\n'
     '  if [ -n "$rawfile" ]; then echo "$resp" > "$rawfile"; fi\n'
     '  local ts; ts=$(echo "$resp" | jq -r \'.hits.hits[0]._source["@timestamp"] // empty\')\n', 1)

# 3) cabang DRY_RUN di run_one (d1=T1, d2=T2, cek error dari KEDUANYA)
a = ('  local T0 T0_iso; T0=$(date -u +%s); T0_iso=$(date -u -d "@$T0" +%Y-%m-%dT%H:%M:%S.000Z)\n'
     '\n  # Luncurkan serangan async dari attacker\n')
assert s.count(a) == 1, "anchor3"
b = ('  local T0 T0_iso; T0=$(date -u +%s); T0_iso=$(date -u -d "@$T0" +%Y-%m-%dT%H:%M:%S.000Z)\n'
     '\n'
     '  if [ "$DRY_RUN" = "1" ]; then\n'
     '    local d1="$RAW/dryrun_iter_$(printf %02d $iter)_T1.json"\n'
     '    local d2="$RAW/dryrun_iter_$(printf %02d $iter)_T2.json"\n'
     '    echo "  [DRY_RUN] WOULD RUN on $ATTACKER_SSH :: $cmd"\n'
     '    echo "  [DRY_RUN] cek query ES T1 (sid=$sid) & T2 (firewall-drop) ..."\n'
     '    local r1 r2; r1=$(first_alert_epoch "$sid" "$T0_iso" "$d1"); r2=$(first_mitigation_epoch "$T0_iso" "$d2")\n'
     '    if grep -q \'"error"\' "$d1" "$d2" 2>/dev/null; then\n'
     '      echo "  [DRY_RUN] ES ERROR (cek auth/index/field):"; head -c 400 "$d1"; echo; head -c 400 "$d2"; echo\n'
     '      echo "$iter,$type,$sid,$T0,,,,,$ATTACKER_IP,DRYRUN_ES_ERROR" >> "$CSV"\n'
     '    else\n'
     '      echo "  [DRY_RUN] ES OK (T1&T2 JSON valid; T1_found=${r1:-none} T2_found=${r2:-none})"\n'
     '      echo "$iter,$type,$sid,$T0,,,,,$ATTACKER_IP,DRYRUN_OK" >> "$CSV"\n'
     '    fi\n'
     '    return 0\n'
     '  fi\n'
     '\n  # Luncurkan serangan async dari attacker\n')
s = s.replace(a, b, 1)

assert s != orig, "no change"
open(dst, "w", encoding="utf-8", newline="\n").write(s)
print("PATCH OK")
