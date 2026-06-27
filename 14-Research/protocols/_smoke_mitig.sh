#!/usr/bin/env bash
# Smoke test terisolasi untuk first_mitigation_epoch di bawah set -euo pipefail.
# Stub es() dan jq() supaya tidak butuh ES/jq nyata; fokus: cek exit prematur.
set -euo pipefail

ES="x"; INDEX="x"; ATTACKER_IP="1.2.3.4"
es()  { printf '%s' '{"hits":{"hits":[]}}'; }   # response valid, tanpa hits
jq()  { printf '%s' ''; }                        # simulasikan @timestamp kosong -> ts kosong

# Ambil HANYA definisi first_mitigation_epoch dari script yang sudah dipatch
source <(sed -n '/^first_mitigation_epoch() {/,/^}/p' run_controlled_iterations.sh)

echo "== TEST 1: panggil 1 argumen (pola run sungguhan) =="
out1=$(first_mitigation_epoch "2026-01-01T00:00:00.000Z")
echo "  OK: returned=[$out1] (fungsi tidak exit prematur, set -e tidak menghentikan script)"

echo "== TEST 2: panggil 2 argumen (pola dry-run, rawfile terisi) =="
rm -f ./_mitig_raw.json
out2=$(first_mitigation_epoch "2026-01-01T00:00:00.000Z" ./_mitig_raw.json)
echo "  returned=[$out2]"
if [ -f ./_mitig_raw.json ]; then
  echo "  OK: rawfile DITULIS -> isi: $(cat ./_mitig_raw.json)"
else
  echo "  GAGAL: rawfile tidak ditulis"; exit 3
fi
rm -f ./_mitig_raw.json

echo "ALL SMOKE TESTS PASSED"
