#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <elastic_password>" >&2
  exit 1
fi

PASS="$1"
ES="https://localhost:9200"
INDEX="cti-logs-iqbal-*"

echo "[+] Menghapus field 'mitre' dari seluruh log di indeks $INDEX..."

curl -s -k -u elastic:"$PASS" -X POST "$ES/$INDEX/_update_by_query?conflicts=proceed&wait_for_completion=true" -H 'Content-Type: application/json' -d'
{
  "script": {
    "source": "ctx._source.remove(\"mitre\")",
    "lang": "painless"
  },
  "query": {
    "exists": {
      "field": "mitre.technique_id"
    }
  }
}' | jq .

echo -e "\n[+] Reset pemetaan MITRE selesai."