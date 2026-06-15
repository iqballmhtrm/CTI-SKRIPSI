#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <elastic_password>" >&2
  exit 2
fi
PASS="$1"
MAPFILE="/tmp/mitre-mapping.yml"
ES='https://localhost:9200'
INDEX='cti-logs-iqbal-*'

if [ ! -f "$MAPFILE" ]; then
  echo "Mapping file $MAPFILE not found" >&2
  exit 1
fi

while IFS= read -r line; do
  # skip comments and empty lines
  [[ -z "$line" ]] && continue
  [[ "$line" =~ ^# ]] && continue
  sid=$(echo "$line" | awk -F': ' '{print $1}')
  tech=$(echo "$line" | awk -F': ' '{print $2}' | tr -d '\r')
  if [[ -z "$sid" || -z "$tech" ]]; then
    continue
  fi
  echo "Applying $sid -> $tech"

  jq -n --arg tech "$tech" --argjson sid "$sid" '{
    "script": {
      "source": "if (ctx._source.mitre == null) ctx._source.mitre = new HashMap(); ctx._source.mitre.put(\"technique_id\", params.tech);",
      "lang": "painless",
      "params": {"tech": $tech}
    },
    "query": {
      "bool": {
        "should": [
          {"term": {"alert.signature_id": $sid}},
          {"term": {"suricata.eve.alert.signature_id": $sid}},
          {"term": {"data.alert.signature_id": $sid}}
        ],
        "minimum_should_match": 1,
        "must_not": [
          {"exists": {"field": "mitre.technique_id"}}
        ]
      }
    }
  }' > "/tmp/payload_${sid}.json"

  curl -s -k -u elastic:"$PASS" -X POST "$ES/$INDEX/_update_by_query?conflicts=proceed&wait_for_completion=true" -H 'Content-Type: application/json' --data-binary @"/tmp/payload_${sid}.json" | jq . || true
  rm -f "/tmp/payload_${sid}.json"
done < "$MAPFILE"

echo "Done applying cleaned mappings"
