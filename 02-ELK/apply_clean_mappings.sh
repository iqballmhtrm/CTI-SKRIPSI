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

declare -A tech_sids

echo "Reading mapping file and grouping SIDs by technique..."
while IFS= read -r line; do
  # skip comments and empty lines
  [[ -z "$line" ]] && continue
  [[ "$line" =~ ^# ]] && continue
  sid=$(echo "$line" | awk -F': ' '{print $1}' | tr -d ' ')
  tech=$(echo "$line" | awk -F': ' '{print $2}' | tr -d '\r ')
  if [[ -z "$sid" || -z "$tech" ]]; then
    continue
  fi
  tech_sids["$tech"]+="$sid "
done < "$MAPFILE"

for tech in "${!tech_sids[@]}"; do
  sids_str="${tech_sids[$tech]}"
  echo "Applying mapping for technique: $tech (SIDs: $sids_str)"
  tmp=/tmp/payload_${tech}.json
  
  jq -n \
    --arg tech "$tech" \
    --arg sids_str "$sids_str" \
    '{
      script: {
        source: "if (ctx._source.mitre == null) ctx._source.mitre = new HashMap(); ctx._source.mitre.put(\"technique_id\", params.tech);",
        lang: "painless",
        params: {tech: $tech}
      },
      query: {
        bool: {
          should: [
            {terms: {"alert.signature_id": ($sids_str | split(" ") | map(select(length > 0) | tonumber))}},
            {terms: {"suricata.eve.alert.signature_id": ($sids_str | split(" ") | map(select(length > 0) | tonumber))}},
            {terms: {"data.alert.signature_id": ($sids_str | split(" ") | map(select(length > 0) | tonumber))}}
          ],
          minimum_should_match: 1
        }
      }
    }' > "$tmp"

  curl -s -k -u elastic:"$PASS" -X POST "$ES/$INDEX/_update_by_query?conflicts=proceed&wait_for_completion=true" -H 'Content-Type: application/json' --data-binary @"$tmp" | jq . || true
  rm -f "$tmp"
done

echo "Done applying cleaned mappings"
