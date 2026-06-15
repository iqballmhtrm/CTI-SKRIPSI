#!/usr/bin/env bash
set -euo pipefail

ES="https://localhost:9200"
KIBANA="https://localhost:5601"
PASS="$1"
MAPPING_FILE="/etc/logstash/dictionaries/mitre-mapping.yml"
INDEX="cti-logs-iqbal-*"
SNAP_REPO_NAME="cti_backup"

echo "--- START: retro-enrichment script ---"

# Check existing snapshot repositories
echo "Checking existing snapshot repositories..."
repos=$(curl -s -k -u elastic:"$PASS" "$ES/_snapshot" | jq -r 'keys[]?') || repos=""
if [ -n "$repos" ]; then
  repo=$(echo "$repos" | head -n1)
  echo "Using existing snapshot repo: $repo"
else
  repo="$SNAP_REPO_NAME"
  echo "Attempting to register FS snapshot repo at /tmp/cti-snapshots"
  mkdir -p /tmp/cti-snapshots || true
  put_out=$(curl -s -k -u elastic:"$PASS" -X PUT "$ES/_snapshot/$repo" -H 'Content-Type: application/json' -d '{"type":"fs","settings":{"location":"/tmp/cti-snapshots","compress":true}}' 2>&1) || true
  echo "$put_out" | jq -r . || echo "$put_out"
  ok=$(echo "$put_out" | jq -r '.acknowledged' 2>/dev/null || echo "false")
  if [ "$ok" != "true" ]; then
    echo "Snapshot repository registration failed or not allowed; proceeding WITHOUT snapshot." >&2
    repo=""
  else
    echo "Snapshot repo $repo created"
  fi
fi

if [ -n "$repo" ]; then
  SNAPNAME="snap_$(date +%s)"
  echo "Creating snapshot $repo/$SNAPNAME for indices $INDEX"
  curl -s -k -u elastic:"$PASS" -X PUT "$ES/_snapshot/$repo/$SNAPNAME?wait_for_completion=true" -H 'Content-Type: application/json' -d "{\"indices\":\"$INDEX\",\"include_global_state\":false}" | jq || true
else
  echo "Skipping snapshot step."
fi

# Perform update_by_query for each mapping entry
if [ -f "$MAPPING_FILE" ]; then
  echo "Applying retro-enrichment from $MAPPING_FILE (Optimized Batch)"
  declare -A tech_sids
  
  while read -r SID TECH; do
    if [ -z "$SID" ] || [ -z "$TECH" ]; then
      continue
    fi
    tech_sids["$TECH"]+="$SID "
  done < <(awk -F': ' '/^[0-9]/{print $1 " " $2}' "$MAPPING_FILE" | tr -d '\r')

  for tech in "${!tech_sids[@]}"; do
    sids_str="${tech_sids[$tech]}"
    echo "Applying mapping for technique: $tech (SIDs: $sids_str)"
    TMP=$(mktemp)
    jq -n \
      --arg tech "$tech" \
      --arg sids_str "$sids_str" \
      '{
      script: {
        source: "if (ctx._source.mitre == null) { ctx._source.mitre = new HashMap(); } ctx._source.mitre.put(\"technique_id\", params.tech);",
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
          "minimum_should_match": 1,
          "must_not": [
            {"exists": {"field": "mitre.technique_id"}}
          ]
        }
      }
    }' > "$TMP"
    curl -s -k -u elastic:"$PASS" -X POST "$ES/$INDEX/_update_by_query?conflicts=proceed&wait_for_completion=true" -H 'Content-Type: application/json' --data-binary @"$TMP" | jq || true
    rm -f "$TMP"
  done
else
  echo "Mapping file not found: $MAPPING_FILE" >&2
fi

# Count unmapped
echo "Counting unmapped events..."
curl -s -k -u elastic:"$PASS" "$ES/$INDEX/_count" -H 'Content-Type: application/json' -d '{"query":{"bool":{"must":[{"match":{"event_type":"alert"}}],"must_not":[{"exists":{"field":"mitre.technique_id"}}]}}}' | jq

# Import dashboard to Kibana if uploaded to /tmp
if [ -f /tmp/dashboard-final.ndjson ]; then
  echo "Importing dashboard to Kibana..."
  curl -s -k -u elastic:"$PASS" -H 'kbn-xsrf: true' -F file=@/tmp/dashboard-final.ndjson "$KIBANA/api/saved_objects/_import?overwrite=true" | jq || true
else
  echo "/tmp/dashboard-final.ndjson not found, skipping dashboard import." >&2
fi

# Cleanup
rm -f /tmp/run_mitre_updates.sh
rm -f /tmp/dashboard-final.ndjson

echo "--- DONE: retro-enrichment script ---"
