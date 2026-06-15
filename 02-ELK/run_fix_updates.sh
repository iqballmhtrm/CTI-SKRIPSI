#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <elastic_password>" >&2
  exit 1
fi

ESPASS="$1"

echo "Updating index settings to raise total_fields.limit..."
curl -s -k -u elastic:"$ESPASS" -X PUT 'https://localhost:9200/cti-logs-iqbal-*/_settings' -H 'Content-Type: application/json' -d '{"index.mapping.total_fields.limit":2000}' | jq .

echo "Rerunning update_by_query for SID 2013504..."
curl -s -k -u elastic:"$ESPASS" -X POST 'https://localhost:9200/cti-logs-iqbal-*/_update_by_query?conflicts=proceed&wait_for_completion=true' -H 'Content-Type: application/json' -d '{"script":{"source":"if (ctx._source.mitre == null) ctx._source.mitre = new HashMap(); if (ctx._source.mitre.get(\"technique_id\") == null) ctx._source.mitre.put(\"technique_id\", params.tech);","lang":"painless","params":{"tech":"T1105"}},"query":{"bool":{"must":[{"term":{"alert.signature_id":2013504}}],"must_not":[{"exists":{"field":"mitre.technique_id"}}]}}}' | jq .

echo "Aggregating top unmapped SIDs..."
curl -s -k -u elastic:"$ESPASS" 'https://localhost:9200/cti-logs-iqbal-*/_search' -H 'Content-Type: application/json' -d '{"size":0,"query":{"bool":{"must":[{"match":{"event_type":"alert"}}],"must_not":[{"exists":{"field":"mitre.technique_id"}}]}},"aggs":{"by_alert_sig":{"terms":{"field":"alert.signature_id","size":50}},"by_suricata_sig":{"terms":{"field":"suricata.eve.alert.signature_id","size":50}}}}' | jq .
