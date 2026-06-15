#!/usr/bin/env bash
set -euo pipefail
PASS="$1"
SID="$2"

echo "=== Samples for SID $SID ==="
curl -s -k -u elastic:"$PASS" 'https://localhost:9200/cti-logs-iqbal-*/_search' -H 'Content-Type: application/json' -d "{\"size\":5,\"_source\":[\"@timestamp\",\"alert\",\"suricata\"],\"query\":{\"bool\":{\"must\":[{\"term\":{\"alert.signature_id\":$SID}},{\"match\":{\"event_type\":\"alert\"}}],\"must_not\":[{\"exists\":{\"field\":\"mitre.technique_id\"}}]}}}" | jq .
