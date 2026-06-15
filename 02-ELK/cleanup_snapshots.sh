#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <elastic_password> [repo_name] [keep_days]" >&2
  exit 2
fi

PASS="$1"
REPO="${2:-cti_backup}"
KEEP_DAYS="${3:-7}"
ES="https://localhost:9200"

echo "Fetching snapshots from repository: $REPO"
SNAPSHOTS=$(curl -s -k -u elastic:"$PASS" "$ES/_snapshot/$REPO/_all" | jq -c '.snapshots[]? | {snapshot: .snapshot, start_time_in_millis: .start_time_in_millis}')

if [ -z "$SNAPSHOTS" ] || [ "$SNAPSHOTS" == "null" ]; then
  echo "No snapshots found or repository does not exist."
  exit 0
fi

CURRENT_TIME=$(date +%s%3N)
# Calculate ms threshold
THRESHOLD_MS=$(( KEEP_DAYS * 24 * 60 * 60 * 1000 ))
CUTOFF_TIME=$(( CURRENT_TIME - THRESHOLD_MS ))

echo "Cleaning up snapshots older than $KEEP_DAYS days..."
for snap in $SNAPSHOTS; do
  SNAP_NAME=$(echo "$snap" | jq -r '.snapshot')
  SNAP_TIME=$(echo "$snap" | jq -r '.start_time_in_millis')

  if [ "$SNAP_TIME" -lt "$CUTOFF_TIME" ]; then
    echo "Deleting snapshot: $SNAP_NAME (Older than $KEEP_DAYS days)"
    curl -s -k -u elastic:"$PASS" -X DELETE "$ES/_snapshot/$REPO/$SNAP_NAME" | jq . || true
  else
    echo "Keeping snapshot: $SNAP_NAME"
  fi
done

echo "Snapshot cleanup completed."