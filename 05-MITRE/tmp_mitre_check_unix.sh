#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run this script with sudo." >&2
  exit 1
fi

echo "Collecting observed SIDs from /var/log/suricata/eve.json..."
if test -f /var/log/suricata/eve.json; then
  grep -o '"signature_id":[0-9]*' /var/log/suricata/eve.json 2>/dev/null | grep -o '[0-9]\+' | sort | uniq > /tmp/observed_sids.txt || true
  echo "Found $(wc -l < /tmp/observed_sids.txt) unique observed SIDs."
else
  echo "No /var/log/suricata/eve.json found"
fi

echo "Collecting mapped SIDs from /etc/logstash/dictionaries/mitre-mapping.yml..."
if test -f /etc/logstash/dictionaries/mitre-mapping.yml; then
  grep -oP '"\K[0-9]{4,7}(?="\s*:\s*" )' /etc/logstash/dictionaries/mitre-mapping.yml 2>/dev/null | sort > /tmp/mapped_sids.txt || true
  # Fallback if -P not supported
  if [ ! -s /tmp/mapped_sids.txt ]; then
    grep -o '"[0-9]\{4,7\}"\s*:' /etc/logstash/dictionaries/mitre-mapping.yml 2>/dev/null | grep -o '[0-9]\+' | sort > /tmp/mapped_sids.txt || true
  fi
  echo "Found $(wc -l < /tmp/mapped_sids.txt || echo 0) mapped SIDs."
else
  echo "No mapping file"
fi

echo "Computing unmapped SIDs..."
if [ -f /tmp/observed_sids.txt ]; then
  comm -23 /tmp/observed_sids.txt /tmp/mapped_sids.txt | tee /tmp/unmapped_sids.txt || true
  echo "Unmapped count: $(wc -l < /tmp/unmapped_sids.txt || echo 0)"
  echo "First 100 unmapped:"
  head -n 100 /tmp/unmapped_sids.txt || true
else
  echo "No observed sids file to compare"
fi

echo "MITRE mapping snippet (1-200):"
sed -n '1,200p' /etc/logstash/dictionaries/mitre-mapping.yml || true

echo "Done."
