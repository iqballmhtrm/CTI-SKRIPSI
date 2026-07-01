#!/usr/bin/env bash
set -euo pipefail

# Copy mapping for readability
sudo cp /etc/logstash/dictionaries/mitre-mapping.yml /tmp/mitre-mapping.yml
sudo chown iqbal:iqbal /tmp/mitre-mapping.yml
sudo chmod 640 /tmp/mitre-mapping.yml

# Prepend new MAPPING_FILE line and remove existing MAPPING_FILE lines
sudo awk 'BEGIN{print "MAPPING_FILE=\"/tmp/mitre-mapping.yml\""} { if ($0 !~ /^MAPPING_FILE=/) print }' /tmp/run_mitre_updates.sh.orig > /tmp/run_mitre_updates.sh.mod
sudo mv /tmp/run_mitre_updates.sh.mod /tmp/run_mitre_updates.sh.orig
sudo chown iqbal:iqbal /tmp/run_mitre_updates.sh.orig
sudo chmod +x /tmp/run_mitre_updates.sh.orig

# Execute the runner (pass-through supplied password will be used by the calling ssh command)
# The caller should pass the elastic password as $1
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <elastic_password>" >&2
  exit 2
fi

/tmp/run_mitre_updates.sh.orig "$1"
