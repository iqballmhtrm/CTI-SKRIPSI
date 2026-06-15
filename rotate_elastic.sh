#!/bin/bash
set -euo pipefail

read -s -p "Current elastic password: " OLD_PASS
echo

# Generate a strong new password (fallback if openssl missing)
if command -v openssl >/dev/null 2>&1; then
  NEW_PASS=$(openssl rand -base64 24)
else
  NEW_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)
fi

echo
cat <<EOF
=== NEW ELASTIC PASSWORD (copy/save now) ===
$NEW_PASS
============================================
EOF

echo "Updating elastic password in Elasticsearch..."
resp=$(curl -s -k -u "elastic:${OLD_PASS}" -X POST "https://localhost:9200/_security/user/elastic/_password" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"${NEW_PASS}\"}" || true)

if command -v jq >/dev/null 2>&1; then
  echo "$resp" | jq .
else
  echo "$resp"
fi

echo "Updating Logstash keystore (ELASTIC_PASS)..."
# remove existing key if present (ignore errors)
sudo /usr/share/logstash/bin/logstash-keystore remove --path.settings /etc/logstash ELASTIC_PASS 2>/dev/null || true
# add new value from stdin
printf '%s' "${NEW_PASS}" | sudo /usr/share/logstash/bin/logstash-keystore add --path.settings /etc/logstash --stdin ELASTIC_PASS

echo "Restarting Logstash..."
sudo systemctl restart logstash
sudo systemctl status logstash --no-pager -l | sed -n '1,200p'

echo "Checking Elasticsearch cluster health with new credential..."
curl -s -k -u "elastic:${NEW_PASS}" 'https://localhost:9200/_cluster/health?pretty' || true

echo "Done. Please store the NEW ELASTIC password securely and update other services if needed." 
