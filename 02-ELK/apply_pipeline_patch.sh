#!/bin/bash
set -e

TIMESTAMP=$(date +%s)
sudo cp /etc/logstash/conf.d/soc-pipeline.conf /etc/logstash/conf.d/soc-pipeline.conf.bak.${TIMESTAMP}

cat > /tmp/newblock.txt <<'BLOCK'
  ####################################################################
  # NORMALIZE SIGNATURE ID INTO METADATA
  ####################################################################
  if ! [@metadata][sig_id_str] {
    if [data][alert][signature_id] {
      mutate { add_field => { "[@metadata][sig_id_str]" => "%{[data][alert][signature_id]}" } }
    } else if [alert][signature_id] {
      mutate { add_field => { "[@metadata][sig_id_str]" => "%{[alert][signature_id]}" } }
    } else if [suricata][eve][alert][signature_id] {
      mutate { add_field => { "[@metadata][sig_id_str]" => "%{[suricata][eve][alert][signature_id]}" } }
    } else if [wazuh][data][alert][signature_id] {
      mutate { add_field => { "[@metadata][sig_id_str]" => "%{[wazuh][data][alert][signature_id]}" } }
    }
  }

  if [@metadata][sig_id_str] {
    translate {
      source => "[@metadata][sig_id_str]"
      target => "[mitre][technique_id]"
      dictionary_path => "/etc/logstash/dictionaries/mitre-mapping.yml"
      fallback => "Unmapped"
      refresh_interval => 300
    }

    if [mitre][technique_id] != "Unmapped" {
      translate {
        source => "[mitre][technique_id]"
        target => "[mitre][technique_name]"
        dictionary_path => "/etc/logstash/dictionaries/mitre-id-to-name.yml"
        fallback => "Unknown Name"
        refresh_interval => 300
      }
    } else {
      mutate { add_field => { "[mitre][technique_name]" => "Unmapped" } }
    }
  }
BLOCK

# Insert newblock before first 'output {' occurrence
sudo awk 'BEGIN{inserted=0} { if(!inserted && $0 ~ /^output[[:space:]]*{/) { while((getline line < "/tmp/newblock.txt") > 0) print line; inserted=1 } print }' /etc/logstash/conf.d/soc-pipeline.conf > /tmp/soc-pipeline.conf.new
sudo mv /tmp/soc-pipeline.conf.new /etc/logstash/conf.d/soc-pipeline.conf

# Test config
sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash --config.test_and_exit

# Restart Logstash
sudo systemctl restart logstash

# Wait a moment
sleep 2

# Tail logstash logs
sudo journalctl -u logstash -n 200 --no-pager | tail -n 80

# Re-run ES verification (will prompt for elastic password for each curl)
echo "--- ES sample for 2013504 ---"
curl -s -k -u elastic 'https://localhost:9200/cti-logs-iqbal-*/_search' -H 'Content-Type: application/json' -d '{"size":5,"query":{"term":{"data.alert.signature_id.keyword":"2013504"}},"_source":["@timestamp","data.alert.signature_id","data.alert.signature","mitre"]}' | jq .

echo "--- ES sample for 2033966 ---"
curl -s -k -u elastic 'https://localhost:9200/cti-logs-iqbal-*/_search' -H 'Content-Type: application/json' -d '{"size":5,"query":{"term":{"data.alert.signature_id.keyword":"2033966"}},"_source":["@timestamp","data.alert.signature_id","data.alert.signature","mitre"]}' | jq .

echo "--- ES sample for 2033967 ---"
curl -s -k -u elastic 'https://localhost:9200/cti-logs-iqbal-*/_search' -H 'Content-Type: application/json' -d '{"size":5,"query":{"term":{"data.alert.signature_id.keyword":"2033967"}},"_source":["@timestamp","data.alert.signature_id","data.alert.signature","mitre"]}' | jq .

echo "--- ES count unmapped alerts ---"
curl -s -k -u elastic 'https://localhost:9200/cti-logs-iqbal-*/_count' -H 'Content-Type: application/json' -d '{"query":{"bool":{"must":[{"match":{"event_type":"alert"}}],"must_not":[{"exists":{"field":"mitre.technique_id"}}]}}}' | jq .


echo "Done."
