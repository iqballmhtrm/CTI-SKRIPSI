import json
import urllib.request
import ssl
import base64

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

pwd = "lflqgBlynmWIBHgzvN17lvZ1Lz34qAxn"

auth = base64.b64encode(f"elastic:{pwd}".encode()).decode()
# We query only documents that actually have an alert (i.e. have @metadata.sig_id_str? Wait, @metadata isn't indexed in Elasticsearch! It's dropped!)
# We should query documents that have `event.module` as `suricata` or `wazuh` OR just any document where `rule.level` or `alert.severity` exists.
req = urllib.request.Request(
    "https://localhost:9200/cti-logs-iqbal-*/_search?size=20",
    data=json.dumps({
        "query": {
            "bool": {
                "should": [
                    {"exists": {"field": "wazuh.data.alert.signature"}},
                    {"exists": {"field": "alert.signature"}},
                    {"exists": {"field": "suricata.eve.alert.signature"}}
                ],
                "minimum_should_match": 1
            }
        }
    }).encode(),
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Basic {auth}"
    }
)

try:
    with urllib.request.urlopen(req, context=ctx) as response:
        res = json.loads(response.read().decode())
except Exception as e:
    print("FAILED TO CONNECT ELASTIC:", e)
    import sys
    sys.exit(1)

hits = res.get('hits', {}).get('hits', [])
print("========================================")
print(f"DIKETEMUKAN {len(hits)} DOKUMEN ALERT")
print("========================================")

fields_coverage = {
    "@timestamp": 0,
    "source.ip": 0,
    "attack_type": 0,
    "severity": 0,
    "mitre.technique_name": 0
}

samples = []

for h in hits:
    src = h['_source']
    ts = src.get('@timestamp')
    src_ip = src.get('source', {}).get('ip')
    
    # Extracting like the Logstash mutate filter
    attack_type = None
    if 'wazuh' in src and 'data' in src['wazuh'] and 'alert' in src['wazuh']['data']:
        attack_type = src['wazuh']['data']['alert'].get('signature')
    elif 'alert' in src and 'signature' in src['alert']:
        attack_type = src['alert'].get('signature')
    elif 'suricata' in src and 'eve' in src['suricata'] and 'alert' in src['suricata']['eve']:
        attack_type = src['suricata']['eve']['alert'].get('signature')
        
    severity = None
    if 'wazuh' in src and 'data' in src['wazuh'] and 'rule' in src['wazuh']['data']:
        severity = src['wazuh']['data']['rule'].get('level')
    elif 'alert' in src and 'severity' in src['alert']:
        severity = src['alert'].get('severity')
    elif 'suricata' in src and 'eve' in src['suricata'] and 'alert' in src['suricata']['eve']:
        severity = src['suricata']['eve']['alert'].get('severity')
        
    mitre = src.get('mitre', {}).get('technique_name')
    
    if ts: fields_coverage['@timestamp'] += 1
    if src_ip: fields_coverage['source.ip'] += 1
    if attack_type: fields_coverage['attack_type'] += 1
    if severity: fields_coverage['severity'] += 1
    if mitre: fields_coverage['mitre.technique_name'] += 1
    
    samples.append({
        "timestamp_alert": ts,
        "src_ip": src_ip,
        "attack_type": attack_type,
        "severity": severity,
        "mitre_technique": mitre,
        "pipeline_source": "logstash_http"
    })

print("\n--- SAMPLE 5 EVENT TERBARU ---")
for s in samples[:5]:
    print(json.dumps(s, indent=2))

print("\n--- COVERAGE ---")
total = len(hits)
if total == 0:
    print("TIDAK ADA DATA")
else:
    for k, v in fields_coverage.items():
        pct = (v / total) * 100
        print(f"{k}: {v}/{total} ({pct:.0f}%)")
