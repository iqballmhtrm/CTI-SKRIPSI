
import json

with open(r"C:\Users\mohiq\VirtualBox VMs\CTI-Skripsi\06-Dashboard\dashboard-before-repair.ndjson", "r", encoding="utf-8") as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if not line.strip():
        continue
    try:
        obj = json.loads(line)
        # Fix visState if it exists (it is a stringified JSON)
        if "attributes" in obj and "visState" in obj["attributes"]:
            visState = json.loads(obj["attributes"]["visState"])
            
            # 1. Replace mitre.tactic.keyword -> data.alert.metadata.mitre_tactic_name
            if "aggs" in visState:
                for agg in visState["aggs"]:
                    if "params" in agg and "field" in agg["params"]:
                        if agg["params"]["field"] == "mitre.tactic.keyword":
                            agg["params"]["field"] = "data.alert.metadata.mitre_tactic_name"
                        # 2. Replace source_ip_fixed.keyword -> data.srcip.keyword
                        elif agg["params"]["field"] == "source_ip_fixed.keyword":
                            agg["params"]["field"] = "data.srcip.keyword"
                        # Replace source.ip -> data.srcip
                        elif agg["params"]["field"] == "source.ip":
                            agg["params"]["field"] = "data.srcip"
                        
                        # 5. Fix Top Threat Actors alert_count and unique_techniques
                        if agg["params"]["field"] == "alert_count" or agg["params"]["field"] == "unique_techniques":
                            agg["type"] = "count"
                            del agg["params"]["field"]
            
            obj["attributes"]["visState"] = json.dumps(visState)
        
        # 4. Port Scanning Detection rule.id -> data.alert.signature_id
        if "attributes" in obj and "kibanaSavedObjectMeta" in obj["attributes"]:
            searchSource = obj["attributes"]["kibanaSavedObjectMeta"].get("searchSourceJSON", "{}")
            searchSourceObj = json.loads(searchSource)
            if "query" in searchSourceObj and "query" in searchSourceObj["query"]:
                q = searchSourceObj["query"]["query"]
                if "rule.id" in q:
                    searchSourceObj["query"]["query"] = q.replace("rule.id", "data.alert.signature_id")
            obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"] = json.dumps(searchSourceObj)

        new_lines.append(json.dumps(obj))
    except Exception as e:
        print("Error processing line:", e)
        new_lines.append(line.strip())

with open(r"C:\Users\mohiq\VirtualBox VMs\CTI-Skripsi\06-Dashboard\dashboard-final-v4.ndjson", "w", encoding="utf-8") as f:
    for line in new_lines:
        f.write(line + "\n")
print("Done creating v4")

