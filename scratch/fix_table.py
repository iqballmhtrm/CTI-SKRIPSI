#!/usr/bin/env python3
"""Fix: Threat Actors Table uses source.ip.keyword, inject fresh Hydra alerts."""
import json

INDEX_PATTERN_ID = "7afca9a4-6f1e-4e1c-81e0-b82fd03711b3"

def alert_filter():
    return {
        "meta": {"index": INDEX_PATTERN_ID, "negate": False, "disabled": False,
                 "alias": None, "type": "phrase", "key": "event_type.keyword",
                 "value": "alert", "params": {"query": "alert"}},
        "query": {"match_phrase": {"event_type.keyword": "alert"}}
    }

def ssrc(filters):
    return json.dumps({
        "index": INDEX_PATTERN_ID,
        "query": {"query": "", "language": "kuery"},
        "filter": filters
    })

# Only re-export the Threat Actors Table with fixed field
vis_state = json.dumps({
    "title": "V3 - Top Threat Actors Table",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count",
         "params": {"customLabel": "Alert Count"}, "schema": "metric"},
        {"id": "2", "enabled": True, "type": "terms",
         "params": {"field": "src_ip.keyword", "orderBy": "1", "order": "desc",
                    "size": 10, "otherBucket": False, "missingBucket": False,
                    "customLabel": "Source IP"},
         "schema": "bucket"},
        {"id": "3", "enabled": True, "type": "cardinality",
         "params": {"field": "mitre.technique_id", "customLabel": "Unique Techniques"},
         "schema": "metric"}
    ],
    "params": {
        "type": "table", "perPage": 10, "showPartialRows": False,
        "showMetricsAtAllLevels": False,
        "sort": {"columnIndex": None, "direction": None},
        "showTotal": False, "totalFunc": "sum", "percentageCol": ""
    }
})

obj = {
    "attributes": {
        "title": "V3 - Top Threat Actors Table",
        "visState": vis_state,
        "uiStateJSON": "{}",
        "description": "",
        "kibanaSavedObjectMeta": {"searchSourceJSON": ssrc([alert_filter()])}
    },
    "id": "v3-threat-actors-table",
    "type": "visualization",
    "references": [{"id": INDEX_PATTERN_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
}

with open("/tmp/fix_table.ndjson", "w") as f:
    f.write(json.dumps(obj) + "\n")

print("OK: fix_table.ndjson written")
