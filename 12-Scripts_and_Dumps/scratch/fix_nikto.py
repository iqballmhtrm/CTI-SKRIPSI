import json

INDEX_PATTERN_ID = "7afca9a4-6f1e-4e1c-81e0-b82fd03711b3"

def alert_filter():
    return {
        "meta": {"index": INDEX_PATTERN_ID, "negate": False, "disabled": False,
                 "alias": None, "type": "phrase", "key": "event_type.keyword",
                 "value": "alert", "params": {"query": "alert"}},
        "query": {"match_phrase": {"event_type.keyword": "alert"}}
    }

def mitre_filter(tech_id):
    return {
        "meta": {"index": INDEX_PATTERN_ID, "negate": False, "disabled": False,
                 "alias": None, "type": "phrase", "key": "mitre.technique_id",
                 "value": tech_id, "params": {"query": tech_id}},
        "query": {"match_phrase": {"mitre.technique_id": tech_id}}
    }

def ssrc(filters):
    return json.dumps({
        "index": INDEX_PATTERN_ID,
        "query": {"query": "", "language": "kuery"},
        "filter": filters
    })

vis_nikto = {
    "attributes": {
        "title": "V3 - Validasi Nikto (T1595.002)",
        "visState": json.dumps({"title": "V3 - Validasi Nikto (T1595.002)", "type": "metric", "aggs": [{"id": "1", "enabled": True, "type": "count", "params": {"customLabel": "Count"}, "schema": "metric"}], "params": {"type": "metric", "addTooltip": True, "addLegend": False, "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red", "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}], "labels": {"show": True}, "invertColors": False, "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 60}}}}),
        "uiStateJSON": "{}",
        "description": "",
        "kibanaSavedObjectMeta": {"searchSourceJSON": ssrc([alert_filter(), mitre_filter("T1595.002")])}
    },
    "id": "v3-validation-nikto",
    "type": "visualization",
    "references": [{"id": INDEX_PATTERN_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
}

with open("/tmp/fix_nikto.ndjson", "w") as f:
    f.write(json.dumps(vis_nikto) + "\n")

print("OK: fix_nikto.ndjson written")
