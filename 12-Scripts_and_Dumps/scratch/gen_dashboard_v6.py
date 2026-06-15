#!/usr/bin/env python3
"""Generate CTI Dashboard V3 NDJSON with correct filters for Kibana import."""
import json

INDEX_PATTERN_ID = "7afca9a4-6f1e-4e1c-81e0-b82fd03711b3"

def alert_filter():
    return {
        "meta": {"index": INDEX_PATTERN_ID, "negate": False, "disabled": False,
                 "alias": None, "type": "phrase", "key": "event_type.keyword",
                 "value": "alert", "params": {"query": "alert"}},
        "query": {"match_phrase": {"event_type.keyword": "alert"}}
    }

def not_unmapped_filter():
    return {
        "meta": {"index": INDEX_PATTERN_ID, "negate": True, "disabled": False,
                 "alias": None, "type": "phrase", "key": "mitre.technique_id",
                 "value": "Unmapped", "params": {"query": "Unmapped"}},
        "query": {"match_phrase": {"mitre.technique_id": "Unmapped"}}
    }

def exists_filter(field):
    return {
        "meta": {"index": INDEX_PATTERN_ID, "negate": False, "disabled": False,
                 "alias": None, "type": "exists", "key": field, "value": "exists"},
        "exists": {"field": field}
    }

def technique_filter(tid):
    return {
        "meta": {"index": INDEX_PATTERN_ID, "negate": False, "disabled": False,
                 "alias": None, "type": "phrase", "key": "mitre.technique_id",
                 "value": tid, "params": {"query": tid}},
        "query": {"match_phrase": {"mitre.technique_id": tid}}
    }

def ssrc(filters):
    return json.dumps({
        "index": INDEX_PATTERN_ID,
        "query": {"query": "", "language": "kuery"},
        "filter": filters
    })

def mkvis(vid, title, vtype, aggs, params, filters):
    return {
        "attributes": {
            "title": title,
            "visState": json.dumps({"title": title, "type": vtype, "aggs": aggs, "params": params}),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {"searchSourceJSON": ssrc(filters)}
        },
        "id": vid,
        "type": "visualization",
        "references": [{"id": INDEX_PATTERN_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]
    }

objects = []

# Index pattern
objects.append({
    "attributes": {"title": "cti-logs-iqbal-*", "timeFieldName": "@timestamp", "fields": "[]"},
    "id": INDEX_PATTERN_ID,
    "type": "index-pattern"
})

# 1. Total Mapped MITRE Alerts
objects.append(mkvis(
    "v3-mitre-mapped-count", "V3 - Total Mapped MITRE Alerts", "metric",
    [{"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"}],
    {"addTooltip": True, "addLegend": False, "type": "metric",
     "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}],
                "labels": {"show": True}, "invertColors": False,
                "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                          "subText": "Mapped MITRE Alerts", "fontSize": 60}}},
    [alert_filter(), exists_filter("mitre.technique_id"), not_unmapped_filter()]
))

# 2. Technique Distribution (pie) — only mapped
objects.append(mkvis(
    "v3-mitre-technique-pie", "V3 - MITRE ATT&CK Technique Distribution", "pie",
    [
        {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
        {"id": "2", "enabled": True, "type": "terms",
         "params": {"field": "mitre.technique_id", "orderBy": "1", "order": "desc",
                    "size": 10, "otherBucket": False, "otherBucketLabel": "Other",
                    "missingBucket": False},
         "schema": "segment"}
    ],
    {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
     "isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}},
    [alert_filter(), exists_filter("mitre.technique_id"), not_unmapped_filter()]
))

# 3. Tactic Distribution (bar) — alerts only, incl Unmapped for contrast
hbar_params = {
    "type": "horizontal_bar", "addTooltip": True, "addLegend": True,
    "legendPosition": "right", "times": [], "addTimeMarker": False,
    "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "left",
                      "show": True, "style": {}, "scale": {"type": "linear"},
                      "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 200},
                      "title": {}}],
    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                   "position": "bottom", "show": True, "style": {},
                   "scale": {"type": "linear", "mode": "normal"},
                   "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                   "title": {"text": "Count"}}],
    "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                      "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                      "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
    "grid": {"categoryLines": False}
}

objects.append(mkvis(
    "v3-mitre-tactic-bar", "V3 - MITRE ATT&CK Tactic Distribution", "horizontal_bar",
    [
        {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
        {"id": "2", "enabled": True, "type": "terms",
         "params": {"field": "mitre.technique_id", "orderBy": "1", "order": "desc",
                    "size": 10, "otherBucket": False, "missingBucket": False},
         "schema": "segment"}
    ],
    hbar_params,
    [alert_filter()]
))

# 4. Timeline (date histogram, split by technique)
hist_params = {
    "type": "histogram", "addTooltip": True, "addLegend": True,
    "legendPosition": "right", "times": [], "addTimeMarker": False,
    "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                      "show": True, "style": {}, "scale": {"type": "linear"},
                      "labels": {"show": True, "rotate": 0, "filter": True, "truncate": 100},
                      "title": {}}],
    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                   "position": "left", "show": True, "style": {},
                   "scale": {"type": "linear", "mode": "normal"},
                   "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                   "title": {"text": "Count"}}],
    "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                      "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                      "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
    "grid": {"categoryLines": False}
}

objects.append(mkvis(
    "v3-mitre-timeline", "V3 - MITRE Alert Timeline by Tactic", "histogram",
    [
        {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
        {"id": "2", "enabled": True, "type": "date_histogram",
         "params": {"field": "@timestamp", "useNormalizedEsInterval": True,
                    "scaleMetricValues": False, "interval": "auto",
                    "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}},
         "schema": "segment"},
        {"id": "3", "enabled": True, "type": "terms",
         "params": {"field": "mitre.technique_id", "orderBy": "1", "order": "desc",
                    "size": 5, "otherBucket": False, "missingBucket": False},
         "schema": "group"}
    ],
    hist_params,
    [alert_filter(), exists_filter("mitre.technique_id"), not_unmapped_filter()]
))

# 5. Pyramid of Pain (alerts only)
objects.append(mkvis(
    "v3-pyramid-layer-bar", "V3 - Pyramid of Pain Layer Distribution", "horizontal_bar",
    [
        {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
        {"id": "2", "enabled": True, "type": "terms",
         "params": {"field": "pyramid.layer", "orderBy": "1", "order": "desc",
                    "size": 10, "otherBucket": False, "missingBucket": False},
         "schema": "segment"}
    ],
    hbar_params,
    [alert_filter()]
))

# 6. Top Threat Actors Table (alerts only)
objects.append(mkvis(
    "v3-threat-actors-table", "V3 - Top Threat Actors Table", "table",
    [
        {"id": "1", "enabled": True, "type": "count",
         "params": {"customLabel": "Alert Count"}, "schema": "metric"},
        {"id": "2", "enabled": True, "type": "terms",
         "params": {"field": "source.ip", "orderBy": "1", "order": "desc",
                    "size": 10, "otherBucket": False, "missingBucket": False,
                    "customLabel": "Source IP"},
         "schema": "bucket"},
        {"id": "3", "enabled": True, "type": "cardinality",
         "params": {"field": "mitre.technique_id", "customLabel": "Unique Techniques"},
         "schema": "metric"}
    ],
    {"type": "table", "perPage": 10, "showPartialRows": False,
     "showMetricsAtAllLevels": False, "sort": {"columnIndex": None, "direction": None},
     "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
    [alert_filter()]
))

# 7-9. Validation metrics — each with specific technique filter
for vid, title, tid, sub in [
    ("v3-validation-nmap",  "V3 - Validasi Nmap (T1046)",      "T1046",     "T1046 Detections"),
    ("v3-validation-hydra", "V3 - Validasi Hydra (T1110.001)", "T1110.001", "T1110.001 Detections"),
    ("v3-validation-nikto", "V3 - Validasi Nikto (T1595)",     "T1595",     "T1595 Detections"),
]:
    objects.append(mkvis(
        vid, title, "metric",
        [{"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"}],
        {"addTooltip": True, "addLegend": False, "type": "metric",
         "metric": {"percentageMode": False, "useRanges": False,
                    "colorSchema": "Green to Red", "metricColorMode": "None",
                    "colorsRange": [{"from": 0, "to": 10000}],
                    "labels": {"show": True}, "invertColors": False,
                    "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                              "subText": sub, "fontSize": 60}}},
        [alert_filter(), technique_filter(tid)]
    ))

# Dashboard
panels = [
    {"gridData": {"x": 0,  "y": 0,  "w": 24, "h": 15, "i": "1"}, "panelIndex": "1", "embeddableConfig": {}, "panelRefName": "panel_0"},
    {"gridData": {"x": 24, "y": 0,  "w": 24, "h": 15, "i": "2"}, "panelIndex": "2", "embeddableConfig": {}, "panelRefName": "panel_1"},
    {"gridData": {"x": 0,  "y": 15, "w": 24, "h": 15, "i": "3"}, "panelIndex": "3", "embeddableConfig": {}, "panelRefName": "panel_2"},
    {"gridData": {"x": 24, "y": 15, "w": 24, "h": 15, "i": "4"}, "panelIndex": "4", "embeddableConfig": {}, "panelRefName": "panel_3"},
    {"gridData": {"x": 0,  "y": 30, "w": 24, "h": 15, "i": "5"}, "panelIndex": "5", "embeddableConfig": {}, "panelRefName": "panel_4"},
    {"gridData": {"x": 24, "y": 30, "w": 24, "h": 15, "i": "6"}, "panelIndex": "6", "embeddableConfig": {}, "panelRefName": "panel_5"},
    {"gridData": {"x": 0,  "y": 45, "w": 16, "h": 10, "i": "7"}, "panelIndex": "7", "embeddableConfig": {}, "panelRefName": "panel_6"},
    {"gridData": {"x": 16, "y": 45, "w": 16, "h": 10, "i": "8"}, "panelIndex": "8", "embeddableConfig": {}, "panelRefName": "panel_7"},
    {"gridData": {"x": 32, "y": 45, "w": 16, "h": 10, "i": "9"}, "panelIndex": "9", "embeddableConfig": {}, "panelRefName": "panel_8"},
]

vis_ids = [
    "v3-mitre-mapped-count", "v3-mitre-technique-pie", "v3-mitre-tactic-bar",
    "v3-mitre-timeline", "v3-pyramid-layer-bar", "v3-threat-actors-table",
    "v3-validation-nmap", "v3-validation-hydra", "v3-validation-nikto",
]

objects.append({
    "attributes": {
        "title": "CTI Dashboard V3",
        "hits": 0,
        "description": "Dashboard CTI - MITRE ATT&CK Mapping (Alert-Only Filter)",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
        "timeRestore": True,
        "timeTo": "now",
        "timeFrom": "now-24h",
        "refreshInterval": {"pause": False, "value": 10000},
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        }
    },
    "id": "v3-cti-dashboard-final",
    "type": "dashboard",
    "references": [{"id": vid, "name": f"panel_{i}", "type": "visualization"} for i, vid in enumerate(vis_ids)]
})

with open("/tmp/dashboard_v6.ndjson", "w") as f:
    for obj in objects:
        f.write(json.dumps(obj) + "\n")

print(f"OK: {len(objects)} objects written to /tmp/dashboard_v6.ndjson")
