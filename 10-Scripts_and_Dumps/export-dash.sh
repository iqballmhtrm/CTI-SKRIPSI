#!/bin/bash
curl -s -X POST "http://localhost:5601/api/saved_objects/_export" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d '{"type": ["dashboard", "visualization", "index-pattern"]}' > /tmp/dashboard-final.ndjson
