#!/bin/bash
curl -s -X GET "http://localhost:9200/wazuh-alerts-*/_mapping" > /tmp/mappings.json
