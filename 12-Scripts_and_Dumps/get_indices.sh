#!/bin/bash
curl -s -X GET "http://localhost:9200/_cat/indices?v" > /tmp/indices.txt
