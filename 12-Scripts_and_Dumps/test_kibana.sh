#!/bin/bash
curl -s -X GET "http://192.168.56.10:5601/api/status" -u "admin:admin" -H "kbn-xsrf: true"
echo ""
curl -s -X GET "http://192.168.56.10:5601/api/status" -u "wazuh:wazuh" -H "kbn-xsrf: true"
echo ""
curl -s -X GET "http://192.168.56.10:5601/api/status" -u "admin:123123" -H "kbn-xsrf: true"
echo ""
curl -s -X GET "http://192.168.56.10:5601/api/status" -u "elastic:123123" -H "kbn-xsrf: true"
echo ""
