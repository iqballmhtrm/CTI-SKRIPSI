#!/bin/bash
sed -i 's/mutate {/mutate {\n    remove_field => [ "[predecoder][timestamp]" ]/g' /etc/logstash/conf.d/wazuh-elasticsearch.conf
systemctl restart logstash
