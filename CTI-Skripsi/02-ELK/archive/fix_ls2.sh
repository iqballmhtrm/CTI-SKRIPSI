#!/bin/bash
sed -i 's/json {/mutate {\n    remove_field => [ "[predecoder][timestamp]" ]\n  }\n\n  json {/' /etc/logstash/conf.d/soc-pipeline.conf
systemctl restart logstash
