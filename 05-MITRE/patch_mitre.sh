#!/bin/bash
sed -i 's/if \[data\]\[alert\]\[signature_id\] {/if \[\@metadata\]\[sig_id_str\] {/' /etc/logstash/conf.d/soc-pipeline.conf
sed -i 's/\"\[\@metadata\]\[sig_id_str\]\" => \"%{\[data\]\[alert\]\[signature_id\]}\"/# removed/' /etc/logstash/conf.d/soc-pipeline.conf
systemctl restart logstash
