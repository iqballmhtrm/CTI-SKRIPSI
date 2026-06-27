import re

with open(r'C:\Users\mohiq\VirtualBox VMs\CTI-Skripsi\12-SOAR-Dashboard\soc-pipeline.conf.bak', 'r') as f:
    config = f.read()

sig_replace = '''  if [wazuh][data][alert][signature_id] {
    mutate { add_field => { "[@metadata][sig_id_str]" => "%{[wazuh][data][alert][signature_id]}" } }
  } else if [rule][id] {
    mutate { add_field => { "[@metadata][sig_id_str]" => "%{[rule][id]}" } }
  } else if [alert][signature_id] {
    mutate { add_field => { "[@metadata][sig_id_str]" => "%{[alert][signature_id]}" } }
  } else if [suricata][eve][alert][signature_id] {'''

config = config.replace(
    '  if [wazuh][data][alert][signature_id] {\n\n    mutate {\n      add_field => {\n        "[@metadata][sig_id_str]" => "%{[wazuh][data][alert][signature_id]}"\n      }\n    }\n\n  } else if [suricata][eve][alert][signature_id] {',
    sig_replace
)

attack_replace = '''  # --- SOAR NORMALIZATION ---
  if [@metadata][sig_id_str] {
    mutate {
      add_field => {
        "[soar][attack_type]" => "Unknown Signature"
        "[soar][severity]" => "0"
        "[soar][mitre_technique]" => "Unmapped"
        "[soar][mitre_status]" => "Unmapped"
      }
    }
    
    if [wazuh][data][alert][signature] {
      mutate { replace => { "[soar][attack_type]" => "%{[wazuh][data][alert][signature]}" } }
    } else if [rule][description] {
      mutate { replace => { "[soar][attack_type]" => "%{[rule][description]}" } }
    } else if [alert][signature] {
      mutate { replace => { "[soar][attack_type]" => "%{[alert][signature]}" } }
    } else if [suricata][eve][alert][signature] {
      mutate { replace => { "[soar][attack_type]" => "%{[suricata][eve][alert][signature]}" } }
    }
    
    if [wazuh][data][rule][level] {
      mutate { replace => { "[soar][severity]" => "%{[wazuh][data][rule][level]}" } }
    } else if [rule][level] {
      mutate { replace => { "[soar][severity]" => "%{[rule][level]}" } }
    } else if [alert][severity] {
      mutate { replace => { "[soar][severity]" => "%{[alert][severity]}" } }
    } else if [suricata][eve][alert][severity] {
      mutate { replace => { "[soar][severity]" => "%{[suricata][eve][alert][severity]}" } }
    }

    if [mitre][technique_name] and [mitre][technique_name] != "Unmapped" {
      mutate {
        replace => { 
          "[soar][mitre_technique]" => "%{[mitre][technique_name]}" 
          "[soar][mitre_status]" => "Mapped"
        }
      }
    }
  }'''

config = re.sub(r'  # --- SOAR NORMALIZATION ---.*?  }  # PENUTUP FILTER', attack_replace + '\n\n}   # PENUTUP FILTER', config, flags=re.DOTALL)

http_replace = '''  # --- SOAR HTTP WEBHOOK ---
  if [@metadata][sig_id_str] {
    http {
      url => "http://127.0.0.1:5000/webhook"
      http_method => "post"
      format => "json"
      mapping => {
        "timestamp_alert" => "%{[@timestamp]}"
        "src_ip" => "%{[source][ip]}"
        "attack_type" => "%{[soar][attack_type]}"
        "severity" => "%{[soar][severity]}"
        "mitre_technique" => "%{[soar][mitre_technique]}"
        "mitre_status" => "%{[soar][mitre_status]}"
        "pipeline_source" => "logstash_http"
      }
    }
  }'''

config = re.sub(r'  # --- SOAR HTTP WEBHOOK ---.*', http_replace + '\n}', config, flags=re.DOTALL)

with open(r'C:\Users\mohiq\VirtualBox VMs\CTI-Skripsi\12-SOAR-Dashboard\soc-pipeline.conf', 'w') as f:
    f.write(config)
